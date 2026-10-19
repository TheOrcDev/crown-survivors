import { Hono } from "hono";
import { cors } from "hono/cors";
import { auth, type Session } from "./auth.js";
import { ALLOWED_ORIGINS, isAllowedReturnUrl } from "./origins.js";
import { BOARDS, type Board, getLeaderboard, getMyRank, insertScore, validateScore, RATE_LIMIT_SECONDS } from "./scores.js";

type Vars = { user: Session["user"] | null; session: Session["session"] | null };

export const app = new Hono<{ Variables: Vars }>();

app.use(
  "*",
  cors({
    origin: (origin) => (ALLOWED_ORIGINS.includes(origin) ? origin : null),
    credentials: true,
    allowMethods: ["GET", "POST", "OPTIONS"],
    allowHeaders: ["Content-Type", "Authorization"],
    exposeHeaders: ["set-auth-token"],
    maxAge: 600,
  }),
);

// Better Auth routes: /api/auth/sign-in/social, /api/auth/callback/twitter, /api/auth/get-session, /api/auth/sign-out ...
// Users must not edit name/handle/avatar themselves; they always come from X.
app.all("/api/auth/update-user", (c) => c.json({ error: "not allowed" }, 403));
app.on(["GET", "POST"], "/api/auth/*", (c) => auth.handler(c.req.raw));

// Resolve the session (cookie or Bearer token) for everything else.
app.use("*", async (c, next) => {
  const s = await auth.api.getSession({ headers: c.req.raw.headers });
  c.set("user", s?.user ?? null);
  c.set("session", s?.session ?? null);
  await next();
});

app.get("/api/health", (c) => c.json({ ok: true, service: "crown-survivors-api" }));

/**
 * Top-level sign-in entry the game links to (window.location = ...):
 *   GET /auth/x?returnTo=<game url>
 * Runs the OAuth dance first-party on this domain, then /auth/handoff sends the
 * browser back to the game with #lb_token=... so it works even where
 * third-party cookies are blocked (Safari / iOS).
 */
app.get("/auth/x", async (c) => {
  const returnTo = c.req.query("returnTo");
  if (!isAllowedReturnUrl(returnTo)) return c.json({ error: "returnTo must be a game URL" }, 400);
  const base = process.env.BETTER_AUTH_URL ?? new URL(c.req.url).origin;
  const callbackURL = `${base}/auth/handoff?returnTo=${encodeURIComponent(returnTo)}`;
  const res = await auth.api.signInSocial({
    body: { provider: "twitter", callbackURL, errorCallbackURL: callbackURL },
    headers: c.req.raw.headers,
    asResponse: true,
  });
  const data = (await res.json()) as { url?: string };
  if (!data.url) return c.json({ error: "could not start sign-in" }, 500);
  const out = new Response(null, { status: 302, headers: { Location: data.url } });
  for (const cookie of res.headers.getSetCookie()) out.headers.append("Set-Cookie", cookie);
  return out;
});

app.get("/auth/handoff", (c) => {
  const returnTo = c.req.query("returnTo");
  if (!isAllowedReturnUrl(returnTo)) return c.json({ error: "bad returnTo" }, 400);
  const url = new URL(returnTo);
  const session = c.get("session");
  url.hash = session ? `lb_token=${encodeURIComponent(session.token)}` : `lb_error=${encodeURIComponent(c.req.query("error") ?? "signin_failed")}`;
  return c.redirect(url.toString(), 302);
});

/** Current user (handle/avatar) or null. */
app.get("/api/me", (c) => {
  const u = c.get("user");
  if (!u) return c.json({ user: null });
  return c.json({ user: { id: u.id, name: u.name, handle: (u as { handle?: string | null }).handle ?? null, avatar: u.image ?? null } });
});

function parseBoard(v: string | undefined): Board | null {
  return BOARDS.includes(v as Board) ? (v as Board) : null;
}

app.post("/api/scores", async (c) => {
  const user = c.get("user");
  if (!user) return c.json({ error: "sign in required" }, 401);
  let body: unknown;
  try {
    body = await c.req.json();
  } catch {
    return c.json({ error: "invalid JSON" }, 400);
  }
  const v = validateScore(body);
  if (!v.ok) return c.json({ error: v.error }, 400);
  const id = await insertScore(user.id, v.value);
  if (id === null) {
    c.header("Retry-After", String(RATE_LIMIT_SECONDS));
    return c.json({ error: `one submission per ${RATE_LIMIT_SECONDS}s` }, 429);
  }
  return c.json({ ok: true, id }, 201);
});

app.get("/api/leaderboard", async (c) => {
  const board = parseBoard(c.req.query("board") ?? "fastest");
  if (!board) return c.json({ error: "board must be fastest|survival|kills" }, 400);
  const raw = Number(c.req.query("limit") ?? 50);
  const limit = Number.isFinite(raw) ? Math.min(Math.max(Math.trunc(raw), 1), 100) : 50;
  const rows = await getLeaderboard(board, limit);
  c.header("Cache-Control", "public, s-maxage=15, stale-while-revalidate=60");
  return c.json({ board, rows });
});

app.get("/api/me/rank", async (c) => {
  const user = c.get("user");
  if (!user) return c.json({ error: "sign in required" }, 401);
  const board = parseBoard(c.req.query("board") ?? "fastest");
  if (!board) return c.json({ error: "board must be fastest|survival|kills" }, 400);
  const { row, total } = await getMyRank(board, user.id);
  c.header("Cache-Control", "private, no-store");
  return c.json({ board, total, rank: row?.rank ?? null, row });
});

app.onError((err, c) => {
  console.error(err);
  return c.json({ error: "internal error" }, 500);
});
