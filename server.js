import "dotenv/config"; // loads .env locally; a no-op on Render (vars come from the platform)
import express from "express";
import cors from "cors";
import QRCode from "qrcode";
import { createClient } from "@supabase/supabase-js";
import crypto from "node:crypto";

// ---------- config ----------
const PORT = process.env.PORT || 4000;
const SUPABASE_URL = process.env.SUPABASE_URL || process.env.NEXT_PUBLIC_SUPABASE_URL;
const SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;
// First-run bootstrap admin. Used ONCE, to seed the resellers table on an empty database; after
// that every sign-in is checked against that table. Not a standing back door.
const ADMIN_EMAIL = (process.env.ADMIN_EMAIL || "admin@apnatv.com").trim().toLowerCase();
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "";

// Signs dashboard session tokens. There is deliberately NO default: a shipped fallback secret is a
// master key to every reseller account, so the server refuses to start in production without one.
const AUTH_SECRET = process.env.AUTH_SECRET || "";
const IS_PROD = (process.env.NODE_ENV || "").toLowerCase() === "production";
const SESSION_HOURS = Number(process.env.SESSION_HOURS || 12);

// Browser origins allowed to call the admin API. Comma-separated; empty = allow any (dev only).
// Normalized (trailing slash + case) so a copy-pasted env var with `.../` still matches the bare
// origin a browser actually sends — a mismatch here fails every request with a bare "Failed to
// fetch" in the browser, no server-side error to point at.
const normOrigin = (o) => String(o || "").trim().toLowerCase().replace(/\/+$/, "");
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || "")
  .split(",").map(normOrigin).filter(Boolean);
// Where the QR-scanned activation page lives (the dashboard). Used to build the QR link.
const DASHBOARD_URL = process.env.DASHBOARD_URL || "";
// The ONLY managed portal every box connects to by default — hardcoded here and in the app
// (RemoteConfig). star.homeip.net is correct: the app's RedirectFixInterceptor resolves it to the
// live backend. A box can instead report its OWN portal — see isSelfManaged below.
const STATIC_PORTAL_URL = process.env.STATIC_PORTAL_URL || "http://star.homeip.net";
const RESELLERS_TABLE = "resellers";

// Fail fast rather than boot into an insecure state that looks fine until it is exploited.
const fatal = [];
if (!SUPABASE_URL || !SERVICE_ROLE_KEY) {
  fatal.push("SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY are required.");
}
if (!AUTH_SECRET || AUTH_SECRET.length < 32) {
  fatal.push("AUTH_SECRET is required and must be at least 32 characters (it signs every session).");
}
if (IS_PROD && ALLOWED_ORIGINS.length === 0) {
  fatal.push("ALLOWED_ORIGINS is required in production (the dashboard origin, comma-separated).");
}
if (fatal.length) {
  console.error("FATAL:\n  - " + fatal.join("\n  - "));
  process.exit(1);
}

const supabase = createClient(SUPABASE_URL, SERVICE_ROLE_KEY, {
  auth: { persistSession: false },
});

const app = express();
// The app (no Origin header) always passes; browsers are held to the allowlist so a random site
// cannot drive the admin API with a signed-in reseller's browser.
app.use(cors({
  origin(origin, cb) {
    if (!origin || ALLOWED_ORIGINS.length === 0) return cb(null, true);
    cb(null, ALLOWED_ORIGINS.includes(normOrigin(origin)));
  },
}));
app.use(express.json());

// ---------- helpers ----------
const ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
function genPairingCode(len = 6) {
  let out = "";
  for (let i = 0; i < len; i++) out += ALPHABET[Math.floor(Math.random() * ALPHABET.length)];
  return out;
}

// ============================================================
// AUTH — real accounts, signed sessions, per-reseller isolation
// ============================================================
//
// The old build handed every caller the same static secret as its "token", so anyone who signed in
// was the same omniscient admin and saw every reseller's devices. Now:
//   * passwords are scrypt hashes (node built-in; no extra dependency to keep patched),
//   * a session is an HMAC-signed token carrying WHO you are and when it expires,
//   * every admin query is scoped to the caller's reseller id unless they are an admin.

const b64u = (buf) => Buffer.from(buf).toString("base64url");

/** scrypt$<salt>$<hash> — salt is per user, so identical passwords never share a hash. */
function hashPassword(password) {
  const salt = crypto.randomBytes(16);
  const hash = crypto.scryptSync(String(password), salt, 64);
  return `scrypt$${salt.toString("base64url")}$${hash.toString("base64url")}`;
}

function verifyPassword(password, stored) {
  const parts = String(stored || "").split("$");
  if (parts.length !== 3 || parts[0] !== "scrypt") return false;
  const salt = Buffer.from(parts[1], "base64url");
  const expected = Buffer.from(parts[2], "base64url");
  const actual = crypto.scryptSync(String(password), salt, expected.length);
  // Constant-time: a length-dependent early return leaks how much of the hash matched.
  return expected.length === actual.length && crypto.timingSafeEqual(expected, actual);
}

function signToken(payload) {
  const body = b64u(JSON.stringify(payload));
  const sig = crypto.createHmac("sha256", AUTH_SECRET).update(body).digest("base64url");
  return `${body}.${sig}`;
}

function verifyToken(token) {
  const [body, sig] = String(token || "").split(".");
  if (!body || !sig) return null;
  const expected = crypto.createHmac("sha256", AUTH_SECRET).update(body).digest("base64url");
  const a = Buffer.from(sig);
  const b = Buffer.from(expected);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  const payload = JSON.parse(Buffer.from(body, "base64url").toString());
  if (!payload?.exp || payload.exp < Date.now()) return null;   // expired
  return payload;
}

/** Rejects anyone without a valid, unexpired session; attaches it as req.user. */
function requireAuth(req, res, next) {
  const user = verifyToken((req.headers.authorization || "").replace(/^Bearer\s+/i, ""));
  if (!user) return res.status(401).json({ error: "unauthorized" });
  req.user = user;
  next();
}

/** Platform-wide actions (releases, managing resellers) are admin-only. */
function requireAdmin(req, res, next) {
  if (req.user?.role !== "admin") return res.status(403).json({ error: "admins only" });
  next();
}

const isAdmin = (req) => req.user?.role === "admin";

/**
 * THE isolation rule, in one place: an admin sees everything, a reseller sees only rows stamped
 * with their id. Every device read and write goes through one of these two helpers, so there is no
 * route where forgetting a filter silently exposes another client's boxes.
 *
 * A self-managed box (see isSelfManaged below) is never claimed by anyone — there is no dashboard
 * "activate" step for it, so its reseller_id stays null and only an admin ever sees it. That is a
 * property of the self-managed feature itself (it exists precisely to need NO dashboard action),
 * not a gap introduced here.
 */
function deviceSelect(req, columns = "*", opts = undefined) {
  const q = supabase.from("devices").select(columns, opts);
  return isAdmin(req) ? q : q.eq("reseller_id", req.user.sub);
}

function deviceUpdate(req, patch) {
  const q = supabase.from("devices").update(patch);
  return isAdmin(req) ? q : q.eq("reseller_id", req.user.sub);
}

// ---- login throttling: a shared in-memory counter, enough to stop online guessing ----
const loginAttempts = new Map();
const LOGIN_MAX = 8;
const LOGIN_WINDOW_MS = 10 * 60 * 1000;

function loginBlocked(key) {
  const rec = loginAttempts.get(key);
  if (!rec) return false;
  if (Date.now() - rec.first > LOGIN_WINDOW_MS) {
    loginAttempts.delete(key);
    return false;
  }
  return rec.count >= LOGIN_MAX;
}

function noteLoginFailure(key) {
  const rec = loginAttempts.get(key);
  if (!rec || Date.now() - rec.first > LOGIN_WINDOW_MS) {
    loginAttempts.set(key, { count: 1, first: Date.now() });
  } else {
    rec.count += 1;
  }
}

/**
 * Seeds the FIRST admin from ADMIN_EMAIL/ADMIN_PASSWORD when the resellers table is empty, so a
 * fresh deploy is reachable. Once any account exists this does nothing — the env vars stop being
 * credentials and the table is the only source of truth. On the LIVE deploy this seeds the exact
 * admin@apnatv.com / apnatv2026 pair the old static-secret login used, so the existing admin's
 * credentials keep working unchanged even though the mechanism underneath is now real accounts.
 */
async function bootstrapAdmin() {
  const { count, error } = await supabase
    .from(RESELLERS_TABLE).select("id", { count: "exact", head: true });
  if (error) {
    console.error(`Cannot read ${RESELLERS_TABLE}: ${error.message}. Run supabase/schema.sql.`);
    return;
  }
  if ((count ?? 0) > 0) return;
  if (!ADMIN_EMAIL || !ADMIN_PASSWORD) {
    console.warn("No accounts yet. Set ADMIN_EMAIL + ADMIN_PASSWORD once to seed the first admin.");
    return;
  }
  const { error: insErr } = await supabase.from(RESELLERS_TABLE).insert({
    email: ADMIN_EMAIL,
    password_hash: hashPassword(ADMIN_PASSWORD),
    name: "Administrator",
    role: "admin",
  });
  if (insErr) console.error(`Could not seed admin: ${insErr.message}`);
  else console.log(`Seeded first admin: ${ADMIN_EMAIL}`);
}

// ============================================================
// DEVICE (app-facing) endpoints
// ============================================================

// Health check
app.get("/", (_req, res) => res.json({ ok: true, service: "apnatv-backend" }));
app.get("/api/health", (_req, res) => res.json({ ok: true }));

// POST /api/device/register  { device_id, mac?, model?, sig_sha256?, app_version? }
// The box auto-registers on boot, sending its own MAC. We store the MAC + the static
// portal URL here so the dashboard never has to type either one — just "Activate".
app.post("/api/device/register", async (req, res) => {
  const device_id = String(req.body?.device_id || "").trim();
  const mac = String(req.body?.mac || "").trim();
  if (!device_id) return res.status(400).json({ error: "device_id required" });

  const { data: existing } = await supabase
    .from("devices")
    .select("id, status, pairing_code, mac")
    .eq("device_id", device_id)
    .maybeSingle();

  if (existing?.status === "activated") {
    return res.json({ status: "activated", pairing_code: existing.pairing_code, mac: existing.mac });
  }

  // Self-managed: the box is on a RESELLER's OWN portal (a non-star server_url it sent). Such a box
  // is NOT under our activation/payment/revoke control — we just RECORD it so the dashboard can SHOW
  // it. Only the default star.homeip.net portal goes through the pairing-code activation flow.
  const norm = (s) => String(s || "").trim().toLowerCase().replace(/^https?:\/\//, "").replace(/\/+$/, "");
  const server_url_in = String(req.body?.server_url || "").trim();
  const isSelfManaged = server_url_in && norm(server_url_in) !== norm(STATIC_PORTAL_URL);

  const pairing_code = existing?.pairing_code ?? genPairingCode();
  const row = {
    device_id,
    pairing_code,
    status: isSelfManaged ? "self_managed" : (existing?.status ?? "pending"),
    server_url: isSelfManaged ? server_url_in : STATIC_PORTAL_URL,
    mac: mac || existing?.mac || null,    // auto-set from the device's own MAC
    model: req.body?.model ?? null,
    sig_sha256: req.body?.sig_sha256 ?? null,
    app_version: req.body?.app_version ?? null,
    last_seen: new Date().toISOString(),
  };
  // A self-managed box is never "unpaid" in our system — mark it paid so nothing ever locks it.
  if (isSelfManaged) row.payment_status = "paid";

  const { error } = await supabase.from("devices").upsert(row, { onConflict: "device_id" });
  if (error) return res.status(500).json({ error: error.message });
  res.json({ status: row.status, pairing_code, mac: row.mac });
});

// GET /api/device/config?device_id=...
app.get("/api/device/config", async (req, res) => {
  const device_id = String(req.query.device_id || "").trim();
  if (!device_id) return res.status(400).json({ error: "device_id required" });

  const { data } = await supabase
    .from("devices")
    .select("status, server_url, mac, payment_status, customer_name")
    .eq("device_id", device_id)
    .maybeSingle();
  if (!data) return res.status(404).json({ status: "unknown" });

  await supabase
    .from("devices")
    .update({ last_seen: new Date().toISOString() })
    .eq("device_id", device_id);

  if (data.status === "activated") {
    // Activated but unpaid/expired → keep the app locked (status != "activated").
    const paid = data.payment_status === "paid";
    return res.json({
      status: paid ? "activated" : "payment_required",
      server_url: data.server_url,
      mac: data.mac,
      payment_status: data.payment_status,
      customer_name: data.customer_name,
    });
  }
  res.json({ status: data.status });
});

// GET /api/version/check?version_code=N&device_id=...
app.get("/api/version/check", async (req, res) => {
  const current = Number(req.query.version_code ?? "0");
  const device_id = String(req.query.device_id || "").trim();
  if (device_id) {
    // UPSERT, not update: a device that connected via the direct "type portal URL" flow (never
    // called /api/device/register) used to be invisible here forever — an update() against a
    // device_id with no matching row silently touches zero rows. Every device checks for updates
    // on launch regardless of how it connected, so this is the one call guaranteed to eventually
    // surface it in the dashboard, even with no MAC/portal known yet.
    await supabase
      .from("devices")
      .upsert(
        { device_id, app_version: current, last_seen: new Date().toISOString() },
        { onConflict: "device_id", ignoreDuplicates: false }
      );
  }
  const { data: latest } = await supabase
    .from("app_versions")
    .select("version_code, version_name, apk_url, apk_size, changelog, force_update")
    .eq("is_published", true)
    .order("version_code", { ascending: false })
    .limit(1)
    .maybeSingle();

  if (!latest || latest.version_code <= current) return res.json({ update_available: false });
  res.json({ update_available: true, ...latest });
});

// GET /api/qr?data=<url>&size=480  -> PNG
app.get("/api/qr", async (req, res) => {
  const data = req.query.data;
  const size = Math.min(Number(req.query.size ?? "480"), 1080);
  if (!data) return res.status(400).json({ error: "data required" });
  const png = await QRCode.toBuffer(String(data), {
    type: "png",
    width: size,
    margin: 1,
    color: { dark: "#160D06", light: "#F3EAD8" },
    errorCorrectionLevel: "M",
  });
  res.setHeader("Content-Type", "image/png");
  res.setHeader("Cache-Control", "no-store");
  res.send(png);
});

// ============================================================
// UNIVERSAL QR-PAIRING (setup screen) — NO activation/payment gate.
// The box shows a QR that opens /setup/<CODE> in the provider's browser; the provider types the
// portal URL there; the box polls /api/setup/<CODE> and auto-connects. In-memory store (TTL 15m) —
// the box polls every few seconds during pairing, which keeps the dyno awake, so no DB is needed.
// ============================================================
const setupPairings = new Map(); // CODE -> { server_url, at }
const SETUP_TTL_MS = 15 * 60 * 1000;
function cleanupPairings() {
  const now = Date.now();
  for (const [k, v] of setupPairings) if (now - v.at > SETUP_TTL_MS) setupPairings.delete(k);
}

// The box polls this; returns the portal URL once the provider has submitted it.
app.get("/api/setup/:code", (req, res) => {
  cleanupPairings();
  const code = String(req.params.code || "").trim().toUpperCase();
  const entry = setupPairings.get(code);
  res.setHeader("Cache-Control", "no-store");
  res.json({ server_url: entry?.server_url || null });
});

// The provider's browser posts the portal URL here (via the /setup page's form).
app.post("/api/setup/:code", (req, res) => {
  const code = String(req.params.code || "").trim().toUpperCase();
  let url = String(req.body?.server_url || "").trim();
  if (!code) return res.status(400).json({ error: "code required" });
  if (!url) return res.status(400).json({ error: "server_url required" });
  if (!/^https?:\/\//i.test(url)) url = "http://" + url; // tolerate a bare host
  setupPairings.set(code, { server_url: url, at: Date.now() });
  res.json({ ok: true });
});

// The page the provider opens from the QR — a simple mobile-friendly form.
app.get("/setup/:code", (req, res) => {
  const code = String(req.params.code || "").trim().toUpperCase();
  const mac = String(req.query.mac || "").trim();
  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.send(`<!doctype html><html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Easy TV — Connect your portal</title>
<style>
  :root { color-scheme: dark; }
  * { box-sizing: border-box; }
  body { margin:0; font-family:-apple-system,Segoe UI,Roboto,Arial,sans-serif; background:#160D06; color:#F3EAD8;
         display:flex; min-height:100vh; align-items:center; justify-content:center; padding:20px; }
  .card { width:100%; max-width:440px; background:#241610; border:1px solid rgba(200,154,110,.35);
          border-radius:16px; padding:26px; }
  h1 { margin:0 0 4px; font-size:22px; color:#C89A6E; }
  p.sub { margin:0 0 18px; color:#B49A80; font-size:14px; }
  .meta { font-size:13px; color:#B49A80; margin:10px 0; }
  .meta b { color:#F3EAD8; letter-spacing:1px; }
  label { display:block; font-size:13px; color:#B49A80; margin:16px 0 6px; }
  input { width:100%; padding:14px; font-size:16px; border-radius:10px; border:1px solid rgba(200,154,110,.4);
          background:#160D06; color:#F3EAD8; }
  input:focus { outline:none; border-color:#C89A6E; }
  button { width:100%; margin-top:18px; padding:14px; font-size:16px; font-weight:700; border:0;
           border-radius:10px; background:#C89A6E; color:#160D06; cursor:pointer; }
  button:disabled { opacity:.6; }
  .msg { margin-top:16px; font-size:14px; text-align:center; min-height:20px; }
  .ok { color:#5FBF8F; } .err { color:#D9776A; }
</style></head><body>
  <div class="card">
    <h1>Connect your portal</h1>
    <p class="sub">Enter the IPTV portal URL for this box. It will connect automatically.</p>
    <div class="meta">Pairing code: <b>${code}</b></div>
    ${mac ? `<div class="meta">Box MAC: <b>${mac}</b> — whitelist this on your panel.</div>` : ``}
    <label for="url">Portal URL</label>
    <input id="url" type="url" inputmode="url" autocomplete="off" autocapitalize="off"
           placeholder="http://your-portal.com/c/">
    <button id="go" onclick="submitUrl()">Connect this box</button>
    <div id="msg" class="msg"></div>
  </div>
<script>
  var CODE = ${JSON.stringify(code)};
  async function submitUrl() {
    var url = document.getElementById('url').value.trim();
    var msg = document.getElementById('msg');
    var btn = document.getElementById('go');
    if (!url) { msg.className='msg err'; msg.textContent='Please enter a portal URL.'; return; }
    btn.disabled = true; msg.className='msg'; msg.textContent='Sending…';
    try {
      var r = await fetch('/api/setup/' + encodeURIComponent(CODE), {
        method:'POST', headers:{'Content-Type':'application/json'},
        body: JSON.stringify({ server_url: url })
      });
      if (r.ok) { msg.className='msg ok'; msg.textContent='✓ Sent! The box will connect in a few seconds.'; }
      else { msg.className='msg err'; msg.textContent='Something went wrong. Try again.'; btn.disabled=false; }
    } catch (e) { msg.className='msg err'; msg.textContent='Network error. Try again.'; btn.disabled=false; }
  }
</script>
</body></html>`);
});

// ============================================================
// ADMIN (dashboard-facing) endpoints — all behind requireAuth
// ============================================================

// POST /api/admin/login  { email, password } -> { token, email, role, name }
app.post("/api/admin/login", async (req, res) => {
  const email = String(req.body?.email || "").trim().toLowerCase();
  const password = String(req.body?.password || "");
  const throttleKey = `${req.ip}|${email}`;
  if (loginBlocked(throttleKey)) {
    return res.status(429).json({ error: "Too many attempts. Try again in a few minutes." });
  }

  const { data: user } = await supabase
    .from(RESELLERS_TABLE).select("id, email, name, role, active, password_hash")
    .ilike("email", email).maybeSingle();

  // One message for every failure — telling them the email exists is a free hint to an attacker.
  if (!user || !user.active || !verifyPassword(password, user.password_hash)) {
    noteLoginFailure(throttleKey);
    return res.status(401).json({ error: "Invalid email or password" });
  }
  loginAttempts.delete(throttleKey);

  const token = signToken({
    sub: user.id,
    email: user.email,
    role: user.role,
    exp: Date.now() + SESSION_HOURS * 3600 * 1000,
  });
  res.json({ token, email: user.email, role: user.role, name: user.name });
});

/** Who am I — lets the dashboard show the signed-in account and hide admin-only pages. */
app.get("/api/admin/me", requireAuth, (req, res) => {
  res.json({ email: req.user.email, role: req.user.role, id: req.user.sub });
});

// ---- resellers (admin only): this is how a NEW client gets an account ----
app.get("/api/admin/resellers", requireAuth, requireAdmin, async (_req, res) => {
  const { data } = await supabase.from(RESELLERS_TABLE)
    .select("id, email, name, role, active, created_at")
    .order("created_at", { ascending: false });
  res.json({ resellers: data ?? [] });
});

app.post("/api/admin/resellers", requireAuth, requireAdmin, async (req, res) => {
  const email = String(req.body?.email || "").trim().toLowerCase();
  const password = String(req.body?.password || "");
  const name = String(req.body?.name || "").trim() || null;
  const role = req.body?.role === "admin" ? "admin" : "reseller";
  if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) {
    return res.status(400).json({ error: "A valid email is required" });
  }
  if (password.length < 8) {
    return res.status(400).json({ error: "Password must be at least 8 characters" });
  }
  const { error } = await supabase.from(RESELLERS_TABLE)
    .insert({ email, password_hash: hashPassword(password), name, role });
  if (error) {
    const dup = /duplicate|unique/i.test(error.message);
    return res.status(dup ? 409 : 500).json({ error: dup ? "That email already exists" : error.message });
  }
  res.json({ ok: true });
});

app.post("/api/admin/resellers/:id/active", requireAuth, requireAdmin, async (req, res) => {
  if (req.params.id === req.user.sub) {
    return res.status(400).json({ error: "You cannot disable your own account" });
  }
  const { error } = await supabase.from(RESELLERS_TABLE)
    .update({ active: !!req.body?.active }).eq("id", req.params.id);
  if (error) return res.status(500).json({ error: error.message });
  res.json({ ok: true });
});

app.post("/api/admin/resellers/:id/password", requireAuth, requireAdmin, async (req, res) => {
  const password = String(req.body?.password || "");
  if (password.length < 8) {
    return res.status(400).json({ error: "Password must be at least 8 characters" });
  }
  const { error } = await supabase.from(RESELLERS_TABLE)
    .update({ password_hash: hashPassword(password) }).eq("id", req.params.id);
  if (error) return res.status(500).json({ error: error.message });
  res.json({ ok: true });
});

// Buckets a set of ISO timestamps into one count per calendar day, oldest first, always `days`
// long even when a day had zero activity — a chart with gaps where days silently disappear reads
// as broken, not as "nothing happened that day".
function dailyBuckets(isoDates, days = 14) {
  const buckets = new Map();
  const today = new Date();
  for (let i = days - 1; i >= 0; i--) {
    const d = new Date(today);
    d.setDate(d.getDate() - i);
    buckets.set(d.toISOString().slice(0, 10), 0);
  }
  for (const iso of isoDates) {
    const key = String(iso || "").slice(0, 10);
    if (buckets.has(key)) buckets.set(key, buckets.get(key) + 1);
  }
  return [...buckets.entries()].map(([date, value]) => ({
    label: new Date(date).toLocaleDateString(undefined, { day: "numeric", month: "short" }),
    value,
  }));
}

// GET /api/admin/overview -> stats
app.get("/api/admin/overview", requireAuth, async (req, res) => {
  const since5 = new Date(Date.now() - 5 * 60 * 1000).toISOString();
  const since14d = new Date(Date.now() - 14 * 24 * 3600 * 1000).toISOString();
  // Every count runs through deviceSelect, so a reseller's dashboard totals cover only their boxes.
  const head = (mod) => mod(deviceSelect(req, "*", { count: "exact", head: true }));
  const [total, activated, pending, revoked, online, releases, latest, recent, versions, newDevices] =
    await Promise.all([
      head((q) => q),
      head((q) => q.eq("status", "activated")),
      head((q) => q.eq("status", "pending")),
      head((q) => q.eq("status", "revoked")),
      head((q) => q.gte("last_seen", since5)),
      supabase.from("app_versions").select("*", { count: "exact", head: true }),
      supabase.from("app_versions").select("version_code, version_name, force_update")
        .eq("is_published", true).order("version_code", { ascending: false }).limit(1).maybeSingle(),
      deviceSelect(req, "device_id, status, app_version, server_url, last_seen, created_at")
        .order("created_at", { ascending: false }).limit(8),
      supabase.from("app_versions").select("version_code, version_name").order("version_code", { ascending: false }),
      // Just the timestamps, for the 14-day trend chart — bucketed in JS below rather than a SQL
      // GROUP BY, since a reseller's own filter (deviceSelect) has to apply to it too.
      deviceSelect(req, "created_at").gte("created_at", since14d),
    ]);

  const latestCode = latest.data?.version_code ?? 0;
  let outdated = 0;
  if (latestCode > 0) {
    const r = await deviceSelect(req, "*", { count: "exact", head: true }).lt("app_version", latestCode);
    outdated = r.count ?? 0;
  }
  const perVersion = await Promise.all(
    (versions.data ?? []).map(async (v) => {
      const r = await deviceSelect(req, "*", { count: "exact", head: true }).eq("app_version", v.version_code);
      return { ...v, count: r.count ?? 0 };
    })
  );

  res.json({
    total: total.count ?? 0,
    activated: activated.count ?? 0,
    pending: pending.count ?? 0,
    revoked: revoked.count ?? 0,
    online: online.count ?? 0,
    releases: releases.count ?? 0,
    outdated,
    latest: latest.data ?? null,
    recent: recent.data ?? [],
    perVersion,
    daily: dailyBuckets((newDevices.data ?? []).map((d) => d.created_at)),
  });
});

// ---- versions ----
// The release feed is not per-reseller — everyone reads the same list (they need to know what
// their boxes will update to), but only an admin can publish or delete a build.
app.get("/api/admin/versions", requireAuth, async (_req, res) => {
  const { data } = await supabase.from("app_versions").select("*").order("version_code", { ascending: false });
  res.json({ versions: data ?? [] });
});

app.post("/api/admin/versions", requireAuth, requireAdmin, async (req, res) => {
  const b = req.body || {};
  const { error } = await supabase.from("app_versions").insert({
    version_code: Number(b.version_code),
    version_name: String(b.version_name || "").trim(),
    apk_url: String(b.apk_url || "").trim(),
    changelog: b.changelog ? String(b.changelog).trim() : null,
    force_update: !!b.force_update,
    is_published: b.is_published !== false,
  });
  if (error) return res.status(500).json({ error: error.message });
  res.json({ ok: true });
});

app.post("/api/admin/versions/:id/publish", requireAuth, requireAdmin, async (req, res) => {
  await supabase.from("app_versions").update({ is_published: !!req.body?.publish }).eq("id", req.params.id);
  res.json({ ok: true });
});

app.delete("/api/admin/versions/:id", requireAuth, requireAdmin, async (req, res) => {
  await supabase.from("app_versions").delete().eq("id", req.params.id);
  res.json({ ok: true });
});

// ---- devices ----
app.get("/api/admin/devices", requireAuth, async (req, res) => {
  const { data } = await deviceSelect(req, "*").order("created_at", { ascending: false });
  res.json({ devices: data ?? [] });
});

// Activate — URL + MAC were already stored on register, so no input is needed.
// Admin only (optionally) sets the customer name + payment status.
app.post("/api/admin/devices/:id/activate", requireAuth, async (req, res) => {
  const customer_name = String(req.body?.customer_name || "").trim() || null;
  const payment_status = String(req.body?.payment_status || "paid").trim();
  const patch = {
    customer_name,
    payment_status,
    status: "activated",
    activated_at: new Date().toISOString(),
  };

  // Activating CLAIMS the box for whoever did it, which is what stops one client's devices ever
  // appearing in another's dashboard. An unclaimed box is claimable; someone else's is not.
  const { data: row } = await supabase.from("devices")
    .select("id, reseller_id").eq("id", req.params.id).maybeSingle();
  if (!row) return res.status(404).json({ error: "No such device" });
  if (!isAdmin(req) && row.reseller_id && row.reseller_id !== req.user.sub) {
    return res.status(403).json({ error: "That device belongs to another account" });
  }
  if (!row.reseller_id) patch.reseller_id = isAdmin(req) ? (req.body?.reseller_id ?? null) : req.user.sub;

  const { error } = await supabase.from("devices").update(patch).eq("id", req.params.id);
  if (error) return res.status(500).json({ error: error.message });
  res.json({ ok: true });
});

// Toggle payment (paid / unpaid / expired). Unpaid/expired → app locks on next config poll.
app.post("/api/admin/devices/:id/payment", requireAuth, async (req, res) => {
  const payment_status = String(req.body?.payment_status || "").trim();
  if (!["paid", "unpaid", "expired"].includes(payment_status)) {
    return res.status(400).json({ error: "payment_status must be paid | unpaid | expired" });
  }
  const { error, count } = await deviceUpdate(req, { payment_status })
    .eq("id", req.params.id).select("id", { count: "exact" });
  if (error) return res.status(500).json({ error: error.message });
  if (!count) return res.status(404).json({ error: "No such device" });
  res.json({ ok: true });
});

app.post("/api/admin/devices/:id/revoke", requireAuth, async (req, res) => {
  const { count } = await deviceUpdate(req, { status: "revoked" })
    .eq("id", req.params.id).select("id", { count: "exact" });
  if (!count) return res.status(404).json({ error: "No such device" });
  res.json({ ok: true });
});

// Activate by pairing code (the QR-scanned flow)
app.get("/api/admin/by-code/:code", requireAuth, async (req, res) => {
  const { data } = await supabase.from("devices")
    .select("id, device_id, status, server_url, mac, pairing_code, customer_name, payment_status, reseller_id")
    .eq("pairing_code", String(req.params.code).trim().toUpperCase()).maybeSingle();
  // A pairing code is how an UNCLAIMED box gets adopted, so a lookup can find one that isn't yours
  // yet — but never one another reseller already owns.
  if (data && !isAdmin(req) && data.reseller_id && data.reseller_id !== req.user.sub) {
    return res.json({ device: null });
  }
  res.json({ device: data ?? null });
});

// Activate by pairing code (the QR flow). URL + MAC already stored on register —
// admin just confirms, optionally with a customer name + payment status.
app.post("/api/admin/activate", requireAuth, async (req, res) => {
  const code = String(req.body?.code || "").trim().toUpperCase();
  const customer_name = String(req.body?.customer_name || "").trim() || null;
  const payment_status = String(req.body?.payment_status || "paid").trim();
  if (!code) return res.status(400).json({ error: "code required" });
  const patch = {
    customer_name, payment_status,
    status: "activated", activated_at: new Date().toISOString(),
  };

  const { data: row } = await supabase.from("devices")
    .select("id, reseller_id").eq("pairing_code", code).maybeSingle();
  if (!row) return res.status(404).json({ error: "No device found for that code" });
  if (!isAdmin(req) && row.reseller_id && row.reseller_id !== req.user.sub) {
    return res.status(403).json({ error: "That device belongs to another account" });
  }
  // Same claim-on-activate rule as the by-id route above.
  if (!row.reseller_id && !isAdmin(req)) patch.reseller_id = req.user.sub;

  const { error } = await supabase.from("devices").update(patch).eq("id", row.id);
  if (error) return res.status(500).json({ error: error.message });
  res.json({ ok: true });
});

app.listen(PORT, async () => {
  console.log(`Apna TV backend listening on :${PORT}`);
  console.log(`  CORS ${ALLOWED_ORIGINS.length ? ALLOWED_ORIGINS.join(", ") : "any (dev)"}`);
  await bootstrapAdmin();
});
