import "dotenv/config"; // loads .env locally; a no-op on Render (vars come from the platform)
import express from "express";
import cors from "cors";
import QRCode from "qrcode";
import { createClient } from "@supabase/supabase-js";

// ---------- config ----------
const PORT = process.env.PORT || 4000;
const SUPABASE_URL = process.env.SUPABASE_URL || process.env.NEXT_PUBLIC_SUPABASE_URL;
const SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;
const ADMIN_EMAIL = process.env.ADMIN_EMAIL || "admin@apnatv.com";
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "apnatv2026";
const AUTH_SECRET = process.env.AUTH_SECRET || "apnatv-7f3c1e9a8b2d4f6e-session";
// Where the QR-scanned activation page lives (the dashboard). Used to build the QR link.
const DASHBOARD_URL = process.env.DASHBOARD_URL || "";
// The ONLY portal every box connects to — hardcoded here and in the app (RemoteConfig).
// star.homeip.net is correct: the app's RedirectFixInterceptor resolves it to the live backend.
const STATIC_PORTAL_URL = process.env.STATIC_PORTAL_URL || "http://star.homeip.net";

if (!SUPABASE_URL || !SERVICE_ROLE_KEY) {
  console.error("FATAL: SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY env vars are required.");
}

const supabase = createClient(SUPABASE_URL, SERVICE_ROLE_KEY, {
  auth: { persistSession: false },
});

const app = express();
app.use(cors()); // allow the dashboard (Netlify) + app to call us
app.use(express.json());

// ---------- helpers ----------
const ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
function genPairingCode(len = 6) {
  let out = "";
  for (let i = 0; i < len; i++) out += ALPHABET[Math.floor(Math.random() * ALPHABET.length)];
  return out;
}

// Admin auth: the dashboard logs in and sends `Authorization: Bearer <AUTH_SECRET>`.
function requireAuth(req, res, next) {
  const token = (req.headers.authorization || "").replace(/^Bearer\s+/i, "");
  if (token !== AUTH_SECRET) return res.status(401).json({ error: "unauthorized" });
  next();
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
    await supabase
      .from("devices")
      .update({ app_version: current, last_seen: new Date().toISOString() })
      .eq("device_id", device_id);
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

// POST /api/admin/login  { email, password } -> { token }
app.post("/api/admin/login", (req, res) => {
  const email = String(req.body?.email || "").trim().toLowerCase();
  const password = String(req.body?.password || "");
  if (email === ADMIN_EMAIL.toLowerCase() && password === ADMIN_PASSWORD) {
    return res.json({ token: AUTH_SECRET, email: ADMIN_EMAIL });
  }
  res.status(401).json({ error: "Invalid email or password" });
});

// GET /api/admin/overview -> stats
app.get("/api/admin/overview", requireAuth, async (_req, res) => {
  const since5 = new Date(Date.now() - 5 * 60 * 1000).toISOString();
  const head = (mod) => mod(supabase.from("devices").select("*", { count: "exact", head: true }));
  const [total, activated, pending, revoked, online, releases, latest, recent, versions] =
    await Promise.all([
      head((q) => q),
      head((q) => q.eq("status", "activated")),
      head((q) => q.eq("status", "pending")),
      head((q) => q.eq("status", "revoked")),
      head((q) => q.gte("last_seen", since5)),
      supabase.from("app_versions").select("*", { count: "exact", head: true }),
      supabase.from("app_versions").select("version_code, version_name, force_update")
        .eq("is_published", true).order("version_code", { ascending: false }).limit(1).maybeSingle(),
      supabase.from("devices").select("device_id, status, app_version, server_url, last_seen, created_at")
        .order("created_at", { ascending: false }).limit(8),
      supabase.from("app_versions").select("version_code, version_name").order("version_code", { ascending: false }),
    ]);

  const latestCode = latest.data?.version_code ?? 0;
  let outdated = 0;
  if (latestCode > 0) {
    const r = await supabase.from("devices").select("*", { count: "exact", head: true }).lt("app_version", latestCode);
    outdated = r.count ?? 0;
  }
  const perVersion = await Promise.all(
    (versions.data ?? []).map(async (v) => {
      const r = await supabase.from("devices").select("*", { count: "exact", head: true }).eq("app_version", v.version_code);
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
  });
});

// ---- versions ----
app.get("/api/admin/versions", requireAuth, async (_req, res) => {
  const { data } = await supabase.from("app_versions").select("*").order("version_code", { ascending: false });
  res.json({ versions: data ?? [] });
});

app.post("/api/admin/versions", requireAuth, async (req, res) => {
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

app.post("/api/admin/versions/:id/publish", requireAuth, async (req, res) => {
  await supabase.from("app_versions").update({ is_published: !!req.body?.publish }).eq("id", req.params.id);
  res.json({ ok: true });
});

app.delete("/api/admin/versions/:id", requireAuth, async (req, res) => {
  await supabase.from("app_versions").delete().eq("id", req.params.id);
  res.json({ ok: true });
});

// ---- devices ----
app.get("/api/admin/devices", requireAuth, async (_req, res) => {
  const { data } = await supabase.from("devices").select("*").order("created_at", { ascending: false });
  res.json({ devices: data ?? [] });
});

// Activate — URL + MAC were already stored on register, so no input is needed.
// Admin only (optionally) sets the customer name + payment status.
app.post("/api/admin/devices/:id/activate", requireAuth, async (req, res) => {
  const customer_name = String(req.body?.customer_name || "").trim() || null;
  const payment_status = String(req.body?.payment_status || "paid").trim();
  const { error } = await supabase.from("devices").update({
    customer_name,
    payment_status,
    status: "activated",
    activated_at: new Date().toISOString(),
  }).eq("id", req.params.id);
  if (error) return res.status(500).json({ error: error.message });
  res.json({ ok: true });
});

// Toggle payment (paid / unpaid / expired). Unpaid/expired → app locks on next config poll.
app.post("/api/admin/devices/:id/payment", requireAuth, async (req, res) => {
  const payment_status = String(req.body?.payment_status || "").trim();
  if (!["paid", "unpaid", "expired"].includes(payment_status)) {
    return res.status(400).json({ error: "payment_status must be paid | unpaid | expired" });
  }
  const { error } = await supabase.from("devices")
    .update({ payment_status }).eq("id", req.params.id);
  if (error) return res.status(500).json({ error: error.message });
  res.json({ ok: true });
});

app.post("/api/admin/devices/:id/revoke", requireAuth, async (req, res) => {
  await supabase.from("devices").update({ status: "revoked" }).eq("id", req.params.id);
  res.json({ ok: true });
});

// Activate by pairing code (the QR-scanned flow)
app.get("/api/admin/by-code/:code", requireAuth, async (req, res) => {
  const { data } = await supabase.from("devices")
    .select("id, device_id, status, server_url, mac, pairing_code, customer_name, payment_status")
    .eq("pairing_code", String(req.params.code).trim().toUpperCase()).maybeSingle();
  res.json({ device: data ?? null });
});

// Activate by pairing code (the QR flow). URL + MAC already stored on register —
// admin just confirms, optionally with a customer name + payment status.
app.post("/api/admin/activate", requireAuth, async (req, res) => {
  const code = String(req.body?.code || "").trim().toUpperCase();
  const customer_name = String(req.body?.customer_name || "").trim() || null;
  const payment_status = String(req.body?.payment_status || "paid").trim();
  if (!code) return res.status(400).json({ error: "code required" });
  const { data, error } = await supabase.from("devices").update({
    customer_name, payment_status,
    status: "activated", activated_at: new Date().toISOString(),
  }).eq("pairing_code", code).select("id").maybeSingle();
  if (error) return res.status(500).json({ error: error.message });
  if (!data) return res.status(404).json({ error: "No device found for that code" });
  res.json({ ok: true });
});

app.listen(PORT, () => console.log(`Apna TV backend listening on :${PORT}`));
