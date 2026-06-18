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

// POST /api/device/register  { device_id, model?, sig_sha256?, app_version? }
app.post("/api/device/register", async (req, res) => {
  const device_id = String(req.body?.device_id || "").trim();
  if (!device_id) return res.status(400).json({ error: "device_id required" });

  const { data: existing } = await supabase
    .from("devices")
    .select("id, status, pairing_code")
    .eq("device_id", device_id)
    .maybeSingle();

  if (existing?.status === "activated") {
    return res.json({ status: "activated", pairing_code: existing.pairing_code });
  }

  const pairing_code = existing?.pairing_code ?? genPairingCode();
  const { error } = await supabase.from("devices").upsert(
    {
      device_id,
      pairing_code,
      status: existing?.status ?? "pending",
      model: req.body?.model ?? null,
      sig_sha256: req.body?.sig_sha256 ?? null,
      app_version: req.body?.app_version ?? null,
      last_seen: new Date().toISOString(),
    },
    { onConflict: "device_id" }
  );
  if (error) return res.status(500).json({ error: error.message });
  res.json({ status: "pending", pairing_code });
});

// GET /api/device/config?device_id=...
app.get("/api/device/config", async (req, res) => {
  const device_id = String(req.query.device_id || "").trim();
  if (!device_id) return res.status(400).json({ error: "device_id required" });

  const { data } = await supabase
    .from("devices")
    .select("status, server_url, mac")
    .eq("device_id", device_id)
    .maybeSingle();
  if (!data) return res.status(404).json({ status: "unknown" });

  await supabase
    .from("devices")
    .update({ last_seen: new Date().toISOString() })
    .eq("device_id", device_id);

  if (data.status === "activated") {
    return res.json({ status: "activated", server_url: data.server_url, mac: data.mac });
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

app.post("/api/admin/devices/:id/activate", requireAuth, async (req, res) => {
  const server_url = String(req.body?.server_url || "").trim();
  const mac = String(req.body?.mac || "").trim();
  if (!server_url || !mac) return res.status(400).json({ error: "server_url and mac required" });
  const { error } = await supabase.from("devices").update({
    server_url, mac, status: "activated", activated_at: new Date().toISOString(),
  }).eq("id", req.params.id);
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
    .select("id, device_id, status, server_url, mac, pairing_code")
    .eq("pairing_code", String(req.params.code).trim().toUpperCase()).maybeSingle();
  res.json({ device: data ?? null });
});

app.post("/api/admin/activate", requireAuth, async (req, res) => {
  const code = String(req.body?.code || "").trim().toUpperCase();
  const server_url = String(req.body?.server_url || "").trim();
  const mac = String(req.body?.mac || "").trim();
  if (!code || !server_url || !mac) return res.status(400).json({ error: "code, server_url, mac required" });
  const { data, error } = await supabase.from("devices").update({
    server_url, mac, status: "activated", activated_at: new Date().toISOString(),
  }).eq("pairing_code", code).select("id").maybeSingle();
  if (error) return res.status(500).json({ error: error.message });
  if (!data) return res.status(404).json({ error: "No device found for that code" });
  res.json({ ok: true });
});

app.listen(PORT, () => console.log(`Apna TV backend listening on :${PORT}`));
