# Apna TV — Backend (Express API)

Standalone API server for OTA updates, QR device activation and the dashboard.
Deploys on **Render** (Node web service, always-on).

## Run locally
```bash
cd backend
npm install
cp .env.example .env   # fill in your Supabase values
npm start              # http://localhost:4000
```

## Deploy on Render
1. New → **Web Service** → connect the repo (or this `backend/` folder).
2. Build command: `npm install` · Start command: `npm start`
3. Add Environment variables: `SUPABASE_URL`, `SUPABASE_SERVICE_ROLE_KEY`,
   `ADMIN_EMAIL`, `ADMIN_PASSWORD`, `AUTH_SECRET`, (optional) `DASHBOARD_URL`.
4. Deploy → you get `https://apnatv-backend.onrender.com`.

## Endpoints
App-facing: `POST /api/device/register`, `GET /api/device/config`,
`GET /api/version/check`, `GET /api/qr`.
Dashboard-facing (Bearer auth): `POST /api/admin/login`, `GET /api/admin/overview`,
`GET/POST /api/admin/versions`, `POST /api/admin/devices/:id/activate|revoke`,
`POST /api/admin/activate`.
