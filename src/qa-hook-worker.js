// QA webhook endpoint for Smallstep Protect Wi-Fi (R4, R6, R9, Q-G1).
// Cloudflare Pages Function. Served at https://showmefun.xyz/qa-hook/*
//
// Bindings (Pages project > Settings):
//   KV namespace:  QA_HOOK_KV
//   Secrets:       HOOK_BASIC_USER, HOOK_BASIC_PASS, HOOK_BEARER_TOKEN, HOOK_ADMIN_TOKEN
//   Optional:      HOOK_SIGNING_SECRET (base64, from the Smallstep UI)
//
// Webhook paths (Smallstep calls these):
//   POST /qa-hook/basic    Basic auth
//   POST /qa-hook/bearer   Bearer auth
// Admin paths (Authorization: Bearer <HOOK_ADMIN_TOKEN>):
//   GET    /qa-hook/logs?limit=20   newest first
//   DELETE /qa-hook/logs            delete all logs
//   GET    /qa-hook/response        current response JSON
//   PUT    /qa-hook/response        set response JSON
// Public:
//   GET    /qa-hook/healthz
//
// Response control keys (removed before sending):
//   "_status": 500   HTTP status to return
//   "_delay": 15     seconds to wait before the reply (max 60)
//   "_raw": "text"   send this text instead of JSON

const DEFAULT_RESPONSE = { allow: true, data: { vlan: "10", department: "qa" } };
const LOG_TTL = 60 * 60 * 24 * 30; // 30 days
const MAX_BODY = 1 << 20;
const enc = new TextEncoder();

const json = (status, obj) =>
  new Response(JSON.stringify(obj), { status, headers: { "content-type": "application/json" } });

function safeEqual(a, b) {
  const x = enc.encode(String(a)), y = enc.encode(String(b));
  if (x.length !== y.length) return false;
  if (crypto.subtle.timingSafeEqual) return crypto.subtle.timingSafeEqual(x, y);
  let d = 0;
  for (let i = 0; i < x.length; i++) d |= x[i] ^ y[i];
  return d === 0;
}

function checkAuth(kind, header, env) {
  if (kind === "basic") {
    if (!header.startsWith("Basic ")) return [false, { scheme: header.split(" ")[0] || null }];
    let u, p;
    try {
      const s = atob(header.slice(6));
      const i = s.indexOf(":");
      u = s.slice(0, i); p = s.slice(i + 1);
    } catch { return [false, { scheme: "Basic", decode: "failed" }]; }
    const pm = safeEqual(p, env.HOOK_BASIC_PASS);
    return [safeEqual(u, env.HOOK_BASIC_USER) && pm, { scheme: "Basic", username: u, password_match: pm }];
  }
  if (!header.startsWith("Bearer ")) return [false, { scheme: header.split(" ")[0] || null }];
  const ok = safeEqual(header.slice(7), env.HOOK_BEARER_TOKEN);
  return [ok, { scheme: "Bearer", token_match: ok }];
}

async function checkSig(raw, sig, env) {
  if (!sig) return null;
  if (!env.HOOK_SIGNING_SECRET) return "present (HOOK_SIGNING_SECRET not set)";
  let key;
  try { key = Uint8Array.from(atob(env.HOOK_SIGNING_SECRET), c => c.charCodeAt(0)); }
  catch { key = enc.encode(env.HOOK_SIGNING_SECRET); }
  const k = await crypto.subtle.importKey("raw", key, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const mac = new Uint8Array(await crypto.subtle.sign("HMAC", k, raw));
  const hex = [...mac].map(b => b.toString(16).padStart(2, "0")).join("");
  return safeEqual(hex, sig.toLowerCase()) ? "valid" : "INVALID";
}

async function loadResponse(env) {
  const r = (await env.QA_HOOK_KV.get("response", "json")) || structuredClone(DEFAULT_RESPONSE);
  const ctrl = {};
  for (const k of Object.keys(r)) if (k.startsWith("_")) { ctrl[k] = r[k]; delete r[k]; }
  return [Number(ctrl._status || 200), ctrl, r];
}

function isAdmin(request, env) {
  const h = request.headers.get("authorization") || "";
  return !!env.HOOK_ADMIN_TOKEN && h.startsWith("Bearer ") && safeEqual(h.slice(7), env.HOOK_ADMIN_TOKEN);
}

async function webhook(kind, request, env) {
  const len = Number(request.headers.get("content-length") || 0);
  if (len > MAX_BODY) return json(413, { error: "too large" });
  const raw = new Uint8Array(await request.arrayBuffer());
  const [ok, auth] = checkAuth(kind, request.headers.get("authorization") || "", env);
  const headers = {};
  for (const [k, v] of request.headers) headers[k] = k === "authorization" ? "<redacted>" : v;
  const text = new TextDecoder().decode(raw);
  let body = null;
  if (text) { try { body = JSON.parse(text); } catch { body = { _unparsed: text }; } }

  let status = 401, ctrl = {}, out = { error: "unauthorized" };
  if (ok) {
    [status, ctrl, out] = await loadResponse(env);
    if (ctrl._delay) await new Promise(r => setTimeout(r, Math.min(Number(ctrl._delay), 60) * 1000));
  }
  const time = new Date().toISOString();
  const entry = {
    time, path: `/qa-hook/${kind}`,
    client: request.headers.get("cf-connecting-ip"),
    auth_ok: ok, auth,
    signature: await checkSig(raw, request.headers.get("x-smallstep-signature"), env),
    headers, body,
    response: { status, body: "_raw" in ctrl ? ctrl._raw : out },
  };
  // Newest first: key sorts by inverted timestamp.
  const key = `log:${String(9999999999999 - Date.now()).padStart(13, "0")}:${crypto.randomUUID()}`;
  await env.QA_HOOK_KV.put(key, JSON.stringify(entry), { expirationTtl: LOG_TTL });

  if ("_raw" in ctrl) return new Response(String(ctrl._raw), { status, headers: { "content-type": "text/plain" } });
  return json(status, out);
}

export async function onRequest({ request, env, params }) {
  const path = (params.path || []).join("/");
  const m = request.method;

  if (!env.QA_HOOK_KV || !env.HOOK_BASIC_USER || !env.HOOK_BASIC_PASS || !env.HOOK_BEARER_TOKEN)
    return json(500, { error: "not configured: set QA_HOOK_KV binding and HOOK_* secrets" });

  if (path === "healthz" && m === "GET") return json(200, { ok: true });
  if ((path === "basic" || path === "bearer") && m === "POST") return webhook(path, request, env);

  if (path === "logs" || path === "response") {
    if (!isAdmin(request, env)) return json(401, { error: "unauthorized" });
    if (path === "logs" && m === "GET") {
      const limit = Math.min(Number(new URL(request.url).searchParams.get("limit") || 20), 100);
      const { keys } = await env.QA_HOOK_KV.list({ prefix: "log:", limit });
      const logs = await Promise.all(keys.map(k => env.QA_HOOK_KV.get(k.name, "json")));
      return json(200, logs.filter(Boolean));
    }
    if (path === "logs" && m === "DELETE") {
      let n = 0, cursor;
      do {
        const r = await env.QA_HOOK_KV.list({ prefix: "log:", cursor });
        await Promise.all(r.keys.map(k => env.QA_HOOK_KV.delete(k.name)));
        n += r.keys.length; cursor = r.list_complete ? undefined : r.cursor;
      } while (cursor);
      return json(200, { deleted: n });
    }
    if (path === "response" && m === "GET")
      return json(200, (await env.QA_HOOK_KV.get("response", "json")) || DEFAULT_RESPONSE);
    if (path === "response" && m === "PUT") {
      let r;
      try { r = await request.json(); } catch { return json(400, { error: "body must be JSON" }); }
      if (typeof r !== "object" || r === null || Array.isArray(r)) return json(400, { error: "body must be a JSON object" });
      await env.QA_HOOK_KV.put("response", JSON.stringify(r));
      return json(200, r);
    }
  }
  return json(404, { error: "not found" });
}

// ---- Workers entry point (static-assets Worker) ----
// /qa-hook/* is handled here; every other path is served from the static assets.
export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    if (url.pathname === "/qa-hook" || url.pathname.startsWith("/qa-hook/")) {
      const path = url.pathname.slice("/qa-hook".length).split("/").filter(Boolean);
      return onRequest({ request, env, params: { path } });
    }
    return env.ASSETS.fetch(request);
  },
};
