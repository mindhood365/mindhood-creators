import crypto from "node:crypto";

export const config = { path: "/api/*" };

// ---------- storage ----------
const mem = {};
function store(name) {
  if (process.env.LOCAL_DB) {
    const m = (mem[name] ||= new Map());
    return {
      get: async (k) => (m.has(k) ? JSON.parse(m.get(k)) : null),
      setJSON: async (k, v) => void m.set(k, JSON.stringify(v)),
      delete: async (k) => void m.delete(k),
      list: async ({ prefix = "" } = {}) => ({ blobs: [...m.keys()].filter((k) => k.startsWith(prefix)).map((key) => ({ key })) }),
    };
  }
  return globalThis.__getStore({ name, consistency: "strong" });
}
async function init() {
  if (!process.env.LOCAL_DB && !globalThis.__getStore) {
    globalThis.__getStore = (await import("@netlify/blobs")).getStore;
  }
}
const all = async (s, prefix) => {
  const { blobs } = await s.list({ prefix });
  return (await Promise.all(blobs.map((b) => s.get(b.key, { type: "json" })))).filter(Boolean);
};

// ---------- helpers ----------
const json = (o, status = 200) =>
  new Response(JSON.stringify(o), { status, headers: { "content-type": "application/json" } });
const b64 = (b) => Buffer.from(b).toString("base64url");
const eq = (a, b) => {
  const x = Buffer.from(String(a)), y = Buffer.from(String(b));
  return x.length === y.length && crypto.timingSafeEqual(x, y);
};
const hash = (pw, salt) => crypto.scryptSync(pw, salt, 32).toString("hex");

async function secret() {
  const m = store("meta");
  let s = await m.get("secret", { type: "json" });
  if (!s) { s = { v: crypto.randomBytes(32).toString("hex") }; await m.setJSON("secret", s); }
  return s.v;
}
async function ingestKey() {
  if (process.env.INGEST_KEY) return process.env.INGEST_KEY;
  const m = store("meta");
  let s = await m.get("ingest", { type: "json" });
  if (!s) { s = { v: crypto.randomBytes(24).toString("hex") }; await m.setJSON("ingest", s); }
  return s.v;
}
async function sign(payload, ttlSec) {
  const body = b64(JSON.stringify({ ...payload, exp: Date.now() + ttlSec * 1000 }));
  const sig = crypto.createHmac("sha256", await secret()).update(body).digest("base64url");
  return body + "." + sig;
}
async function verify(token) {
  if (!token) return null;
  const [body, sig] = token.split(".");
  if (!body || !sig) return null;
  const good = crypto.createHmac("sha256", await secret()).update(body).digest("base64url");
  if (!eq(sig, good)) return null;
  try {
    const p = JSON.parse(Buffer.from(body, "base64url").toString());
    return p.exp > Date.now() ? p : null;
  } catch { return null; }
}
const bearer = (req) => (req.headers.get("authorization") || "").replace(/^Bearer /, "");

async function throttle(key) {
  const m = store("meta");
  const k = "rl:" + crypto.createHash("sha1").update(key).digest("hex");
  const r = (await m.get(k, { type: "json" })) || { n: 0, t: Date.now() };
  if (Date.now() - r.t > 15 * 60 * 1000) { r.n = 0; r.t = Date.now(); }
  if (r.n >= 8) return false;
  r.n++; await m.setJSON(k, r);
  return true;
}
const clearThrottle = (key) => store("meta").delete("rl:" + crypto.createHash("sha1").update(key).digest("hex"));

const cleanId = (s) => String(s || "").trim().toLowerCase().replace(/[^a-z0-9._-]/g, "");
const cleanCode = (s) => String(s || "").trim().toUpperCase().replace(/[^A-Z0-9]/g, "");
const commission = (amt) => (amt >= 9999 ? 2000 : amt >= 5999 ? 1000 : amt >= 1999 ? 500 : amt >= 99 ? 90 : 0);
const tierOf = (amt) => (amt >= 9999 ? "l3" : amt >= 5999 ? "l2" : amt >= 1999 ? "l1" : "s99");
const genPw = () => {
  const a = "abcdefghjkmnpqrstuvwxyz", n = "23456789";
  let s = "";
  for (let i = 0; i < 6; i++) s += a[crypto.randomInt(a.length)];
  return s.charAt(0).toUpperCase() + s.slice(1) + "@" + crypto.randomInt(1000, 9999) + n[crypto.randomInt(n.length)];
};
const mask = (v) => (v ? "•".repeat(Math.max(0, String(v).length - 4)) + String(v).slice(-4) : "");

const PROFILE_KEYS = ["email", "phone", "tg", "cycle", "method", "holder", "bank", "acc", "ifsc", "upi"];
const pub = (c, withFull) => ({
  id: c.id, name: c.name, code: c.code, active: c.active, created: c.created,
  profile: { ...c.profile, acc: withFull ? c.profile.acc : mask(c.profile.acc), accSet: !!c.profile.acc },
});

// ---------- handler ----------
export default async (req) => {
  await init();
  const url = new URL(req.url);
  const path = url.pathname.replace(/^\/api/, "").replace(/\/$/, "") || "/";
  const method = req.method;
  let body = {};
  if (method === "POST") { try { body = await req.json(); } catch { body = {}; } }
  const creators = store("creators"), refs = store("referrals");
  const ip = req.headers.get("x-nf-client-connection-ip") || "x";

  try {
    // ----- creator -----
    if (path === "/login" && method === "POST") {
      const id = cleanId(body.id);
      if (!(await throttle("c:" + id + ip))) return json({ error: "Too many attempts. Try again in 15 minutes." }, 429);
      const c = await creators.get("c:" + id, { type: "json" });
      if (!c || !c.active || !eq(hash(String(body.pw || ""), c.salt), c.hash)) return json({ error: "Wrong ID or password" }, 401);
      await clearThrottle("c:" + id + ip);
      return json({ token: await sign({ r: "c", id }, 7 * 86400) });
    }
    if (path === "/me" && method === "GET") {
      const p = await verify(bearer(req));
      if (!p || p.r !== "c") return json({ error: "auth" }, 401);
      const c = await creators.get("c:" + p.id, { type: "json" });
      if (!c || !c.active) return json({ error: "auth" }, 401);
      const rows = (await all(refs, "r:" + c.code + ":")).sort((a, b) => b.ts - a.ts);
      return json({ creator: pub(c, false), referrals: rows.map(({ id, tier, amount, commission, ts, who, status }) => ({ id, tier, amount, commission, ts, who, status })) });
    }
    if (path === "/me/profile" && method === "POST") {
      const p = await verify(bearer(req));
      if (!p || p.r !== "c") return json({ error: "auth" }, 401);
      const c = await creators.get("c:" + p.id, { type: "json" });
      if (!c) return json({ error: "auth" }, 401);
      for (const k of PROFILE_KEYS) {
        if (body[k] === undefined) continue;
        if (k === "acc" && /•/.test(String(body[k]))) continue; // masked, unchanged
        c.profile[k] = String(body[k]).slice(0, 80);
      }
      await creators.setJSON("c:" + p.id, c);
      return json({ creator: pub(c, false) });
    }

    // ----- ingest (Make) -----
    if (path === "/ingest" && method === "POST") {
      if (!eq(body.key || "", await ingestKey())) return json({ error: "key" }, 401);
      const code = cleanCode(body.code);
      const cid = code && (await creators.get("code:" + code, { type: "json" }));
      if (!cid) return json({ ok: true, matched: false });
      const c = await creators.get("c:" + cid.id, { type: "json" });
      const amount = Number(body.amount) || 0;
      const pid = String(body.payment_id || "").replace(/[^A-Za-z0-9_-]/g, "");
      if (!pid || !amount) return json({ error: "payment_id and amount required" }, 400);
      const key = "r:" + code + ":" + pid;
      if (!(await refs.get(key, { type: "json" }))) {
        await refs.setJSON(key, {
          id: pid, code, tier: tierOf(amount), amount, commission: commission(amount),
          ts: Number(body.ts) || Date.now(), who: String(body.buyer || "").slice(0, 40), status: "pending",
        });
      }
      return json({ ok: true, matched: true, creator: { name: c.name, tg: c.profile.tg, phone: c.profile.phone }, commission: commission(amount) });
    }

    // ----- admin -----
    if (path === "/admin/login" && method === "POST") {
      const pw = process.env.ADMIN_PASSWORD;
      if (!pw) return json({ error: "ADMIN_PASSWORD not set in Netlify" }, 500);
      if (!(await throttle("a:" + ip))) return json({ error: "Too many attempts. Try again later." }, 429);
      if (!eq(String(body.pw || ""), pw)) return json({ error: "Wrong password" }, 401);
      await clearThrottle("a:" + ip);
      return json({ token: await sign({ r: "a" }, 12 * 3600) });
    }
    if (path.startsWith("/admin/")) {
      const p = await verify(bearer(req));
      if (!p || p.r !== "a") return json({ error: "auth" }, 401);

      if (path === "/admin/overview" && method === "GET") {
        const cs = await all(creators, "c:");
        const rows = await all(refs, "r:");
        const list = cs.map((c) => {
          const mine = rows.filter((r) => r.code === c.code && r.status !== "refunded");
          const due = mine.filter((r) => r.status === "pending" || r.status === "ready").reduce((s, r) => s + r.commission, 0);
          const paid = mine.filter((r) => r.status === "paid").reduce((s, r) => s + r.commission, 0);
          return { ...pub(c, false), sales: mine.length, due, paid };
        });
        return json({ creators: list, ingestKey: await ingestKey() });
      }
      if (path === "/admin/creators" && method === "POST") {
        const id = cleanId(body.id), name = String(body.name || "").trim().slice(0, 60);
        if (!id || !name) return json({ error: "Name and ID required" }, 400);
        if (await creators.get("c:" + id, { type: "json" })) return json({ error: "ID already exists" }, 409);
        let code = "";
        for (let i = 0; i < 20 && !code; i++) {
          const al = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
          let c = "";
          for (let j = 0; j < 6; j++) c += al[crypto.randomInt(al.length)];
          if (!(await creators.get("code:" + c, { type: "json" }))) code = c;
        }
        if (!code) return json({ error: "Could not make a code, try again" }, 500);
        const pw = String(body.pw || "").length >= 6 ? String(body.pw) : genPw();
        const salt = crypto.randomBytes(16).toString("hex");
        const c = {
          id, name, code, salt, hash: hash(pw, salt), active: true, created: Date.now(),
          profile: { email: "", phone: String(body.phone || "").slice(0, 20), tg: String(body.tg || "").slice(0, 20), cycle: "monthly", method: "upi", holder: "", bank: "", acc: "", ifsc: "", upi: "" },
        };
        await creators.setJSON("c:" + id, c);
        await creators.setJSON("code:" + code, { id });
        return json({ creator: pub(c, false), password: pw });
      }
      const m = path.match(/^\/admin\/creators\/([a-z0-9._-]+)(\/[a-z-]+)?$/);
      if (m) {
        const c = await creators.get("c:" + m[1], { type: "json" });
        if (!c) return json({ error: "not found" }, 404);
        if (!m[2] && method === "GET") {
          const rows = (await all(refs, "r:" + c.code + ":")).sort((a, b) => b.ts - a.ts);
          return json({ creator: pub(c, true), referrals: rows });
        }
        if (m[2] === "/reset" && method === "POST") {
          const pw = genPw();
          c.salt = crypto.randomBytes(16).toString("hex"); c.hash = hash(pw, c.salt);
          await creators.setJSON("c:" + c.id, c);
          return json({ password: pw });
        }
        if (m[2] === "/recode" && method === "POST") {
          let code = "";
          for (let i = 0; i < 20 && !code; i++) {
            const al = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
            let c = "";
            for (let j = 0; j < 6; j++) c += al[crypto.randomInt(al.length)];
            if (!(await creators.get("code:" + c, { type: "json" }))) code = c;
          }
          const old = c.code;
          for (const r of await all(refs, "r:" + old + ":")) {
            await refs.setJSON("r:" + code + ":" + r.id, { ...r, code });
            await refs.delete("r:" + old + ":" + r.id);
          }
          await creators.setJSON("code:" + code, { id: c.id });
          await creators.delete("code:" + old);
          c.code = code; await creators.setJSON("c:" + c.id, c);
          return json({ code });
        }
        if (m[2] === "/active" && method === "POST") {
          c.active = !!body.active; await creators.setJSON("c:" + c.id, c);
          return json({ ok: true });
        }
        if (m[2] === "/mark-paid" && method === "POST") {
          const rows = await all(refs, "r:" + c.code + ":");
          let n = 0, sum = 0;
          for (const r of rows) {
            if (r.status === "pending" || r.status === "ready") {
              r.status = "paid"; r.paidAt = Date.now();
              await refs.setJSON("r:" + c.code + ":" + r.id, r); n++; sum += r.commission;
            }
          }
          return json({ ok: true, count: n, amount: sum });
        }
        if (m[2] === "/refund" && method === "POST") {
          const key = "r:" + c.code + ":" + String(body.payment_id || "");
          const r = await refs.get(key, { type: "json" });
          if (!r) return json({ error: "not found" }, 404);
          r.status = "refunded"; await refs.setJSON(key, r);
          return json({ ok: true });
        }
      }
    }
    return json({ error: "not found" }, 404);
  } catch (e) {
    console.error(e);
    return json({ error: "server error" }, 500);
  }
};
