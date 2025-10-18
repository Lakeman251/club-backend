// api/exchange-link-token.js
const crypto = require("crypto");

// ===== utils =====
function b64urlDecode(str) {
  str = String(str).replace(/-/g, "+").replace(/_/g, "/");
  str = str.replace(/=+$/g, "");
  const padLen = (4 - (str.length % 4)) % 4;
  if (padLen) str += "=".repeat(padLen);
  return Buffer.from(str, "base64").toString();
}

function sign(data, secret) {
  return crypto.createHmac("sha256", secret)
    .update(data)
    .digest("base64")
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");
}

// ===== helper: генерируем сессионный токен =====
function makeSession(tg_id) {
  const exp = Date.now() + 24 * 60 * 60 * 1000; // 24 часа
  const payload = Buffer.from(JSON.stringify({ tg_id, exp })).toString("base64")
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");
  const sig = crypto.createHmac("sha256", process.env.JWT_SECRET || "")
    .update(payload)
    .digest("base64")
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");
  return `${payload}.${sig}`;
}

// ===== handler =====
module.exports = (req, res) => {
  const ORIGIN = process.env.CORS_ORIGIN || "*";
  res.setHeader("Access-Control-Allow-Origin", ORIGIN);
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
  if (req.method === "OPTIONS") return res.status(204).end();
  if (req.method !== "POST")
    return res.status(405).json({ ok: false, error: "method_not_allowed" });

 // --- нормализуем вход ---
let raw;
if (typeof req.body === "string") {
  raw = req.body.trim();                // пришло как text/plain
} else {
  raw = (req.body?.token ?? "").toString().trim(); // пришло как JSON
}
raw = raw.replace(/^"+|"+$/g, "");
raw = decodeURIComponent(raw);

  const [payloadB64, sig] = raw.split(".");
  if (!payloadB64 || !sig)
    return res.status(401).json({ ok: false, error: "invalid_token_format" });

  // --- проверяем подпись ---
  const expected = sign(payloadB64, process.env.JWT_SECRET || "");
  if (expected !== sig)
    return res.status(401).json({ ok: false, error: "invalid_signature" });

  // --- декодируем payload ---
  let payload;
  try {
    payload = JSON.parse(b64urlDecode(payloadB64));
  } catch {
    return res.status(401).json({ ok: false, error: "bad_payload" });
  }

  // --- логические проверки ---
  if (!payload.tg_id)
    return res.status(401).json({ ok: false, error: "no_tg_id" });
  if (Date.now() > Number(payload.exp))
    return res.status(401).json({ ok: false, error: "expired_token" });

  // --- создаём cookie-сессию ---
  const session = makeSession(payload.tg_id);
  res.setHeader(
    "Set-Cookie",
    `session=${session}; Path=/; HttpOnly; Secure; SameSite=None; Max-Age=${24 * 60 * 60}`
  );

  // --- успех ---
  return res.status(200).json({
    ok: true,
    tg_id: payload.tg_id,
    sb_user_id: payload.sb_user_id || null,
    session
  });
};
