// api/exchange-link-token.js
const crypto = require("crypto");

// --- утилиты ---
function b64urlDecode(str) {
  str = str.replace(/-/g, "+").replace(/_/g, "/");
  const pad = 4 - (str.length % 4 || 4);
  return Buffer.from(str + "=".repeat(pad), "base64").toString();
}

function sign(data, secret) {
  return crypto
    .createHmac("sha256", secret)
    .update(data)
    .digest("base64")
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");
}

// --- обработчик ---
module.exports = (req, res) => {
  const ORIGIN = process.env.CORS_ORIGIN || "*";
  res.setHeader("Access-Control-Allow-Origin", ORIGIN);
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
  if (req.method === "OPTIONS") return res.status(204).end();
  if (req.method !== "POST")
    return res.status(405).json({ ok: false, error: "method_not_allowed" });

  // --- получаем и нормализуем токен ---
  let raw = (req.body?.token ?? "").toString().trim();
  raw = raw.replace(/^"+|"+$/g, ""); // срезаем кавычки, если есть
  raw = decodeURIComponent(raw); // и на всякий случай раскодируем

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

  // --- валидация ---
  if (!payload.tg_id)
    return res.status(401).json({ ok: false, error: "no_tg_id" });
  if (Date.now() > Number(payload.exp))
    return res.status(401).json({ ok: false, error: "expired_token" });

  // --- успех ---
  return res.status(200).json({ ok: true, tg_id: payload.tg_id });
};
