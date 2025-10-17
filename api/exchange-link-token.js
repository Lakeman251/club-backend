// api/issue-link-token.js
const crypto = require("crypto");

function b64url(buf) {
  return Buffer.from(buf).toString("base64").replace(/=/g,"").replace(/\+/g,"-").replace(/\//g,"_");
}
function sign(data, secret) {
  return crypto.createHmac("sha256", secret).update(data).digest("base64")
    .replace(/=/g,"").replace(/\+/g,"-").replace(/\//g,"_");
}

module.exports = (req, res) => {
  const ORIGIN = process.env.CORS_ORIGIN || "*";
  res.setHeader("Access-Control-Allow-Origin", ORIGIN);
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, X-WebHook-Secret");
  if (req.method === "OPTIONS") return res.status(204).end();
  if (req.method !== "POST") return res.status(405).json({ ok:false, error:"method_not_allowed" });

  // проверка секрета от SaleBot
  const got = req.headers["x-webhook-secret"];
  if (!got || got !== process.env.WEBHOOK_SECRET) {
    return res.status(401).json({ ok:false, error:"bad_secret" });
  }

  const { platform_id, sb_user_id } = req.body || {};
  if (!platform_id) return res.status(400).json({ ok:false, error:"no_platform_id" });

  // payload токена
  const payload = {
    tg_id: String(platform_id),
    sb_user_id: String(sb_user_id || ""),
    exp: Date.now() + 10 * 60 * 1000 // 10 минут
  };

  const payloadStr = JSON.stringify(payload);
  const payloadB64 = b64url(payloadStr);
  const sig = sign(payloadB64, process.env.JWT_SECRET || "");
  const token = `${payloadB64}.${sig}`;

  // Отдаём в двух полях под синтаксис SaleBot
  return res.status(200).json({
    ok: true,
    token,
    custom_answer: token
  });
};
