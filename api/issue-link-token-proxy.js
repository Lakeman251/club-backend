// api/issue-link-token-proxy.js
const crypto = require("crypto");

module.exports = (req, res) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
  if (req.method === "OPTIONS") return res.status(204).end();

  const { platform_id } = req.body || {};
  if (!platform_id) return res.status(400).send("no_platform_id");

  // TTL токена — 2 часа
  const payload = {
    tg_id: String(platform_id),
    exp: Date.now() + 2 * 60 * 60 * 1000 // 2 часа
  };

  const payloadB64 = Buffer.from(JSON.stringify(payload)).toString("base64");
  const sig = crypto
    .createHmac("sha256", process.env.JWT_SECRET)
    .update(payloadB64)
    .digest("base64")
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");

  const token = `${payloadB64}.${sig}`;
  res.send(token); // возвращаем просто строку токена
};
