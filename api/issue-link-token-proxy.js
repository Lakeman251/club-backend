const crypto = require("crypto");
module.exports = (req, res) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
  if (req.method === "OPTIONS") return res.status(204).end();

  const { platform_id } = req.body || {};
  if (!platform_id) return res.status(400).send("no_platform_id");

  const payload = { tg_id: String(platform_id), exp: Date.now() + 600000 };
  const payloadB64 = Buffer.from(JSON.stringify(payload)).toString("base64");
  const sig = crypto
    .createHmac("sha256", process.env.JWT_SECRET)
    .update(payloadB64)
    .digest("base64")
    .replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
  const token = `${payloadB64}.${sig}`;
  res.send(token); // ← просто строка, без JSON
};
