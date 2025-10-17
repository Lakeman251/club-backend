const crypto = require("crypto");

const TOKENS = new Map();

module.exports = (req, res) => {
  const ORIGIN = process.env.CORS_ORIGIN || "*";
  res.setHeader("Access-Control-Allow-Origin", ORIGIN);
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, X-Webhook-Secret");
  if (req.method === "OPTIONS") return res.status(204).end();
  if (req.method !== "POST") return res.status(405).json({ ok:false, error:"method_not_allowed" });

  const got = req.headers["x-webhook-secret"];
  if (!got || got !== process.env.WEBHOOK_SECRET) {
    return res.status(401).json({ ok:false, error:"bad_secret" });
  }

  const { platform_id, sb_user_id } = req.body || {};
  if (!platform_id) return res.status(400).json({ ok:false, error:"no_platform_id" });

  const token = crypto.randomBytes(24).toString("base64url");
  const expires_at = Date.now() + 2 * 60 * 1000; // 2 минуты

  TOKENS.set(token, { platform_id, sb_user_id, expires_at });
  for (const [k, v] of TOKENS) if (v.expires_at < Date.now()) TOKENS.delete(k);

  return res.status(200).json({ ok:true, token, ttl_sec:120 });
};

module.exports._TOKENS = TOKENS;
