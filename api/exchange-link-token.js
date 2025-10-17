// обмен одноразового токена на сессию (возвращаем tg_id)
const { _TOKENS } = require("./issue-link-token");

module.exports = (req, res) => {
  const ORIGIN = process.env.CORS_ORIGIN || "*";
  res.setHeader("Access-Control-Allow-Origin", ORIGIN);
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
  if (req.method === "OPTIONS") return res.status(204).end();
  if (req.method !== "POST") return res.status(405).json({ ok:false, error:"method_not_allowed" });

  const { token } = req.body || {};
  if (!token) return res.status(400).json({ ok:false, error:"no_token" });

  const rec = _TOKENS.get(token);
  if (!rec) return res.status(401).json({ ok:false, error:"invalid_or_used_token" });
  if (rec.expires_at < Date.now()) {
    _TOKENS.delete(token);
    return res.status(401).json({ ok:false, error:"expired_token" });
  }

  _TOKENS.delete(token); // одноразовый
  // для Telegram platform_id == tg_id
  return res.status(200).json({ ok:true, tg_id: String(rec.platform_id) });
};
