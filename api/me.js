const crypto = require("crypto");

function b64urlDecode(str) {
  str = String(str).replace(/-/g, "+").replace(/_/g, "/");
  str = str.replace(/=+$/g, "");
  const padLen = (4 - (str.length % 4)) % 4;
  if (padLen) str += "=".repeat(padLen);
  return Buffer.from(str, "base64").toString();
}
function verify(token, secret) {
  if (!token) return null;
  const [p, s] = String(token).split(".");
  if (!p || !s) return null;
  const expSig = crypto.createHmac("sha256", secret).update(p).digest("base64")
    .replace(/=/g,"").replace(/\+/g,"-").replace(/\//g,"_");
  if (expSig !== s) return null;
  let payload;
  try { payload = JSON.parse(b64urlDecode(p)); } catch { return null; }
  if (Date.now() > Number(payload.exp)) return null;
  return payload;
}

module.exports = (req, res) => {
  const ORIGIN = process.env.CORS_ORIGIN || "https://lakeman251.github.io";
  // CORS для куки
  res.setHeader("Access-Control-Allow-Origin", ORIGIN);
  res.setHeader("Vary", "Origin");
  res.setHeader("Access-Control-Allow-Credentials", "true");
  res.setHeader("Access-Control-Allow-Methods", "GET, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");

  if (req.method === "OPTIONS") return res.status(204).end();
  if (req.method !== "GET")
    return res.status(405).json({ ok:false, error:"method_not_allowed" });

  const cookie = req.headers.cookie || "";
  const match = cookie.match(/(?:^|;\s*)session=([^;]+)/);
  const token = match ? decodeURIComponent(match[1]) : "";
  const payload = verify(token, process.env.JWT_SECRET || "");
  if (!payload) return res.status(401).json({ ok:false, error:"no_session" });

  res.status(200).json({ ok:true, tg_id: String(payload.tg_id) });
};
