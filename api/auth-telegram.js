// POST /api/auth-telegram
const crypto = require("crypto");

module.exports = async (req, res) => {
  const ORIGIN = process.env.CORS_ORIGIN || "*";

  if (req.method === "OPTIONS") {
    res.setHeader("Access-Control-Allow-Origin", ORIGIN);
    res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type");
    return res.status(204).end();
  }
  res.setHeader("Access-Control-Allow-Origin", ORIGIN);

  if (req.method !== "POST") {
    return res.status(405).json({ ok:false, error:"method_not_allowed" });
  }

  const { initData } = req.body || {};
  if (!initData) return res.status(400).json({ ok:false, error:"no_initData" });

  // проверка подписи initData токеном бота
  const ok = verifyTelegramInitData(initData, process.env.TG_BOT_TOKEN);
  if (!ok) return res.status(401).json({ ok:false, error:"invalid_initData" });

  // достаём tg_id из initData (поле user – это JSON в строке)
  const params = Object.fromEntries(new URLSearchParams(initData));
  let user = {};
  try { user = JSON.parse(params.user || "{}"); } catch {}
  const tg_id = user.id;

  if (!tg_id) return res.status(400).json({ ok:false, error:"no_tg_id" });

  // пока просто подтверждаем вход (позже подключим проверку статуса в БД)
  return res.status(200).json({ ok:true, tg_id });
};

function verifyTelegramInitData(initDataString, botToken) {
  if (!botToken) return false;
  const params = Object.fromEntries(new URLSearchParams(initDataString));
  const hash = params.hash;
  if (!hash) return false;

  // data_check_string = все пары key=value (кроме hash), отсортированные, через \n
  const dataCheckString = Object.keys(params)
    .filter((k) => k !== "hash")
    .sort()
    .map((k) => `${k}=${params[k]}`)
    .join("\n");

  // secret = sha256(botToken)
  const secret = crypto.createHash("sha256").update(botToken).digest();

  // HMAC-SHA256(secret, data_check_string)
  const hmac = crypto.createHmac("sha256", secret).update(dataCheckString).digest("hex");

  // безопасное сравнение
  try {
    return crypto.timingSafeEqual(Buffer.from(hmac, "hex"), Buffer.from(hash, "hex"));
  } catch {
    return false;
  }
}
