// Проверяем uid через официальный API Salebot (формат chatter.salebot.pro/api/{api_key}/{action})
// Требуются ENV: SALEBOT_API_KEY, SALEBOT_PROJECT_ID
const fetch = require("node-fetch");

module.exports = async (req, res) => {
  const ORIGIN = process.env.CORS_ORIGIN || "*";
  res.setHeader("Access-Control-Allow-Origin", ORIGIN);
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
  if (req.method === "OPTIONS") return res.status(204).end();
  if (req.method !== "POST") return res.status(405).json({ ok:false, error:"method_not_allowed" });

  const { uid } = req.body || {};
  if (!uid) return res.status(400).json({ ok:false, error:"no_uid" });

  try {
    const API_KEY = process.env.SALEBOT_API_KEY;
    const PROJECT_ID = process.env.SALEBOT_PROJECT_ID; // если у них нужно; если нет — не используем
    if (!API_KEY) return res.status(500).json({ ok:false, error:"no_api_key" });

    // ⚠️ ДВА ВАРИАНТА в зависимости от вашей версии Salebot.
    // 1) Часто есть экшен вида "get_client" или "get_user"
    //    Пример: /api/{api_key}/get_client?user_id=...  (или client_id)
    // 2) Или "client_info" / "user_info". Название экшена может отличаться.
    // Поставим универсально через query user_id; если ваш экшен называется иначе — поменяем "get_client" на нужное.

    const url = `https://chatter.salebot.pro/api/${API_KEY}/get_client?user_id=${encodeURIComponent(uid)}`;

    const r = await fetch(url, { method: "GET" });
    const data = await r.json().catch(() => ({}));

    // ОЖИДАЕМ:
    // data.telegram_id или data.platform_id (tg user id)
    // data.status или data.tags/fields, по которым понимаем активность
    const tg_id = String(data.telegram_id || data.platform_id || "");
    if (!tg_id) return res.status(404).json({ ok:false, error:"user_not_found" });

    // Проверяем активность (подстроим под вашу схему)
    const active =
      data.status === "ACTIVE" ||
      data.is_paid === 1 ||
      (Array.isArray(data.tags) && data.tags.includes("paid"));

    if (!active) return res.status(403).json({ ok:false, error:"membership_not_active" });

    return res.status(200).json({ ok:true, tg_id, status: "ACTIVE" });
  } catch (e) {
    console.error("salebot_api_error", e);
    return res.status(500).json({ ok:false, error:"salebot_api_error" });
  }
};
