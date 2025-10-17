// Мини-тестовый обработчик для Vercel
export default function handler(req, res) {
  res.status(200).json({ ok: true, message: "Backend работает 🚀" });
}
