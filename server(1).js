// ================================================================
// ФинОтчётность Уз — Backend (Express.js)
// Статика приложения + JWT-кабинет пользователей + SQLite +
// OpenAI-прокси (ключ только на сервере) + helmet + rate-limit + CORS
//
// ДЕПЛОЙ (Render / Railway):
//   1. Положите рядом server.js, package.json, finotchetnost_uz.html
//   2. Переменные окружения:
//        JWT_SECRET   — случайная длинная строка (ОБЯЗАТЕЛЬНО)
//        OPENAI_KEY   — ключ OpenAI (для прокси ИИ, опционально)
//        FRONTEND_URL — URL фронтенда для CORS (опционально, по умолчанию *)
//        NODE_ENV=production
//   3. Build: npm install | Start: npm start
//   На Render включите Persistent Disk (путь /opt/render/project/src),
//   иначе SQLite-файл будет стираться при redeploy.
//
// ЛОКАЛЬНО: npm install && JWT_SECRET=secret OPENAI_KEY=sk-... npm start
//   → http://localhost:3000
// ================================================================
const path = require('path');
const fs = require('fs');
const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const Database = require('better-sqlite3');

// ---------- Конфигурация ----------
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-change-me';
const OPENAI_KEY = process.env.OPENAI_KEY || '';
const MODEL = process.env.MODEL || 'gpt-4o-mini';
const FRONTEND_URL = process.env.FRONTEND_URL || '*';

// ---------- База данных SQLite ----------
const db = new Database(path.join(__dirname, 'data.sqlite'));
db.pragma('journal_mode = WAL');
db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  email      TEXT UNIQUE NOT NULL,
  pass_hash  TEXT NOT NULL,
  created_at TEXT DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS reports (
  user_id    INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  data       TEXT NOT NULL,               -- JSON отчёта (баланс+ОФР)
  updated_at TEXT DEFAULT (datetime('now'))
);`);

// ---------- Приложение Express ----------
const app = express();
app.disable('x-powered-by');

// Безопасные заголовки (CSP отключён: фронт грузит CDN-скрипты)
app.use(helmet({ contentSecurityPolicy: false, crossOriginEmbedderPolicy: false }));

// CORS: в проде укажите FRONTEND_URL=https://ваш-фронт.netlify.app
app.use(cors({
  origin: FRONTEND_URL === '*' ? true : FRONTEND_URL,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  maxAge: 600,
}));

app.use(express.json({ limit: '2mb' }));

// ---------- Rate limiting (защита от DDoS/брутфорса) ----------
const authLimiter = rateLimit({                       // вход/регистрация — строго
  windowMs: 15 * 60 * 1000, limit: 30,
  standardHeaders: 'draft-7', legacyHeaders: false,
  message: { error: 'Слишком много попыток. Подождите 15 минут.' },
});
const chatLimiter = rateLimit({                       // прокси ИИ — платный ресурс
  windowMs: 60 * 1000, limit: 20,
  standardHeaders: 'draft-7', legacyHeaders: false,
  message: { error: 'Лимит запросов к ИИ (20/мин). Подождите.' },
});
const apiLimiter = rateLimit({                        // остальное API
  windowMs: 60 * 1000, limit: 120,
  standardHeaders: 'draft-7', legacyHeaders: false,
});

// ---------- Вспомогательные функции ----------
const sign = uid => jwt.sign({ uid }, JWT_SECRET, { expiresIn: '7d' });

// Middleware: проверка JWT, в req.user = { uid }
function auth(req, res, next) {
  const h = req.headers.authorization || '';
  const token = h.startsWith('Bearer ') ? h.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Нет токена. Войдите снова.' });
  try { req.user = jwt.verify(token, JWT_SECRET); next(); }
  catch { return res.status(401).json({ error: 'Токен просрочен или недействителен.' }); }
}
const emailOk = e => typeof e === 'string' && e.length <= 120 && /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(e);

// ---------- Статика: само веб-приложение ----------
const htmlPath = path.join(__dirname, 'finotchetnost_uz.html');
app.get('/', (req, res) => {
  if (!fs.existsSync(htmlPath)) return res.status(404).send('finotchetnost_uz.html не найден рядом с server.js');
  res.type('html').send(fs.readFileSync(htmlPath));
});

// ================= АУТЕНТИФИКАЦИЯ (JWT) =================

// POST /api/register {email, password} → {token, email}
app.post('/api/register', authLimiter, async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!emailOk(email)) return res.status(400).json({ error: 'Некорректный e-mail.' });
    if (typeof password !== 'string' || password.length < 6 || password.length > 72)
      return res.status(400).json({ error: 'Пароль должен быть 6–72 символа.' });

    const hash = await bcrypt.hash(password, 10);
    const cleanEmail = email.toLowerCase().trim();
    try {
      const info = db.prepare('INSERT INTO users(email, pass_hash) VALUES (?, ?)').run(cleanEmail, hash);
      res.json({ token: sign(info.lastInsertRowid), email: cleanEmail });
    } catch (e) {
      if (String(e.code).includes('SQLITE_CONSTRAINT'))
        return res.status(409).json({ error: 'Этот e-mail уже зарегистрирован.' });
      throw e;
    }
  } catch (e) { console.error(e); res.status(500).json({ error: 'Ошибка сервера.' }); }
});

// POST /api/login {email, password} → {token, email}
app.post('/api/login', authLimiter, async (req, res) => {
  const { email, password } = req.body || {};
  const row = db.prepare('SELECT id, email, pass_hash FROM users WHERE email = ?')
    .get(String(email || '').toLowerCase().trim());
  const ok = row && await bcrypt.compare(String(password || ''), row.pass_hash);
  if (!ok) return res.status(401).json({ error: 'Неверный e-mail или пароль.' });
  res.json({ token: sign(row.id), email: row.email });
});

// ================= ЛИЧНЫЙ КАБИНЕТ: ОТЧЁТЫ =================

// GET /api/report → {data, updated_at} | {data: null}
app.get('/api/report', apiLimiter, auth, (req, res) => {
  const row = db.prepare('SELECT data, updated_at FROM reports WHERE user_id = ?').get(req.user.uid);
  res.json(row ? { data: JSON.parse(row.data), updated_at: row.updated_at } : { data: null });
});

// PUT /api/report {data: {...}} → сохранить/обновить
app.put('/api/report', apiLimiter, auth, (req, res) => {
  const data = req.body && req.body.data;
  if (typeof data !== 'object' || data === null) return res.status(400).json({ error: 'Нет поля data.' });
  const s = JSON.stringify(data);
  if (s.length > 1_500_000) return res.status(413).json({ error: 'Отчёт слишком большой (>1.5 МБ).' });
  db.prepare(`INSERT INTO reports(user_id, data, updated_at) VALUES (?, ?, datetime('now'))
              ON CONFLICT(user_id) DO UPDATE SET data = excluded.data, updated_at = excluded.updated_at`)
    .run(req.user.uid, s);
  res.json({ ok: true });
});

// DELETE /api/report → удалить сохранённый отчёт
app.delete('/api/report', apiLimiter, auth, (req, res) => {
  db.prepare('DELETE FROM reports WHERE user_id = ?').run(req.user.uid);
  res.json({ ok: true });
});

// ================= OPENAI-ПРОКСИ (ключ только на сервере) =================
app.post('/api/chat', chatLimiter, async (req, res) => {
  if (!OPENAI_KEY) return res.status(500).json({ error: 'OPENAI_KEY не задан на сервере.' });
  try {
    const r = await fetch('https://api.openai.com/v1/chat/completions', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + OPENAI_KEY },
      body: JSON.stringify({
        model: (req.body && req.body.model) || MODEL,
        messages: (req.body && req.body.messages) || [],
      }),
    });
    res.status(r.status).type('application/json').send(await r.text());
  } catch (e) { res.status(500).json({ error: String(e) }); }
});

// ---------- Единый обработчик ошибок ----------
app.use((err, req, res, next) => { console.error(err); res.status(500).json({ error: 'Внутренняя ошибка сервера.' }); });

app.listen(PORT, () => console.log(
  `✅ Сервер: http://localhost:${PORT}\n` +
  `   JWT_SECRET: ${JWT_SECRET === 'dev-secret-change-me' ? '⚠ ВНИМАНИЕ: задайте свою строку!' : 'задан'}\n` +
  `   OpenAI: ${OPENAI_KEY ? 'задан' : 'не задан'} | CORS: ${FRONTEND_URL}`
));
