const path = require('path');
const fs = require('fs');
const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { Pool } = require('pg');

// ---------- Конфигурация ----------
const PORT = process.env.PORT || 10000;
const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-change-me';
const OPENAI_KEY = process.env.OPENAI_KEY || '';
const MODEL = process.env.MODEL || 'gpt-4o-mini';
const FRONTEND_URL = process.env.FRONTEND_URL || '*';

// ---------- База данных PostgreSQL ----------
const db = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL ? { rejectUnauthorized: false } : false
});

// Инициализация таблиц в PostgreSQL
async function initDb() {
  try {
    await db.query(`
      CREATE TABLE IF NOT EXISTS users (
        id         SERIAL PRIMARY KEY,
        email      TEXT UNIQUE NOT NULL,
        pass_hash  TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
      CREATE TABLE IF NOT EXISTS reports (
        user_id    INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
        data       TEXT NOT NULL,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);
    console.log('PostgreSQL таблицы успешно проверены/созданы.');
  } catch (err) {
    console.error('Ошибка инициализации БД:', err);
  }
}
initDb();

// ---------- Приложение Express ----------
const app = express();
app.disable('x-powered-by');

app.use(helmet({ contentSecurityPolicy: false, crossOriginEmbedderPolicy: false }));

app.use(cors({
  origin: FRONTEND_URL === '*' ? true : FRONTEND_URL,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  maxAge: 600,
}));

app.use(express.json({ limit: '2mb' }));

// ---------- Rate limiting ----------
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, limit: 30,
  standardHeaders: 'draft-7', legacyHeaders: false,
  message: { error: 'Слишком много попыток. Подождите 15 минут.' },
});
const chatLimiter = rateLimit({
  windowMs: 60 * 1000, limit: 20,
  standardHeaders: 'draft-7', legacyHeaders: false,
  message: { error: 'Лимит запросов к ИИ (20/мин). Подождите.' },
});
const apiLimiter = rateLimit({
  windowMs: 60 * 1000, limit: 120,
  standardHeaders: 'draft-7', legacyHeaders: false,
});

// ---------- Вспомогательные функции ----------
const sign = uid => jwt.sign({ uid }, JWT_SECRET, { expiresIn: '7d' });

function auth(req, res, next) {
  const h = req.headers.authorization || '';
  const token = h.startsWith('Bearer ') ? h.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Нет токена. Войдите снова.' });
  try { req.user = jwt.verify(token, JWT_SECRET); next(); }
  catch { return res.status(401).json({ error: 'Токен просрочен или недействителен.' }); }
}
const emailOk = e => typeof e === 'string' && e.length <= 120 && /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(e);

// ---------- Статика: выдача HTML-интерфейса ----------
const htmlPath = path.join(__dirname, 'finotchetnost_uz.html');
app.get('/', (req, res) => {
  if (!fs.existsSync(htmlPath)) return res.status(404).send('finotchetnost_uz.html не найден рядом с server.js');
  res.type('html').send(fs.readFileSync(htmlPath));
});

// ================= АУТЕНТИФИКАЦИЯ (JWT) =================

app.post('/api/register', authLimiter, async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!emailOk(email)) return res.status(400).json({ error: 'Некорректный e-mail.' });
    if (typeof password !== 'string' || password.length < 6 || password.length > 72)
      return res.status(400).json({ error: 'Пароль должен быть 6–72 символа.' });

    const hash = await bcrypt.hash(password, 10);
    const cleanEmail = email.toLowerCase().trim();
    
    const result = await db.query(
      'INSERT INTO users(email, pass_hash) VALUES($1, $2) RETURNING id',
      [cleanEmail, hash]
    );
    res.json({ token: sign(result.rows[0].id), email: cleanEmail });
  } catch (e) {
    if (e.code === '23505') // Postgres unique constraint violation
      return res.status(409).json({ error: 'Этот e-mail уже зарегистрирован.' });
    console.error(e);
    res.status(500).json({ error: 'Ошибка сервера.' });
  }
});

app.post('/api/login', authLimiter, async (req, res) => {
  try {
    const { email, password } = req.body || {};
    const cleanEmail = String(email || '').toLowerCase().trim();
    const result = await db.query('SELECT id, email, pass_hash FROM users WHERE email = $1', [cleanEmail]);
    const row = result.rows[0];
    
    const ok = row && await bcrypt.compare(String(password || ''), row.pass_hash);
    if (!ok) return res.status(401).json({ error: 'Неверный e-mail или пароль.' });
    res.json({ token: sign(row.id), email: row.email });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Ошибка сервера.' });
  }
});

// ================= ЛИЧНЫЙ КАБИНЕТ: ОТЧЁТЫ =================

app.get('/api/report', apiLimiter, auth, async (req, res) => {
  try {
    const result = await db.query('SELECT data, updated_at FROM reports WHERE user_id = $1', [req.user.uid]);
    const row = result.rows[0];
    res.json(row ? { data: JSON.parse(row.data), updated_at: row.updated_at } : { data: null });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Ошибка сервера.' });
  }
});

app.put('/api/report', apiLimiter, auth, async (req, res) => {
  try {
    const data = req.body && req.body.data;
    if (typeof data !== 'object' || data === null) return res.status(400).json({ error: 'Нет поля data.' });
    const s = JSON.stringify(data);
    if (s.length > 1_500_000) return res.status(413).json({ error: 'Отчёт слишком большой (>1.5 МБ).' });

    await db.query(`
      INSERT INTO reports(user_id, data, updated_at) VALUES($1, $2, CURRENT_TIMESTAMP)
      ON CONFLICT (user_id) DO UPDATE SET data = EXCLUDED.data, updated_at = CURRENT_TIMESTAMP
    `, [req.user.uid, s]);

    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Ошибка сервера.' });
  }
});

app.delete('/api/report', apiLimiter, auth, async (req, res) => {
  try {
    await db.query('DELETE FROM reports WHERE user_id = $1', [req.user.uid]);
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Ошибка сервера.' });
  }
});

// ================= OPENAI-ПРОКСИ =================
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

app.use((err, req, res, next) => { console.error(err); res.status(500).json({ error: 'Внутренняя ошибка сервера.' }); });

app.listen(PORT, () => console.log(`✅ Сервер запущен на порту ${PORT}`));
