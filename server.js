const express = require('express');
const { Pool } = require('pg');
const cors = require('cors');

const app = express();
app.use(cors());
app.use(express.json());

// PostgreSQL ulanishi
const db = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false
  }
});

db.connect((err, client, release) => {
  if (err) {
    return console.error('PostgreSQL bazasiga ulanishda xatolik:', err.stack);
  }
  console.log('PostgreSQL bazasiga muvaffaqiyatli ulandi!');
  release();
});

// Asosiy test marshruti
app.get('/', (req, res) => {
  res.send('Finotchetnost-uz serveri muvaffaqiyatli ishlamoqda!');
});

const PORT = process.env.PORT || 10000;
app.listen(PORT, () => {
  console.log(`Server ${PORT}-portda ishga tushdi`);
});
