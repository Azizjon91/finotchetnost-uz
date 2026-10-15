const { Pool } = require('pg');

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
