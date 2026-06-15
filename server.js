import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import sqlite3 from 'sqlite3';
import { open } from 'sqlite';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';

dotenv.config();
const app = express();
app.use(cors());
app.use(express.json());

let db;

async function initDB() {
  db = await open({
    filename: './database.sqlite',
    driver: sqlite3.Database
  });
  
  await db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      full_name TEXT,
      checking_balance REAL DEFAULT 0,
      savings_balance REAL DEFAULT 0,
      credit_card_balance REAL DEFAULT 0,
      credit_limit REAL DEFAULT 5000,
      is_active INTEGER DEFAULT 1,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      last_login_at DATETIME,
      last_login_ip TEXT
    )
  `);
  
  await db.exec(`
    CREATE TABLE IF NOT EXISTS login_attempts (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT NOT NULL,
      attempt_time DATETIME DEFAULT CURRENT_TIMESTAMP,
      ip_address TEXT,
      success INTEGER,
      failure_reason TEXT
    )
  `);
  
  console.log('✅ Database ready');
}

await initDB();

app.post('/api/auth/login', async (req, res) => {
  const { username, password } = req.body;
  const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
  
  const user = await db.get('SELECT * FROM users WHERE username = ?', [username]);
  
  if (!user) {
    await db.run('INSERT INTO login_attempts (username, ip_address, success, failure_reason) VALUES (?, ?, ?, ?)', [username, ip, 0, 'user_not_found']);
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  
  if (!user.is_active) {
    await db.run('INSERT INTO login_attempts (username, ip_address, success, failure_reason) VALUES (?, ?, ?, ?)', [username, ip, 0, 'account_disabled']);
    return res.status(401).json({ error: 'Account disabled' });
  }
  
  const valid = await bcrypt.compare(password, user.password_hash);
  if (!valid) {
    await db.run('INSERT INTO login_attempts (username, ip_address, success, failure_reason) VALUES (?, ?, ?, ?)', [username, ip, 0, 'wrong_password']);
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  
  await db.run('INSERT INTO login_attempts (username, ip_address, success) VALUES (?, ?, ?)', [username, ip, 1]);
  await db.run('UPDATE users SET last_login_at = CURRENT_TIMESTAMP, last_login_ip = ? WHERE id = ?', [ip, user.id]);
  
  const token = jwt.sign({ userId: user.id, username: user.username }, process.env.JWT_SECRET || 'secretkey', { expiresIn: '24h' });
  
  res.json({ token, user: { id: user.id, username: user.username, full_name: user.full_name, checking_balance: user.checking_balance, savings_balance: user.savings_balance, credit_card_balance: user.credit_card_balance, credit_limit: user.credit_limit } });
});

app.get('/api/user/me', async (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token' });
  
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'secretkey');
    const user = await db.get('SELECT id, username, full_name, checking_balance, savings_balance, credit_card_balance, credit_limit, is_active, last_login_at FROM users WHERE id = ?', [decoded.userId]);
    res.json(user);
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
});

app.post('/api/transfer/internal', async (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  const { fromAccount, toAccount, amount } = req.body;
  
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'secretkey');
    const user = await db.get('SELECT checking_balance, savings_balance FROM users WHERE id = ?', [decoded.userId]);
    
    let fromBalance = fromAccount === 'checking' ? user.checking_balance : user.savings_balance;
    if (fromBalance < amount) return res.status(400).json({ error: 'Insufficient funds' });
    
    if (fromAccount === 'checking') await db.run('UPDATE users SET checking_balance = checking_balance - ? WHERE id = ?', [amount, decoded.userId]);
    else await db.run('UPDATE users SET savings_balance = savings_balance - ? WHERE id = ?', [amount, decoded.userId]);
    
    if (toAccount === 'checking') await db.run('UPDATE users SET checking_balance = checking_balance + ? WHERE id = ?', [amount, decoded.userId]);
    else await db.run('UPDATE users SET savings_balance = savings_balance + ? WHERE id = ?', [amount, decoded.userId]);
    
    const updated = await db.get('SELECT checking_balance, savings_balance FROM users WHERE id = ?', [decoded.userId]);
    res.json({ success: true, checking_balance: updated.checking_balance, savings_balance: updated.savings_balance });
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
});

app.post('/api/admin/users', async (req, res) => {
  const { username, password, full_name, checking_balance, savings_balance, credit_card_balance, credit_limit } = req.body;
  const hash = await bcrypt.hash(password, 10);
  await db.run('INSERT INTO users (username, password_hash, full_name, checking_balance, savings_balance, credit_card_balance, credit_limit) VALUES (?, ?, ?, ?, ?, ?, ?)', [username, hash, full_name, checking_balance || 0, savings_balance || 0, credit_card_balance || 0, credit_limit || 5000]);
  res.json({ success: true });
});

app.get('/api/admin/users', async (req, res) => {
  const users = await db.all('SELECT id, username, full_name, checking_balance, savings_balance, credit_card_balance, credit_limit, is_active FROM users');
  res.json(users);
});

app.put('/api/admin/users/:id', async (req, res) => {
  const { checking_balance, savings_balance, credit_card_balance, is_active } = req.body;
  if (checking_balance !== undefined) await db.run('UPDATE users SET checking_balance = ? WHERE id = ?', [checking_balance, req.params.id]);
  if (savings_balance !== undefined) await db.run('UPDATE users SET savings_balance = ? WHERE id = ?', [savings_balance, req.params.id]);
  if (credit_card_balance !== undefined) await db.run('UPDATE users SET credit_card_balance = ? WHERE id = ?', [credit_card_balance, req.params.id]);
  if (is_active !== undefined) await db.run('UPDATE users SET is_active = ? WHERE id = ?', [is_active, req.params.id]);
  res.json({ success: true });
});

app.delete('/api/admin/users/:id', async (req, res) => {
  await db.run('DELETE FROM users WHERE id = ?', [req.params.id]);
  res.json({ success: true });
});

app.get('/api/admin/login-logs', async (req, res) => {
  const logs = await db.all('SELECT * FROM login_attempts ORDER BY attempt_time DESC LIMIT 100');
  res.json(logs);
});

app.listen(5000, () => console.log('🚀 Server running on http://localhost:5000'));
