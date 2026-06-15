import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import initSqlJs from 'sql.js';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import fs from 'fs';

dotenv.config();
const app = express();
app.use(cors());
app.use(express.json());

let db;
let SQL;

const DB_FILE = './database.db';

async function initDB() {
  SQL = await initSqlJs();
  
  // Load existing database if it exists
  let dbBuffer = null;
  if (fs.existsSync(DB_FILE)) {
    dbBuffer = fs.readFileSync(DB_FILE);
    console.log('✅ Loaded existing database');
  } else {
    console.log('📁 Creating new database file');
  }
  
  db = new SQL.Database(dbBuffer);
  
  // Create tables
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      full_name TEXT,
      checking_balance REAL DEFAULT 0,
      savings_balance REAL DEFAULT 0,
      credit_card_balance REAL DEFAULT 0,
      credit_limit REAL DEFAULT 5000,
      checking_account_number TEXT DEFAULT '4832',
      savings_account_number TEXT DEFAULT '9182',
      credit_account_number TEXT DEFAULT '2345',
      is_active INTEGER DEFAULT 1,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      last_login_at DATETIME,
      last_login_ip TEXT
    )
  `);
  
  db.run(`
    CREATE TABLE IF NOT EXISTS login_attempts (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT NOT NULL,
      attempt_time DATETIME DEFAULT CURRENT_TIMESTAMP,
      ip_address TEXT,
      success INTEGER,
      failure_reason TEXT
    )
  `);
  
  // Save function
  function saveDB() {
    const data = db.export();
    const buffer = Buffer.from(data);
    fs.writeFileSync(DB_FILE, buffer);
    console.log('💾 Database saved to disk');
  }
  
  // Wrap db.run to auto-save after changes
  const originalRun = db.run.bind(db);
  db.run = (sql, params) => {
    const result = originalRun(sql, params);
    saveDB();
    return result;
  };
  
  // Check if admin exists, if not create one
  const checkAdmin = db.exec("SELECT * FROM users WHERE username = 'admin'");
  if (checkAdmin.length === 0 || checkAdmin[0].values.length === 0) {
    const adminHash = bcrypt.hashSync('admin123', 10);
    db.run(`INSERT INTO users (username, password_hash, full_name, checking_balance, savings_balance, credit_limit, is_active)
            VALUES ('admin', ?, 'Administrator', 5000, 2000, 10000, 1)`, [adminHash]);
    console.log('✅ Admin user created automatically');
  }
  
  console.log('✅ Database ready');
  return db;
}

// Helper functions
function dbAll(sql, params = []) {
  const stmt = db.prepare(sql);
  stmt.bind(params);
  const results = [];
  while (stmt.step()) {
    results.push(stmt.getAsObject());
  }
  stmt.free();
  return results;
}

function dbGet(sql, params = []) {
  const stmt = db.prepare(sql);
  stmt.bind(params);
  let result = null;
  if (stmt.step()) {
    result = stmt.getAsObject();
  }
  stmt.free();
  return result;
}

function dbRun(sql, params = []) {
  const stmt = db.prepare(sql);
  stmt.bind(params);
  stmt.step();
  stmt.free();
}

await initDB();

// Login endpoint
app.post('/api/auth/login', async (req, res) => {
  const { username, password } = req.body;
  const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
  
  const user = dbGet('SELECT * FROM users WHERE LOWER(username) = LOWER(?)', [username]);
  
  if (!user) {
    dbRun('INSERT INTO login_attempts (username, ip_address, success, failure_reason) VALUES (?, ?, ?, ?)', [username, ip, 0, 'user_not_found']);
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  
  if (!user.is_active) {
    dbRun('INSERT INTO login_attempts (username, ip_address, success, failure_reason) VALUES (?, ?, ?, ?)', [username, ip, 0, 'account_disabled']);
    return res.status(401).json({ error: 'Account disabled' });
  }
  
  const valid = bcrypt.compareSync(password, user.password_hash);
  if (!valid) {
    dbRun('INSERT INTO login_attempts (username, ip_address, success, failure_reason) VALUES (?, ?, ?, ?)', [username, ip, 0, 'wrong_password']);
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  
  dbRun('INSERT INTO login_attempts (username, ip_address, success) VALUES (?, ?, ?)', [username, ip, 1]);
  dbRun('UPDATE users SET last_login_at = CURRENT_TIMESTAMP, last_login_ip = ? WHERE id = ?', [ip, user.id]);
  
  const token = jwt.sign({ userId: user.id, username: user.username }, process.env.JWT_SECRET || 'secretkey', { expiresIn: '24h' });
  
  res.json({
    token,
    user: {
      id: user.id,
      username: user.username,
      full_name: user.full_name,
      checking_balance: user.checking_balance,
      savings_balance: user.savings_balance,
      credit_card_balance: user.credit_card_balance,
      credit_limit: user.credit_limit,
      checking_account_number: user.checking_account_number || '4832',
      savings_account_number: user.savings_account_number || '9182',
      credit_account_number: user.credit_account_number || '2345'
    }
  });
});

// Get current user
app.get('/api/user/me', async (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token' });
  
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'secretkey');
    const user = dbGet(`SELECT id, username, full_name, checking_balance, savings_balance, 
                        credit_card_balance, credit_limit, is_active, last_login_at,
                        checking_account_number, savings_account_number, credit_account_number 
                        FROM users WHERE id = ?`, [decoded.userId]);
    res.json(user);
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
});

// Internal transfer
app.post('/api/transfer/internal', async (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  const { fromAccount, toAccount, amount } = req.body;
  
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'secretkey');
    const user = dbGet('SELECT checking_balance, savings_balance FROM users WHERE id = ?', [decoded.userId]);
    
    let fromBalance = fromAccount === 'checking' ? user.checking_balance : user.savings_balance;
    if (fromBalance < amount) return res.status(400).json({ error: 'Insufficient funds' });
    
    if (fromAccount === 'checking') {
      dbRun('UPDATE users SET checking_balance = checking_balance - ? WHERE id = ?', [amount, decoded.userId]);
    } else {
      dbRun('UPDATE users SET savings_balance = savings_balance - ? WHERE id = ?', [amount, decoded.userId]);
    }
    
    if (toAccount === 'checking') {
      dbRun('UPDATE users SET checking_balance = checking_balance + ? WHERE id = ?', [amount, decoded.userId]);
    } else {
      dbRun('UPDATE users SET savings_balance = savings_balance + ? WHERE id = ?', [amount, decoded.userId]);
    }
    
    const updated = dbGet('SELECT checking_balance, savings_balance FROM users WHERE id = ?', [decoded.userId]);
    res.json({ success: true, checking_balance: updated.checking_balance, savings_balance: updated.savings_balance });
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
});

// Admin: Add user
app.post('/api/admin/users', async (req, res) => {
  const { username, password, full_name, checking_balance, savings_balance, credit_card_balance, credit_limit, checking_account_number, savings_account_number, credit_account_number } = req.body;
  const hash = bcrypt.hashSync(password, 10);
  dbRun(`INSERT INTO users (username, password_hash, full_name, checking_balance, savings_balance, credit_card_balance, credit_limit, checking_account_number, savings_account_number, credit_account_number)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [username, hash, full_name, checking_balance || 0, savings_balance || 0, credit_card_balance || 0, credit_limit || 5000, 
     checking_account_number || '4832', savings_account_number || '9182', credit_account_number || '2345']);
  res.json({ success: true });
});

// Admin: Get all users
app.get('/api/admin/users', async (req, res) => {
  const users = dbAll('SELECT id, username, full_name, checking_balance, savings_balance, credit_card_balance, credit_limit, is_active, checking_account_number, savings_account_number, credit_account_number FROM users');
  res.json(users);
});

// Admin: Update user
app.put('/api/admin/users/:id', async (req, res) => {
  const { checking_balance, savings_balance, credit_card_balance, is_active, checking_account_number, savings_account_number, credit_account_number } = req.body;
  
  if (checking_balance !== undefined) {
    dbRun('UPDATE users SET checking_balance = ? WHERE id = ?', [checking_balance, req.params.id]);
  }
  if (savings_balance !== undefined) {
    dbRun('UPDATE users SET savings_balance = ? WHERE id = ?', [savings_balance, req.params.id]);
  }
  if (credit_card_balance !== undefined) {
    dbRun('UPDATE users SET credit_card_balance = ? WHERE id = ?', [credit_card_balance, req.params.id]);
  }
  if (is_active !== undefined) {
    dbRun('UPDATE users SET is_active = ? WHERE id = ?', [is_active, req.params.id]);
  }
  if (checking_account_number !== undefined) {
    dbRun('UPDATE users SET checking_account_number = ? WHERE id = ?', [checking_account_number, req.params.id]);
  }
  if (savings_account_number !== undefined) {
    dbRun('UPDATE users SET savings_account_number = ? WHERE id = ?', [savings_account_number, req.params.id]);
  }
  if (credit_account_number !== undefined) {
    dbRun('UPDATE users SET credit_account_number = ? WHERE id = ?', [credit_account_number, req.params.id]);
  }
  
  res.json({ success: true });
});

// Admin: Delete user
app.delete('/api/admin/users/:id', async (req, res) => {
  dbRun('DELETE FROM users WHERE id = ?', [req.params.id]);
  res.json({ success: true });
});

// Admin: Get login logs
app.get('/api/admin/login-logs', async (req, res) => {
  const logs = dbAll('SELECT * FROM login_attempts ORDER BY attempt_time DESC LIMIT 100');
  res.json(logs);
});

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

const PORT = process.env.PORT || 10000;
app.listen(PORT, '0.0.0.0', () => console.log(`🚀 Server running on port ${PORT}`));