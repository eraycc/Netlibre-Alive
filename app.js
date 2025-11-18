#!/usr/bin/env node
/**
 * Netlib Auto Login Keep-Alive Control Panel
 * Web-based management interface for the keep-alive system
 */

const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cron = require('node-cron');
const axios = require('axios');
const { chromium } = require('playwright');
const crypto = require('crypto');
const { URL } = require('url');

// Database setup
let db;
let dbType;

// Parse MySQL DSN
function parseMySQLDSN(dsn) {
  try {
    const url = new URL(dsn);
    
    if (!['mysql:', 'mysql+pymysql:'].includes(url.protocol)) {
      return null;
    }
    
    const useSSL = url.searchParams.get('ssl') === 'true';
    let username = decodeURIComponent(url.username || 'root');
    
    // Handle TiDB username format (user.cluster)
    if (username.includes('.')) {
      username = username.split('.').pop();
    }
    
    return {
      type: 'mysql',
      host: url.hostname || 'localhost',
      port: parseInt(url.port) || 3306,
      database: url.pathname.substring(1) || 'netlib_keepalive',
      user: username,
      password: decodeURIComponent(url.password || ''),
      ssl: useSSL ? { rejectUnauthorized: false } : false
    };
  } catch (error) {
    console.error('Error parsing MySQL DSN:', error);
    return null;
  }
}

// Initialize database
async function initDatabase() {
  const MYSQL_DSN = process.env.MYSQL_DSN;
  
  if (MYSQL_DSN) {
    const config = parseMySQLDSN(MYSQL_DSN);
    if (config) {
      dbType = 'mysql';
      const mysql = require('mysql2/promise');
      
      const pool = mysql.createPool({
        host: config.host,
        port: config.port,
        user: config.user,
        password: config.password,
        database: config.database,
        ssl: config.ssl,
        waitForConnections: true,
        connectionLimit: 10,
        queueLimit: 0,
        enableKeepAlive: true,
        keepAliveInitialDelay: 0
      });
      
      db = {
        async query(sql, params) {
          const [rows] = await pool.execute(sql, params || []);
          return rows;
        },
        async execute(sql, params) {
          await pool.execute(sql, params || []);
        }
      };
      
      console.log(`✅ Connected to MySQL: ${config.host}:${config.port}/${config.database}`);
    }
  }
  
  if (!db) {
    dbType = 'sqlite';
    const sqlite3 = require('sqlite3').verbose();
    const { promisify } = require('util');
    
    const sqliteDb = new sqlite3.Database('./data/netlib_keepalive.db');
    
    db = {
      async query(sql, params) {
        const all = promisify(sqliteDb.all.bind(sqliteDb));
        return await all(sql, params || []);
      },
      async execute(sql, params) {
        const run = promisify(sqliteDb.run.bind(sqliteDb));
        await run(sql, params || []);
      }
    };
    
    console.log('✅ Connected to SQLite database');
  }
  
  await initTables();
}

// Initialize database tables
async function initTables() {
  if (dbType === 'mysql') {
    await db.execute(`
      CREATE TABLE IF NOT EXISTS accounts (
        id INT AUTO_INCREMENT PRIMARY KEY,
        username VARCHAR(255) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        enabled BOOLEAN DEFAULT TRUE,
        cron_expression VARCHAR(100) DEFAULT '0 0 */60 * *',
        last_login_date DATE DEFAULT NULL,
        notification_channels JSON DEFAULT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
      )
    `);
    
    await db.execute(`
      CREATE TABLE IF NOT EXISTS login_history (
        id INT AUTO_INCREMENT PRIMARY KEY,
        account_id INT NOT NULL,
        success BOOLEAN NOT NULL,
        message TEXT,
        login_date DATE NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE CASCADE,
        INDEX idx_login_date (login_date),
        INDEX idx_account_date (account_id, login_date)
      )
    `);
    
    await db.execute(`
      CREATE TABLE IF NOT EXISTS notification_settings (
        id INT AUTO_INCREMENT PRIMARY KEY,
        channel_type VARCHAR(50) NOT NULL,
        enabled BOOLEAN DEFAULT FALSE,
        config JSON NOT NULL,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
      )
    `);
    
    await db.execute(`
      CREATE TABLE IF NOT EXISTS system_settings (
        id INT AUTO_INCREMENT PRIMARY KEY,
        setting_key VARCHAR(100) UNIQUE NOT NULL,
        setting_value TEXT,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
      )
    `);
  } else {
    await db.execute(`
      CREATE TABLE IF NOT EXISTS accounts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        enabled INTEGER DEFAULT 1,
        cron_expression TEXT DEFAULT '0 0 */60 * *',
        last_login_date DATE DEFAULT NULL,
        notification_channels TEXT DEFAULT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);
    
    await db.execute(`
      CREATE TABLE IF NOT EXISTS login_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        account_id INTEGER NOT NULL,
        success INTEGER NOT NULL,
        message TEXT,
        login_date DATE NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE CASCADE
      )
    `);
    
    await db.execute(`
      CREATE TABLE IF NOT EXISTS notification_settings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        channel_type TEXT NOT NULL,
        enabled INTEGER DEFAULT 0,
        config TEXT NOT NULL,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);
    
    await db.execute(`
      CREATE TABLE IF NOT EXISTS system_settings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        setting_key TEXT UNIQUE NOT NULL,
        setting_value TEXT,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);
  }
  
  // Initialize default notification settings
  const channels = ['telegram', 'wechat', 'wxpusher', 'dingtalk'];
  for (const channel of channels) {
    const existing = await db.query(
      'SELECT id FROM notification_settings WHERE channel_type = ?',
      [channel]
    );
    
    if (existing.length === 0) {
      const defaultConfig = dbType === 'mysql' 
        ? JSON.stringify({})
        : '{}';
      
      await db.execute(
        'INSERT INTO notification_settings (channel_type, enabled, config) VALUES (?, ?, ?)',
        [channel, 0, defaultConfig]
      );
    }
  }
  
  console.log('✅ Database tables initialized');
}

// Express app setup
const app = express();
const PORT = parseInt(process.env.PORT || '3000');
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(32).toString('hex');
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || 'admin';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'admin123';

app.use(cors({ credentials: true }));
app.use(express.json());

// Authentication middleware
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  
  if (!token) {
    return res.status(401).json({ message: 'Token is missing!' });
  }
  
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(401).json({ message: 'Token is invalid or expired!' });
    }
    req.user = user;
    next();
  });
}

// Notification Service
class NotificationService {
  static async sendNotification(title, content, accountName, channels) {
    if (!channels || channels.length === 0) return;
    
    for (const channelType of channels) {
      const settings = await db.query(
        'SELECT * FROM notification_settings WHERE channel_type = ? AND enabled = ?',
        [channelType, dbType === 'mysql' ? true : 1]
      );
      
      if (settings.length === 0) continue;
      
      const config = dbType === 'mysql' 
        ? settings[0].config 
        : JSON.parse(settings[0].config);
      
      try {
        switch (channelType) {
          case 'telegram':
            await this.sendTelegram(config, title, content);
            break;
          case 'wechat':
            await this.sendWechat(config, title, content);
            break;
          case 'wxpusher':
            await this.sendWxPusher(config, title, content);
            break;
          case 'dingtalk':
            await this.sendDingTalk(config, title, content);
            break;
        }
      } catch (error) {
        console.error(`Notification error (${channelType}):`, error);
      }
    }
  }
  
  static async sendTelegram(config, title, content) {
    const { bot_token, user_id, api_host } = config;
    if (!bot_token || !user_id) return;
    
    const baseUrl = api_host || 'https://api.telegram.org';
    const url = `${baseUrl}/bot${bot_token}/sendMessage`;
    
    await axios.post(url, {
      chat_id: user_id,
      text: `📢 ${title}\n\n${content}`,
      disable_web_page_preview: true
    }, { timeout: 30000 });
  }
  
  static async sendWechat(config, title, content) {
    const { webhook_key, api_host } = config;
    if (!webhook_key) return;
    
    const baseUrl = api_host || 'https://qyapi.weixin.qq.com';
    const url = `${baseUrl}/cgi-bin/webhook/send?key=${webhook_key}`;
    
    await axios.post(url, {
      msgtype: 'text',
      text: { content: `【${title}】\n\n${content}` }
    }, { timeout: 15000 });
  }
  
  static async sendWxPusher(config, title, content) {
    const { app_token, uid, api_host } = config;
    if (!app_token || !uid) return;
    
    const baseUrl = api_host || 'https://wxpusher.zjiecode.com';
    const url = `${baseUrl}/api/send/message`;
    
    const htmlContent = `
      <div style="padding: 10px; color: #2c3e50; background: #ffffff;">
        <h2 style="color: inherit; margin: 0;">${title}</h2>
        <div style="margin-top: 10px; padding: 10px; background: #f8f9fa; border-radius: 5px; color: #2c3e50;">
          <pre style="white-space: pre-wrap; word-wrap: break-word; margin: 0; color: inherit;">${content}</pre>
        </div>
        <div style="margin-top: 10px; color: #7f8c8d; font-size: 12px;">
          发送时间: ${new Date().toLocaleString('zh-CN', { timeZone: 'Asia/Shanghai' })}
        </div>
      </div>
    `;
    
    await axios.post(url, {
      appToken: app_token,
      content: htmlContent,
      summary: title.substring(0, 20),
      contentType: 2,
      uids: [uid],
      verifyPayType: 0
    }, { timeout: 30000 });
  }
  
  static async sendDingTalk(config, title, content) {
    const { access_token, secret, api_host } = config;
    if (!access_token || !secret) return;
    
    const timestamp = Date.now();
    const stringToSign = `${timestamp}\n${secret}`;
    const hmac = crypto.createHmac('sha256', secret);
    hmac.update(stringToSign);
    const sign = encodeURIComponent(hmac.digest('base64'));
    
    const baseUrl = api_host || 'https://oapi.dingtalk.com';
    const url = `${baseUrl}/robot/send?access_token=${access_token}&timestamp=${timestamp}&sign=${sign}`;
    
    await axios.post(url, {
      msgtype: 'text',
      text: { content: `【${title}】\n${content}` },
      at: { isAtAll: false }
    }, { timeout: 30000 });
  }
}

// Netlib Login Service
class NetlibLoginService {
  constructor() {
    this.loginUrl = 'https://www.netlib.re/';
    this.userAgent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36';
  }
  
  async performLogin(username, password, accountName) {
    console.log(`🚀 Starting login for account: ${accountName}`);
    
    const browser = await chromium.launch({
      headless: true,
      args: ['--no-sandbox', '--disable-setuid-sandbox']
    });
    
    let page;
    let success = false;
    let message = '';
    
    try {
      page = await browser.newPage();
      page.setDefaultTimeout(30000);
      
      console.log(`📱 ${accountName} - Accessing website...`);
      await page.goto(this.loginUrl, { waitUntil: 'networkidle' });
      await page.waitForTimeout(3000);
      
      console.log(`🔑 ${accountName} - Clicking login button...`);
      await page.click('text=Login', { timeout: 5000 });
      await page.waitForTimeout(2000);
      
      console.log(`📝 ${accountName} - Filling username...`);
      await page.fill('input[name="username"], input[type="text"]', username);
      await page.waitForTimeout(1000);
      
      console.log(`🔒 ${accountName} - Filling password...`);
      await page.fill('input[name="password"], input[type="password"]', password);
      await page.waitForTimeout(1000);
      
      console.log(`📤 ${accountName} - Submitting login...`);
      await page.click('button:has-text("Validate"), input[type="submit"]');
      
      await page.waitForLoadState('networkidle');
      await page.waitForTimeout(5000);
      
      const pageContent = await page.content();
      
      if (pageContent.includes('exclusive owner') || pageContent.includes(username)) {
        console.log(`✅ ${accountName} - Login successful`);
        success = true;
        message = 'Login successful';
      } else {
        console.log(`❌ ${accountName} - Login failed`);
        message = 'Login failed - invalid credentials or page structure changed';
      }
    } catch (error) {
      console.log(`❌ ${accountName} - Login error: ${error.message}`);
      message = `Login error: ${error.message}`;
    } finally {
      if (page) await page.close();
      await browser.close();
    }
    
    return { success, message };
  }
}

// Scheduler
class LoginScheduler {
  constructor() {
    this.jobs = new Map();
    this.loginService = new NetlibLoginService();
  }
  
  async start() {
    console.log('🔄 Starting scheduler...');
    
    // Load all enabled accounts
    const accounts = await db.query(
      'SELECT * FROM accounts WHERE enabled = ?',
      [dbType === 'mysql' ? true : 1]
    );
    
    for (const account of accounts) {
      this.scheduleAccount(account);
    }
    
    console.log(`✅ Scheduler started with ${accounts.length} accounts`);
  }
  
  scheduleAccount(account) {
    // Remove existing job if any
    if (this.jobs.has(account.id)) {
      this.jobs.get(account.id).stop();
    }
    
    // Schedule new job
    const cronExpression = account.cron_expression || '0 0 */60 * *';
    
    try {
      const job = cron.schedule(cronExpression, async () => {
        await this.executeLogin(account.id);
      });
      
      this.jobs.set(account.id, job);
      console.log(`📅 Scheduled account ${account.username} with cron: ${cronExpression}`);
    } catch (error) {
      console.error(`Error scheduling account ${account.username}:`, error);
    }
  }
  
  async executeLogin(accountId) {
    try {
      const accounts = await db.query('SELECT * FROM accounts WHERE id = ?', [accountId]);
      if (accounts.length === 0 || !accounts[0].enabled) return;
      
      const account = accounts[0];
      const today = new Date().toISOString().split('T')[0];
      
      // Check if already logged in today
      const existing = await db.query(
        'SELECT id FROM login_history WHERE account_id = ? AND login_date = ?',
        [accountId, today]
      );
      
      if (existing.length > 0) {
        console.log(`Account ${account.username} already logged in today`);
        return;
      }
      
      // Perform login
      const result = await this.loginService.performLogin(
        account.username,
        account.password,
        account.username
      );
      
      // Record history
      await db.execute(
        'INSERT INTO login_history (account_id, success, message, login_date) VALUES (?, ?, ?, ?)',
        [accountId, result.success ? 1 : 0, result.message, today]
      );
      
      // Update last login date if successful
      if (result.success) {
        await db.execute(
          'UPDATE accounts SET last_login_date = ? WHERE id = ?',
          [today, accountId]
        );
      }
      
      // Send notification
      const channels = dbType === 'mysql'
        ? account.notification_channels
        : (account.notification_channels ? JSON.parse(account.notification_channels) : null);
      
      if (channels && channels.length > 0) {
        const title = `Netlib 保活结果 - ${account.username}`;
        const status = result.success ? '✅ 成功' : '❌ 失败';
        const content = `状态: ${status}\n消息: ${result.message}`;
        
        await NotificationService.sendNotification(title, content, account.username, channels);
      }
      
      console.log(`Login for ${account.username}: ${result.success ? 'Success' : 'Failed'}`);
    } catch (error) {
      console.error(`Error executing login for account ${accountId}:`, error);
    }
  }
  
  removeAccount(accountId) {
    if (this.jobs.has(accountId)) {
      this.jobs.get(accountId).stop();
      this.jobs.delete(accountId);
    }
  }
}

const scheduler = new LoginScheduler();

// API Routes

// Login
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  
  if (username === ADMIN_USERNAME && password === ADMIN_PASSWORD) {
    const token = jwt.sign({ user: username }, JWT_SECRET, { expiresIn: '7d' });
    return res.json({ token, message: 'Login successful' });
  }
  
  res.status(401).json({ message: 'Invalid credentials' });
});

// Verify token
app.get('/api/verify', authenticateToken, (req, res) => {
  res.json({ valid: true });
});

// Dashboard statistics
app.get('/api/dashboard', authenticateToken, async (req, res) => {
  try {
    const totalAccounts = await db.query('SELECT COUNT(*) as count FROM accounts');
    const enabledAccounts = await db.query(
      'SELECT COUNT(*) as count FROM accounts WHERE enabled = ?',
      [dbType === 'mysql' ? true : 1]
    );
    
    const today = new Date().toISOString().split('T')[0];
    const todayLogins = await db.query(
      `SELECT a.username, lh.success, lh.message, lh.created_at
       FROM login_history lh
       JOIN accounts a ON lh.account_id = a.id
       WHERE DATE(lh.login_date) = DATE(?)
       ORDER BY lh.created_at DESC
       LIMIT 20`,
      [today]
    );
    
    const totalLogins = await db.query('SELECT COUNT(*) as count FROM login_history');
    const successfulLogins = await db.query(
      'SELECT COUNT(*) as count FROM login_history WHERE success = ?',
      [dbType === 'mysql' ? true : 1]
    );
    
    const totalCount = totalLogins[0].count;
    const successCount = successfulLogins[0].count;
    const successRate = totalCount > 0 ? ((successCount / totalCount) * 100).toFixed(2) : 0;
    
    res.json({
      total_accounts: totalAccounts[0].count,
      enabled_accounts: enabledAccounts[0].count,
      today_logins: todayLogins,
      total_logins: totalCount,
      successful_logins: successCount,
      success_rate: successRate
    });
  } catch (error) {
    console.error('Dashboard error:', error);
    res.status(500).json({ error: 'Failed to load dashboard data' });
  }
});

// Get all accounts
app.get('/api/accounts', authenticateToken, async (req, res) => {
  try {
    const accounts = await db.query(
      'SELECT id, username, enabled, cron_expression, notification_channels, last_login_date, created_at FROM accounts'
    );
    
    const result = accounts.map(acc => ({
      ...acc,
      notification_channels: dbType === 'sqlite' && acc.notification_channels
        ? JSON.parse(acc.notification_channels)
        : acc.notification_channels
    }));
    
    res.json(result);
  } catch (error) {
    console.error('Get accounts error:', error);
    res.status(500).json({ error: 'Failed to load accounts' });
  }
});

// Add account
app.post('/api/accounts', authenticateToken, async (req, res) => {
  try {
    const { username, password, cron_expression, notification_channels } = req.body;
    
    if (!username || !password) {
      return res.status(400).json({ message: 'Username and password are required' });
    }
    
    const channels = dbType === 'mysql'
      ? notification_channels
      : JSON.stringify(notification_channels || []);
    
    await db.execute(
      'INSERT INTO accounts (username, password, cron_expression, notification_channels) VALUES (?, ?, ?, ?)',
      [username, password, cron_expression || '0 0 */60 * *', channels]
    );
    
    // Get the new account and schedule it
    const newAccounts = await db.query('SELECT * FROM accounts WHERE username = ?', [username]);
    if (newAccounts.length > 0) {
      scheduler.scheduleAccount(newAccounts[0]);
    }
    
    res.json({ message: 'Account added successfully' });
  } catch (error) {
    console.error('Add account error:', error);
    res.status(400).json({ message: error.message });
  }
});

// Update account
app.put('/api/accounts/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { enabled, password, cron_expression, notification_channels } = req.body;
    
    const updates = [];
    const params = [];
    
    if (typeof enabled !== 'undefined') {
      updates.push('enabled = ?');
      params.push(dbType === 'mysql' ? enabled : (enabled ? 1 : 0));
    }
    
    if (password) {
      updates.push('password = ?');
      params.push(password);
    }
    
    if (cron_expression) {
      updates.push('cron_expression = ?');
      params.push(cron_expression);
    }
    
    if (notification_channels) {
      updates.push('notification_channels = ?');
      params.push(dbType === 'mysql' ? notification_channels : JSON.stringify(notification_channels));
    }
    
    if (updates.length > 0) {
      params.push(id);
      await db.execute(
        `UPDATE accounts SET ${updates.join(', ')}, updated_at = CURRENT_TIMESTAMP WHERE id = ?`,
        params
      );
      
      // Reschedule if enabled or cron changed
      const accounts = await db.query('SELECT * FROM accounts WHERE id = ?', [id]);
      if (accounts.length > 0) {
        if (accounts[0].enabled) {
          scheduler.scheduleAccount(accounts[0]);
        } else {
          scheduler.removeAccount(parseInt(id));
        }
      }
    }
    
    res.json({ message: 'Account updated successfully' });
  } catch (error) {
    console.error('Update account error:', error);
    res.status(400).json({ message: error.message });
  }
});

// Delete account
app.delete('/api/accounts/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    
    await db.execute('DELETE FROM login_history WHERE account_id = ?', [id]);
    await db.execute('DELETE FROM accounts WHERE id = ?', [id]);
    
    scheduler.removeAccount(parseInt(id));
    
    res.json({ message: 'Account deleted successfully' });
  } catch (error) {
    console.error('Delete account error:', error);
    res.status(400).json({ message: error.message });
  }
});

// Manual login
app.post('/api/login/manual/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    scheduler.executeLogin(parseInt(id));
    res.json({ message: 'Manual login triggered' });
  } catch (error) {
    console.error('Manual login error:', error);
    res.status(400).json({ message: error.message });
  }
});

// Clear login history
app.post('/api/login/clear', authenticateToken, async (req, res) => {
  try {
    const { type, ids } = req.body;
    
    if (type === 'selected' && ids && ids.length > 0) {
      const placeholders = ids.map(() => '?').join(',');
      await db.execute(`DELETE FROM login_history WHERE id IN (${placeholders})`, ids);
    } else if (type === 'all') {
      await db.execute('DELETE FROM login_history');
      await db.execute('UPDATE accounts SET last_login_date = NULL');
    }
    
    res.json({ message: 'Login history cleared' });
  } catch (error) {
    console.error('Clear history error:', error);
    res.status(400).json({ message: error.message });
  }
});

// Get notification settings
app.get('/api/notification', authenticateToken, async (req, res) => {
  try {
    const settings = await db.query('SELECT * FROM notification_settings');
    
    const result = settings.map(s => ({
      ...s,
      config: dbType === 'sqlite' ? JSON.parse(s.config) : s.config
    }));
    
    res.json(result);
  } catch (error) {
    console.error('Get notification settings error:', error);
    res.status(500).json({ error: 'Failed to load settings' });
  }
});

// Update notification settings
app.put('/api/notification/:channel', authenticateToken, async (req, res) => {
  try {
    const { channel } = req.params;
    const { enabled, config } = req.body;
    
    const configStr = dbType === 'mysql' ? config : JSON.stringify(config);
    
    await db.execute(
      'UPDATE notification_settings SET enabled = ?, config = ?, updated_at = CURRENT_TIMESTAMP WHERE channel_type = ?',
      [dbType === 'mysql' ? enabled : (enabled ? 1 : 0), configStr, channel]
    );
    
    res.json({ message: 'Notification settings updated successfully' });
  } catch (error) {
    console.error('Update notification settings error:', error);
    res.status(400).json({ message: error.message });
  }
});

// Test notification
app.post('/api/test/notification', authenticateToken, async (req, res) => {
  try {
    const { channel } = req.body;
    
    await NotificationService.sendNotification(
      '测试通知',
      '这是来自Netlib保活系统的测试通知。如果您收到此消息，说明您的通知设置正常工作！',
      '系统测试',
      [channel]
    );
    
    res.json({ message: 'Test notification sent' });
  } catch (error) {
    console.error('Test notification error:', error);
    res.status(400).json({ message: error.message });
  }
});

// Serve HTML
app.get('/', (req, res) => {
  res.send(HTML_TEMPLATE);
});

// HTML Template (same as Python version, with minor adjustments)
const HTML_TEMPLATE = `
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Netlib 保活控制面板</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'PingFang SC', sans-serif; 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
            min-height: 100vh;
        }
        
        .login-container { 
            display: flex; 
            justify-content: center; 
            align-items: center; 
            min-height: 100vh; 
            padding: 20px;
        }
        .login-box { 
            background: white; 
            padding: 40px; 
            border-radius: 15px; 
            box-shadow: 0 20px 60px rgba(0,0,0,0.2); 
            width: 100%;
            max-width: 400px;
        }
        .login-box h2 { 
            margin-bottom: 30px; 
            color: #333; 
            text-align: center;
        }
        
        .form-group { margin-bottom: 20px; }
        .form-group label { 
            display: block; 
            margin-bottom: 8px; 
            color: #555; 
        }
        .form-group input, .form-group textarea, .form-group select { 
            width: 100%; 
            padding: 12px; 
            border: 2px solid #e0e0e0; 
            border-radius: 8px; 
            font-size: 14px;
        }
        .form-group input:focus, .form-group textarea:focus, .form-group select:focus { 
            border-color: #667eea;
            outline: none;
        }
        
        .btn { 
            padding: 12px 24px; 
            background: linear-gradient(135deg, #667eea, #764ba2); 
            color: white; 
            border: none; 
            border-radius: 8px; 
            cursor: pointer; 
            font-size: 14px; 
        }
        .btn:hover { transform: translateY(-2px); }
        .btn-full { width: 100%; }
        .btn-sm { padding: 8px 16px; font-size: 13px; }
        .btn-danger { background: linear-gradient(135deg, #f56565, #e53e3e); }
        .btn-success { background: linear-gradient(135deg, #48bb78, #38a169); }
        
        .dashboard { display: none; padding: 20px; background: #f7fafc; min-height: 100vh; }
        .container { max-width: 1200px; margin: 0 auto; }
        .header { 
            background: white; 
            padding: 20px 30px; 
            border-radius: 15px; 
            margin-bottom: 30px; 
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .stats-grid { 
            display: grid; 
            grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); 
            gap: 20px; 
            margin-bottom: 30px; 
        }
        .stat-card { 
            background: white; 
            padding: 25px; 
            border-radius: 15px; 
        }
        .stat-card h3 { color: #718096; font-size: 14px; margin-bottom: 12px; }
        .stat-card .value { 
            font-size: 32px; 
            font-weight: bold; 
            background: linear-gradient(135deg, #667eea, #764ba2);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }
        
        .section { 
            background: white; 
            padding: 30px; 
            border-radius: 15px; 
            margin-bottom: 30px;
        }
        .section-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 25px;
        }
        
        .table { width: 100%; border-collapse: collapse; }
        .table th, .table td { padding: 14px; text-align: left; border-bottom: 1px solid #e2e8f0; }
        .table th { background: #f7fafc; font-weight: 600; }
        .table tbody tr:hover { background: #f7fafc; }
        
        .badge { 
            padding: 6px 12px; 
            border-radius: 6px; 
            font-size: 12px;
            display: inline-block;
        }
        .badge-success { background: #c6f6d5; color: #22543d; }
        .badge-danger { background: #fed7d7; color: #742a2a; }
        
        .switch { position: relative; display: inline-block; width: 50px; height: 26px; }
        .switch input { opacity: 0; width: 0; height: 0; }
        .slider { 
            position: absolute; 
            cursor: pointer; 
            top: 0; left: 0; right: 0; bottom: 0; 
            background-color: #cbd5e0; 
            transition: .4s; 
            border-radius: 26px; 
        }
        .slider:before { 
            position: absolute; 
            content: ""; 
            height: 20px; width: 20px; 
            left: 3px; bottom: 3px; 
            background-color: white; 
            transition: .4s; 
            border-radius: 50%; 
        }
        input:checked + .slider { background: linear-gradient(135deg, #667eea, #764ba2); }
        input:checked + .slider:before { transform: translateX(24px); }
        
        .modal { 
            display: none; 
            position: fixed; 
            top: 0; left: 0; 
            width: 100%; height: 100%; 
            background: rgba(0,0,0,0.6); 
            justify-content: center; 
            align-items: center;
            padding: 20px;
        }
        .modal-content { 
            background: white; 
            padding: 30px; 
            border-radius: 15px; 
            width: 100%;
            max-width: 600px;
            max-height: 90vh;
            overflow-y: auto;
        }
        .modal-header { 
            margin-bottom: 25px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .close { 
            font-size: 28px; 
            cursor: pointer; 
            color: #a0aec0;
        }
        
        .toast {
            position: fixed;
            bottom: 20px;
            right: 20px;
            background: white;
            padding: 16px 24px;
            border-radius: 8px;
            box-shadow: 0 4px 12px rgba(0,0,0,0.15);
            display: none;
            z-index: 2000;
        }
        .toast.success { border-left: 4px solid #48bb78; }
        .toast.error { border-left: 4px solid #f56565; }
    </style>
</head>
<body>
    <div id="toast" class="toast"></div>

    <div class="login-container" id="loginContainer">
        <div class="login-box">
            <h2>🔐 管理员登录</h2>
            <div class="form-group">
                <label>用户名</label>
                <input type="text" id="username">
            </div>
            <div class="form-group">
                <label>密码</label>
                <input type="password" id="password">
            </div>
            <button class="btn btn-full" onclick="handleLogin()">登录</button>
        </div>
    </div>

    <div class="dashboard" id="dashboard">
        <div class="container">
            <div class="header">
                <h1>📊 Netlib 保活控制面板</h1>
                <button class="btn btn-danger btn-sm" onclick="logout()">退出</button>
            </div>

            <div class="stats-grid">
                <div class="stat-card">
                    <h3>账号总数</h3>
                    <div class="value" id="totalAccounts">0</div>
                </div>
                <div class="stat-card">
                    <h3>活跃账号</h3>
                    <div class="value" id="activeAccounts">0</div>
                </div>
                <div class="stat-card">
                    <h3>保活总数</h3>
                    <div class="value" id="totalLogins">0</div>
                </div>
                <div class="stat-card">
                    <h3>成功率</h3>
                    <div class="value" id="successRate">0%</div>
                </div>
            </div>

            <div class="section">
                <div class="section-header">
                    <h2>📅 今日保活记录</h2>
                    <button class="btn btn-danger btn-sm" onclick="clearHistory('all')">清空所有</button>
                </div>
                <table class="table">
                    <thead>
                        <tr>
                            <th><input type="checkbox" id="selectAll" onchange="toggleSelectAll()"></th>
                            <th>账号</th>
                            <th>状态</th>
                            <th>消息</th>
                            <th>时间</th>
                        </tr>
                    </thead>
                    <tbody id="todayLogins"></tbody>
                </table>
                <button class="btn btn-danger btn-sm" onclick="deleteSelected()" style="margin-top: 10px;">删除选中</button>
            </div>

            <div class="section">
                <div class="section-header">
                    <h2>👥 账号管理</h2>
                    <button class="btn btn-success btn-sm" onclick="showAddModal()">+ 添加账号</button>
                </div>
                <table class="table">
                    <thead>
                        <tr>
                            <th>用户名</th>
                            <th>状态</th>
                            <th>Cron表达式</th>
                            <th>通知渠道</th>
                            <th>操作</th>
                        </tr>
                    </thead>
                    <tbody id="accountsList"></tbody>
                </table>
            </div>

            <div class="section">
                <div class="section-header">
                    <h2>🔔 通知设置</h2>
                </div>
                <div id="notificationSettings"></div>
            </div>
        </div>
    </div>

    <div class="modal" id="addAccountModal">
        <div class="modal-content">
            <div class="modal-header">
                <h3>添加账号</h3>
                <span class="close" onclick="closeModal('addAccountModal')">&times;</span>
            </div>
            <div class="form-group">
                <label>用户名</label>
                <input type="text" id="newUsername">
            </div>
            <div class="form-group">
                <label>密码</label>
                <input type="password" id="newPassword">
            </div>
            <div class="form-group">
                <label>Cron表达式</label>
                <input type="text" id="newCron" value="0 0 */60 * *">
                <small>默认60天执行一次</small>
            </div>
            <div class="form-group">
                <label>通知渠道</label>
                <select multiple id="newChannels">
                    <option value="telegram">Telegram</option>
                    <option value="wechat">企业微信</option>
                    <option value="wxpusher">WxPusher</option>
                    <option value="dingtalk">钉钉</option>
                </select>
            </div>
            <button class="btn btn-full" onclick="addAccount()">添加</button>
        </div>
    </div>

    <script>
        let authToken = localStorage.getItem('authToken');
        
        function showToast(message, type = 'info') {
            const toast = document.getElementById('toast');
            toast.className = \`toast \${type}\`;
            toast.textContent = message;
            toast.style.display = 'block';
            setTimeout(() => toast.style.display = 'none', 3000);
        }

        async function handleLogin() {
            const username = document.getElementById('username').value;
            const password = document.getElementById('password').value;
            
            try {
                const response = await fetch('/api/login', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ username, password })
                });

                const data = await response.json();
                if (response.ok) {
                    authToken = data.token;
                    localStorage.setItem('authToken', authToken);
                    document.getElementById('loginContainer').style.display = 'none';
                    document.getElementById('dashboard').style.display = 'block';
                    loadDashboard();
                } else {
                    showToast(data.message, 'error');
                }
            } catch (error) {
                showToast('登录失败', 'error');
            }
        }

        function logout() {
            localStorage.removeItem('authToken');
            location.reload();
        }

        async function apiCall(url, options = {}) {
            const response = await fetch(url, {
                ...options,
                headers: {
                    'Authorization': 'Bearer ' + authToken,
                    'Content-Type': 'application/json',
                    ...options.headers
                }
            });

            if (response.status === 401) {
                logout();
                return;
            }

            return await response.json();
        }

        async function loadDashboard() {
            const data = await apiCall('/api/dashboard');
            document.getElementById('totalAccounts').textContent = data.total_accounts;
            document.getElementById('activeAccounts').textContent = data.enabled_accounts;
            document.getElementById('totalLogins').textContent = data.total_logins;
            document.getElementById('successRate').textContent = data.success_rate + '%';

            const tbody = document.getElementById('todayLogins');
            tbody.innerHTML = data.today_logins.map(login => \`
                <tr>
                    <td><input type="checkbox" class="login-checkbox" value="\${login.id}"></td>
                    <td>\${login.username}</td>
                    <td><span class="badge badge-\${login.success ? 'success' : 'danger'}">\${login.success ? '成功' : '失败'}</span></td>
                    <td>\${login.message}</td>
                    <td>\${new Date(login.created_at).toLocaleString()}</td>
                </tr>
            \`).join('');

            loadAccounts();
            loadNotificationSettings();
        }

        async function loadAccounts() {
            const accounts = await apiCall('/api/accounts');
            const tbody = document.getElementById('accountsList');
            tbody.innerHTML = accounts.map(acc => \`
                <tr>
                    <td>\${acc.username}</td>
                    <td>
                        <label class="switch">
                            <input type="checkbox" \${acc.enabled ? 'checked' : ''} onchange="toggleAccount(\${acc.id}, this.checked)">
                            <span class="slider"></span>
                        </label>
                    </td>
                    <td>\${acc.cron_expression}</td>
                    <td>\${(acc.notification_channels || []).join(', ') || '-'}</td>
                    <td>
                        <button class="btn btn-success btn-sm" onclick="manualLogin(\${acc.id})">立即执行</button>
                        <button class="btn btn-danger btn-sm" onclick="deleteAccount(\${acc.id})">删除</button>
                    </td>
                </tr>
            \`).join('');
        }

        async function loadNotificationSettings() {
            const settings = await apiCall('/api/notification');
            const container = document.getElementById('notificationSettings');
            
            container.innerHTML = settings.map(s => \`
                <div style="margin-bottom: 20px; padding: 20px; background: #f7fafc; border-radius: 10px;">
                    <h4>\${s.channel_type}</h4>
                    <label class="switch">
                        <input type="checkbox" \${s.enabled ? 'checked' : ''} onchange="toggleNotification('\${s.channel_type}', this.checked)">
                        <span class="slider"></span>
                    </label>
                    <button class="btn btn-sm" onclick="testNotification('\${s.channel_type}')">测试</button>
                </div>
            \`).join('');
        }

        async function toggleAccount(id, enabled) {
            await apiCall(\`/api/accounts/\${id}\`, {
                method: 'PUT',
                body: JSON.stringify({ enabled })
            });
            loadAccounts();
        }

        async function deleteAccount(id) {
            if (confirm('确定删除此账号吗？')) {
                await apiCall(\`/api/accounts/\${id}\`, { method: 'DELETE' });
                loadAccounts();
            }
        }

        async function manualLogin(id) {
            await apiCall(\`/api/login/manual/\${id}\`, { method: 'POST' });
            showToast('保活任务已触发', 'success');
        }

        function showAddModal() {
            document.getElementById('addAccountModal').style.display = 'flex';
        }

        function closeModal(id) {
            document.getElementById(id).style.display = 'none';
        }

        async function addAccount() {
            const username = document.getElementById('newUsername').value;
            const password = document.getElementById('newPassword').value;
            const cron_expression = document.getElementById('newCron').value;
            const select = document.getElementById('newChannels');
            const notification_channels = Array.from(select.selectedOptions).map(o => o.value);

            await apiCall('/api/accounts', {
                method: 'POST',
                body: JSON.stringify({ username, password, cron_expression, notification_channels })
            });
            
            closeModal('addAccountModal');
            loadAccounts();
        }

        async function toggleNotification(channel, enabled) {
            await apiCall(\`/api/notification/\${channel}\`, {
                method: 'PUT',
                body: JSON.stringify({ enabled, config: {} })
            });
        }

        async function testNotification(channel) {
            await apiCall('/api/test/notification', {
                method: 'POST',
                body: JSON.stringify({ channel })
            });
            showToast('测试通知已发送', 'info');
        }

        function toggleSelectAll() {
            const checked = document.getElementById('selectAll').checked;
            document.querySelectorAll('.login-checkbox').forEach(cb => cb.checked = checked);
        }

        async function deleteSelected() {
            const ids = Array.from(document.querySelectorAll('.login-checkbox:checked')).map(cb => parseInt(cb.value));
            if (ids.length === 0) return;
            
            if (confirm(\`确定删除选中的 \${ids.length} 条记录吗？\`)) {
                await apiCall('/api/login/clear', {
                    method: 'POST',
                    body: JSON.stringify({ type: 'selected', ids })
                });
                loadDashboard();
            }
        }

        async function clearHistory(type) {
            if (confirm('确定清空所有记录吗？')) {
                await apiCall('/api/login/clear', {
                    method: 'POST',
                    body: JSON.stringify({ type })
                });
                loadDashboard();
            }
        }

        if (authToken) {
            fetch('/api/verify', {
                headers: { 'Authorization': 'Bearer ' + authToken }
            }).then(response => {
                if (response.ok) {
                    document.getElementById('loginContainer').style.display = 'none';
                    document.getElementById('dashboard').style.display = 'block';
                    loadDashboard();
                } else {
                    logout();
                }
            });
        }

        document.getElementById('password').addEventListener('keypress', e => {
            if (e.key === 'Enter') handleLogin();
        });
    </script>
</body>
</html>
`;

// Start application
(async () => {
  try {
    await initDatabase();
    await scheduler.start();
    
    app.listen(PORT, () => {
      console.log(`\n✅ Netlib Keep-Alive Control Panel started`);
      console.log(`📡 Server: http://localhost:${PORT}`);
      console.log(`💾 Database: ${dbType.toUpperCase()}`);
      console.log(`👤 Admin: ${ADMIN_USERNAME}`);
      console.log(`\n🚀 System ready!\n`);
    });
  } catch (error) {
    console.error('Failed to start application:', error);
    process.exit(1);
  }
})();
