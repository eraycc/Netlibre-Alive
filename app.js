const express = require('express');
const { chromium } = require('playwright');
const mysql = require('mysql2/promise');
const sqlite3 = require('sqlite3').verbose();
const jwt = require('jsonwebtoken');
const cron = require('node-cron');
const axios = require('axios');
const crypto = require('crypto');
const { URL } = require('url');

// ============================================================================
// 配置和环境变量
// ============================================================================
const CONFIG = {
  port: process.env.PORT || 3000,
  adminUsername: process.env.ADMIN_USERNAME || 'admin',
  adminPassword: process.env.ADMIN_PASSWORD || 'admin123',
  jwtSecret: process.env.JWT_SECRET || crypto.randomBytes(32).toString('hex'),
  mysqlDsn: process.env.MYSQL_DSN || '',
  // 保活配置
  keepalive: {
    defaultInterval: parseInt(process.env.DEFAULT_INTERVAL) || 60 * 60 * 1000, // 默认60分钟
    timeout: 30000,
  }
};

// ============================================================================
// 数据库层
// ============================================================================
class Database {
  constructor() {
    this.type = 'sqlite';
    this.connection = null;
    this.pool = null;
  }

  async init() {
    if (CONFIG.mysqlDsn) {
      try {
        await this.initMySQL();
        this.type = 'mysql';
        console.log('✅ 使用 MySQL 数据库');
      } catch (error) {
        console.error('❌ MySQL 连接失败，回退到 SQLite:', error.message);
        await this.initSQLite();
      }
    } else {
      await this.initSQLite();
    }
    await this.createTables();
  }

  async initMySQL() {
    const parsed = this.parseMySQLDSN(CONFIG.mysqlDsn);
    if (!parsed) throw new Error('无效的 MySQL DSN 格式');

    this.pool = mysql.createPool({
      host: parsed.host,
      port: parsed.port,
      user: parsed.username,
      password: parsed.password,
      database: parsed.database,
      ssl: parsed.ssl,
      waitForConnections: true,
      connectionLimit: 10,
      queueLimit: 0,
      enableKeepAlive: true,
      keepAliveInitialDelay: 0,
    });

    // 测试连接
    await this.pool.query('SELECT 1');
  }

  parseMySQLDSN(dsn) {
    try {
      const url = new URL(dsn);
      return {
        host: url.hostname,
        port: url.port || 3306,
        username: decodeURIComponent(url.username),
        password: decodeURIComponent(url.password),
        database: url.pathname.replace('/', ''),
        ssl: url.searchParams.get('ssl') === 'true'
      };
    } catch (e) {
      return null;
    }
  }

  async initSQLite() {
    return new Promise((resolve, reject) => {
      const dbPath = process.env.SQLITE_PATH || './data/netlib.db';
      const path = require('path');
      const fs = require('fs');
      
      // 确保目录存在
      const dir = path.dirname(dbPath);
      if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
      }

      this.connection = new sqlite3.Database(dbPath, (err) => {
        if (err) reject(err);
        else {
          console.log('✅ 使用 SQLite 数据库');
          resolve();
        }
      });
    });
  }

  async query(sql, params = []) {
    if (this.type === 'mysql') {
      const [results] = await this.pool.query(sql, params);
      return results;
    } else {
      return new Promise((resolve, reject) => {
        this.connection.all(sql, params, (err, rows) => {
          if (err) reject(err);
          else resolve(rows);
        });
      });
    }
  }

  async run(sql, params = []) {
    if (this.type === 'mysql') {
      const [result] = await this.pool.query(sql, params);
      return result;
    } else {
      return new Promise((resolve, reject) => {
        this.connection.run(sql, params, function(err) {
          if (err) reject(err);
          else resolve({ insertId: this.lastID, changes: this.changes });
        });
      });
    }
  }

  async createTables() {
    const accountsTable = `
      CREATE TABLE IF NOT EXISTS accounts (
        id INTEGER PRIMARY KEY ${this.type === 'mysql' ? 'AUTO_INCREMENT' : 'AUTOINCREMENT'},
        name VARCHAR(255) NOT NULL UNIQUE,
        username VARCHAR(255) NOT NULL,
        password VARCHAR(255) NOT NULL,
        enabled BOOLEAN DEFAULT TRUE,
        cron_expression VARCHAR(255) DEFAULT '0 */12 * * *',
        interval_minutes INTEGER DEFAULT 60,
        last_keepalive DATETIME,
        notification_enabled BOOLEAN DEFAULT FALSE,
        telegram_enabled BOOLEAN DEFAULT FALSE,
        telegram_bot_token VARCHAR(255),
        telegram_chat_id VARCHAR(255),
        wechat_enabled BOOLEAN DEFAULT FALSE,
        wechat_webhook VARCHAR(255),
        wxpusher_enabled BOOLEAN DEFAULT FALSE,
        wxpusher_app_token VARCHAR(255),
        wxpusher_uid VARCHAR(255),
        dingtalk_enabled BOOLEAN DEFAULT FALSE,
        dingtalk_webhook VARCHAR(255),
        dingtalk_secret VARCHAR(255),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
      )
    `;

    const historyTable = `
      CREATE TABLE IF NOT EXISTS history (
        id INTEGER PRIMARY KEY ${this.type === 'mysql' ? 'AUTO_INCREMENT' : 'AUTOINCREMENT'},
        account_id INTEGER NOT NULL,
        success BOOLEAN NOT NULL,
        message TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        ${this.type === 'mysql' ? 'FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE CASCADE' : ''}
      )
    `;

    const settingsTable = `
      CREATE TABLE IF NOT EXISTS settings (
        id INTEGER PRIMARY KEY,
        notification_proxy VARCHAR(255),
        browser_headless BOOLEAN DEFAULT TRUE,
        browser_timeout INTEGER DEFAULT 30000,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
      )
    `;

    try {
      await this.query(accountsTable);
      await this.query(historyTable);
      await this.query(settingsTable);
      
      // 插入默认设置
      const defaultSettings = `INSERT OR IGNORE INTO settings (id) VALUES (1)`;
      await this.query(defaultSettings);
      
      console.log('✅ 数据库表创建成功');
    } catch (error) {
      console.error('❌ 创建表失败:', error);
      throw error;
    }
  }
}

// ============================================================================
// 通知服务
// ============================================================================
class NotificationService {
  static async send(account, title, message) {
    if (!account.notification_enabled) return;

    const tasks = [];

    // Telegram
    if (account.telegram_enabled && account.telegram_bot_token && account.telegram_chat_id) {
      tasks.push(this.sendTelegram(account, title, message));
    }

    // 企业微信
    if (account.wechat_enabled && account.wechat_webhook) {
      tasks.push(this.sendWechat(account, title, message));
    }

    // WxPusher
    if (account.wxpusher_enabled && account.wxpusher_app_token && account.wxpusher_uid) {
      tasks.push(this.sendWxPusher(account, title, message));
    }

    // 钉钉
    if (account.dingtalk_enabled && account.dingtalk_webhook) {
      tasks.push(this.sendDingTalk(account, title, message));
    }

    try {
      await Promise.allSettled(tasks);
    } catch (error) {
      console.error('通知发送失败:', error);
    }
  }

  static async sendTelegram(account, title, message) {
    const url = `https://api.telegram.org/bot${account.telegram_bot_token}/sendMessage`;
    await axios.post(url, {
      chat_id: account.telegram_chat_id,
      text: `🤖 Netlib 保活通知\n\n${title}\n${message}\n\n时间: ${new Date().toLocaleString()}`
    }, { timeout: 10000 });
  }

  static async sendWechat(account, title, message) {
    await axios.post(account.wechat_webhook, {
      msgtype: 'text',
      text: { content: `Netlib 保活通知\n${title}\n${message}` }
    }, { timeout: 10000 });
  }

  static async sendWxPusher(account, title, message) {
    const url = 'https://wxpusher.zjiecode.com/api/send/message';
    await axios.post(url, {
      appToken: account.wxpusher_app_token,
      content: `<h3>${title}</h3><p>${message}</p><p>时间: ${new Date().toLocaleString()}</p>`,
      contentType: 2,
      uids: [account.wxpusher_uid]
    }, { timeout: 10000 });
  }

  static async sendDingTalk(account, title, message) {
    let webhook = account.dingtalk_webhook;
    
    // 如果设置了 secret，需要签名
    if (account.dingtalk_secret) {
      const timestamp = Date.now();
      const stringToSign = `${timestamp}\n${account.dingtalk_secret}`;
      const sign = crypto.createHmac('sha256', account.dingtalk_secret)
        .update(stringToSign).digest('base64');
      const encodedSign = encodeURIComponent(sign);
      
      webhook = `${webhook}&timestamp=${timestamp}&sign=${encodedSign}`;
    }

    await axios.post(webhook, {
      msgtype: 'text',
      text: { content: `Netlib 保活通知\n${title}\n${message}` }
    }, { timeout: 10000 });
  }
}

// ============================================================================
// 保活服务
// ============================================================================
class KeepAliveService {
  constructor() {
    this.tasks = new Map();
    this.running = false;
  }

  async start() {
    this.running = true;
    console.log('🚀 保活服务启动');
    await this.loadAndScheduleAll();
    
    // 每分钟检查一次
    setInterval(() => this.checkAndSchedule(), 60000);
  }

  stop() {
    this.running = false;
    this.tasks.forEach(task => clearTimeout(task.timeout));
    this.tasks.clear();
    console.log('🛑 保活服务停止');
  }

  async loadAndScheduleAll() {
    const db = new Database();
    await db.init();
    
    const accounts = await db.query('SELECT * FROM accounts WHERE enabled = 1');
    
    for (const account of accounts) {
      await this.scheduleAccount(account);
    }
  }

  async scheduleAccount(account) {
    if (!this.running) return;

    // 清除现有任务
    if (this.tasks.has(account.id)) {
      clearTimeout(this.tasks.get(account.id).timeout);
    }

    // 计算下次执行时间
    const now = new Date();
    let nextRun;
    
    if (account.cron_expression) {
      // 使用 cron 表达式
      const interval = cron.schedule(account.cron_expression, () => this.execute(account.id));
      this.tasks.set(account.id, { interval, type: 'cron' });
      console.log(`⏰ 账号 ${account.name} 使用 cron: ${account.cron_expression}`);
      return;
    } else {
      // 使用间隔时间
      const intervalMs = (account.interval_minutes || 60) * 60 * 1000;
      const last = account.last_keepalive ? new Date(account.last_keepalive) : new Date(0);
      nextRun = new Date(last.getTime() + intervalMs);
      
      if (nextRun <= now) {
        nextRun = new Date(now.getTime() + 5000); // 5秒后执行
      }
    }

    const timeout = setTimeout(() => {
      this.execute(account.id);
    }, nextRun - now);

    this.tasks.set(account.id, { timeout, type: 'interval' });
    console.log(`⏰ 账号 ${account.name} 下次运行: ${nextRun.toLocaleString()}`);
  }

  async execute(accountId) {
    const db = new Database();
    await db.init();

    const account = await db.query('SELECT * FROM accounts WHERE id = ?', [accountId]);
    if (!account[0]) return;

    const acc = account[0];
    console.log(`🎯 开始保活: ${acc.name}`);

    let success = false;
    let message = '';

    try {
      // 执行登录
      const result = await this.performLogin(acc);
      success = result.success;
      message = result.message;

      console.log(`${success ? '✅' : '❌'} ${acc.name}: ${message}`);
    } catch (error) {
      message = error.message;
      console.error(`❌ ${acc.name} 异常:`, error);
    }

    // 记录历史
    await db.run(
      'INSERT INTO history (account_id, success, message) VALUES (?, ?, ?)',
      [accountId, success, message]
    );

    // 更新最后运行时间
    if (success) {
      await db.run('UPDATE accounts SET last_keepalive = ? WHERE id = ?', [new Date(), accountId]);
    }

    // 发送通知
    if (acc.notification_enabled) {
      const title = `${acc.name} 保活${success ? '成功' : '失败'}`;
      await NotificationService.send(acc, title, message);
    }

    // 重新调度
    setTimeout(() => this.scheduleAccount(acc), 5000);
  }

  async performLogin(account) {
    const browser = await chromium.launch({
      headless: true,
      args: ['--no-sandbox', '--disable-setuid-sandbox']
    });

    try {
      const page = await browser.newPage();
      await page.setDefaultTimeout(CONFIG.keepalive.timeout);

      console.log(`📱 ${account.name} - 访问网站...`);
      await page.goto('https://www.netlib.re/', { waitUntil: 'networkidle' });
      await page.waitForTimeout(2000);

      console.log(`🔑 ${account.name} - 点击登录...`);
      await page.click('text=Login');
      await page.waitForTimeout(1000);

      console.log(`📝 ${account.name} - 填写用户名...`);
      await page.fill('input[name="username"], input[type="text"]', account.username);
      await page.waitForTimeout(500);

      console.log(`🔒 ${account.name} - 填写密码...`);
      await page.fill('input[name="password"], input[type="password"]', account.password);
      await page.waitForTimeout(500);

      console.log(`📤 ${account.name} - 提交登录...`);
      await page.click('button:has-text("Validate"), input[type="submit"]');
      await page.waitForLoadState('networkidle');
      await page.waitForTimeout(3000);

      // 检查登录结果
      const content = await page.content();
      
      if (content.includes('exclusive owner') || content.includes(account.username)) {
        return {
          success: true,
          message: '登录成功'
        };
      } else {
        return {
          success: false,
          message: '登录失败'
        };
      }
    } catch (error) {
      return {
        success: false,
        message: `执行异常: ${error.message}`
      };
    } finally {
      await browser.close();
    }
  }

  async checkAndSchedule() {
    const db = new Database();
    await db.init();
    
    const accounts = await db.query('SELECT * FROM accounts WHERE enabled = 1');
    
    for (const account of accounts) {
      const task = this.tasks.get(account.id);
      if (!task) {
        await this.scheduleAccount(account);
      }
    }
  }

  async manualExecute(accountId) {
    return this.execute(accountId);
  }
}

// ============================================================================
// Express 应用
// ============================================================================
const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// CORS
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Headers', 'Authorization, Content-Type');
  res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  if (req.method === 'OPTIONS') {
    res.sendStatus(200);
  } else {
    next();
  }
});

// JWT 验证中间件
function authenticate(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  
  if (!token) {
    return res.status(401).json({ error: '未提供token' });
  }

  try {
    const decoded = jwt.verify(token, CONFIG.jwtSecret);
    req.user = decoded.username;
    next();
  } catch (error) {
    return res.status(401).json({ error: '无效的token' });
  }
}

// ============================================================================
// API 路由
// ============================================================================

// 登录
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;

  if (username === CONFIG.adminUsername && password === CONFIG.adminPassword) {
    const token = jwt.sign({ username }, CONFIG.jwtSecret, { expiresIn: '7d' });
    res.json({ token });
  } else {
    res.status(401).json({ error: '用户名或密码错误' });
  }
});

// 仪表板数据
app.get('/api/dashboard', authenticate, async (req, res) => {
  const db = new Database();
  await db.init();

  try {
    const totalAccounts = await db.query('SELECT COUNT(*) as count FROM accounts');
    const activeAccounts = await db.query('SELECT COUNT(*) as count FROM accounts WHERE enabled = 1');
    const totalHistory = await db.query('SELECT COUNT(*) as count FROM history');
    const successHistory = await db.query('SELECT COUNT(*) as count FROM history WHERE success = 1');
    const todayHistory = await db.query(`
      SELECT h.*, a.name as account_name 
      FROM history h 
      JOIN accounts a ON h.account_id = a.id 
      WHERE DATE(h.created_at) = DATE('now') 
      ORDER BY h.created_at DESC 
      LIMIT 20
    `);

    const total = totalAccounts[0].count;
    const active = activeAccounts[0].count;
    const totalHis = totalHistory[0].count;
    const successHis = successHistory[0].count;
    const rate = totalHis > 0 ? ((successHis / totalHis) * 100).toFixed(2) : 0;

    res.json({
      totalAccounts: total,
      activeAccounts: active,
      successRate: rate,
      todayHistory
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// 获取账号列表
app.get('/api/accounts', authenticate, async (req, res) => {
  const db = new Database();
  await db.init();

  try {
    const accounts = await db.query('SELECT * FROM accounts');
    res.json(accounts);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// 添加账号
app.post('/api/accounts', authenticate, async (req, res) => {
  const db = new Database();
  await db.init();

  try {
    const { name, username, password, cron_expression, interval_minutes, notification } = req.body;
    
    const result = await db.run(
      `INSERT INTO accounts (name, username, password, cron_expression, interval_minutes, 
        notification_enabled, telegram_enabled, telegram_bot_token, telegram_chat_id,
        wechat_enabled, wechat_webhook, wxpusher_enabled, wxpusher_app_token, wxpusher_uid,
        dingtalk_enabled, dingtalk_webhook, dingtalk_secret) 
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        name, username, password, cron_expression, interval_minutes,
        notification?.enabled, notification?.telegram?.enabled, notification?.telegram?.botToken, notification?.telegram?.chatId,
        notification?.wechat?.enabled, notification?.wechat?.webhook,
        notification?.wxpusher?.enabled, notification?.wxpusher?.appToken, notification?.wxpusher?.uid,
        notification?.dingtalk?.enabled, notification?.dingtalk?.webhook, notification?.dingtalk?.secret
      ]
    );

    const accountId = result.insertId || result.lastID;
    
    // 立即调度
    const service = new KeepAliveService();
    await service.scheduleAccount({ id: accountId, ...req.body });

    res.json({ id: accountId, message: '账号添加成功' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// 更新账号
app.put('/api/accounts/:id', authenticate, async (req, res) => {
  const db = new Database();
  await db.init();

  try {
    const { id } = req.params;
    const { name, username, password, enabled, cron_expression, interval_minutes, notification } = req.body;

    await db.run(
      `UPDATE accounts SET 
        name = ?, username = ?, password = ?, enabled = ?, 
        cron_expression = ?, interval_minutes = ?,
        notification_enabled = ?, telegram_enabled = ?, telegram_bot_token = ?, telegram_chat_id = ?,
        wechat_enabled = ?, wechat_webhook = ?, wxpusher_enabled = ?, wxpusher_app_token = ?, wxpusher_uid = ?,
        dingtalk_enabled = ?, dingtalk_webhook = ?, dingtalk_secret = ?
      WHERE id = ?`,
      [
        name, username, password, enabled, cron_expression, interval_minutes,
        notification?.enabled, notification?.telegram?.enabled, notification?.telegram?.botToken, notification?.telegram?.chatId,
        notification?.wechat?.enabled, notification?.wechat?.webhook,
        notification?.wxpusher?.enabled, notification?.wxpusher?.appToken, notification?.wxpusher?.uid,
        notification?.dingtalk?.enabled, notification?.dingtalk?.webhook, notification?.dingtalk?.secret,
        id
      ]
    );

    res.json({ message: '账号更新成功' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// 删除账号
app.delete('/api/accounts/:id', authenticate, async (req, res) => {
  const db = new Database();
  await db.init();

  try {
    const { id } = req.params;
    await db.run('DELETE FROM accounts WHERE id = ?', [id]);
    res.json({ message: '账号删除成功' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// 手动执行保活
app.post('/api/accounts/:id/keepalive', authenticate, async (req, res) => {
  const service = new KeepAliveService();
  try {
    await service.manualExecute(req.params.id);
    res.json({ message: '保活任务已触发' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// 获取系统设置
app.get('/api/settings', authenticate, async (req, res) => {
  const db = new Database();
  await db.init();

  try {
    const settings = await db.query('SELECT * FROM settings WHERE id = 1');
    res.json(settings[0] || {});
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// 更新系统设置
app.put('/api/settings', authenticate, async (req, res) => {
  const db = new Database();
  await db.init();

  try {
    const { notification_proxy, browser_headless, browser_timeout } = req.body;
    
    await db.run(
      `UPDATE settings SET 
        notification_proxy = ?, browser_headless = ?, browser_timeout = ? 
      WHERE id = 1`,
      [notification_proxy, browser_headless, browser_timeout]
    );

    res.json({ message: '设置更新成功' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// 发送测试通知
app.post('/api/test-notification', authenticate, async (req, res) => {
  const db = new Database();
  await db.init();

  try {
    // 使用第一个账号的通知配置
    const accounts = await db.query('SELECT * FROM accounts WHERE enabled = 1 LIMIT 1');
    if (!accounts[0]) {
      return res.status(400).json({ error: '没有可用的账号配置' });
    }

    await NotificationService.send(accounts[0], '测试通知', '这是一条测试消息');
    res.json({ message: '测试通知已发送' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ============================================================================
// 前端界面
// ============================================================================
const HTML_TEMPLATE = `
<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Netlib 保活控制面板</title>
  <style>
    :root {
      --primary: #667eea;
      --success: #48bb78;
      --danger: #f56565;
      --warning: #ed8936;
      --bg: #f7fafc;
      --card: #ffffff;
      --text: #2d3748;
      --border: #e2e8f0;
    }
    
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: var(--bg); color: var(--text); }
    
    .login-container { min-height: 100vh; display: flex; align-items: center; justify-content: center; background: linear-gradient(135deg, var(--primary), #764ba2); }
    .login-box { background: white; padding: 40px; border-radius: 12px; box-shadow: 0 10px 25px rgba(0,0,0,0.1); width: 90%; max-width: 400px; }
    .login-box h2 { margin-bottom: 24px; text-align: center; }
    .form-group { margin-bottom: 16px; }
    .form-group label { display: block; margin-bottom: 6px; font-size: 14px; }
    .form-group input { width: 100%; padding: 12px; border: 1px solid var(--border); border-radius: 6px; font-size: 14px; }
    .form-group select { width: 100%; padding: 12px; border: 1px solid var(--border); border-radius: 6px; font-size: 14px; }
    .btn { padding: 12px 24px; border: none; border-radius: 6px; font-size: 14px; cursor: pointer; transition: all 0.2s; }
    .btn-primary { background: var(--primary); color: white; }
    .btn:hover { opacity: 0.9; }
    .btn:disabled { opacity: 0.5; cursor: not-allowed; }
    
    .dashboard { display: none; padding: 20px; }
    .header { background: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; display: flex; justify-content: space-between; align-items: center; }
    .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px; margin-bottom: 24px; }
    .stat-card { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.05); }
    .stat-card h3 { font-size: 14px; color: #718096; margin-bottom: 8px; }
    .stat-card .value { font-size: 28px; font-weight: bold; color: var(--primary); }
    
    .section { background: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; }
    .section-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px; }
    .table { width: 100%; border-collapse: collapse; }
    .table th, .table td { padding: 12px; text-align: left; border-bottom: 1px solid var(--border); }
    .table th { font-weight: 600; font-size: 12px; text-transform: uppercase; color: #718096; }
    
    .modal { display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.5); align-items: center; justify-content: center; }
    .modal.show { display: flex; }
    .modal-content { background: white; padding: 24px; border-radius: 8px; width: 90%; max-width: 600px; max-height: 90vh; overflow-y: auto; }
    
    .switch { position: relative; display: inline-block; width: 48px; height: 24px; }
    .switch input { opacity: 0; width: 0; height: 0; }
    .slider { position: absolute; cursor: pointer; top: 0; left: 0; right: 0; bottom: 0; background-color: #ccc; transition: .4s; border-radius: 24px; }
    .slider:before { position: absolute; content: ""; height: 16px; width: 16px; left: 4px; bottom: 4px; background-color: white; transition: .4s; border-radius: 50%; }
    input:checked + .slider { background-color: var(--primary); }
    input:checked + .slider:before { transform: translateX(24px); }
    
    .notification-channel { border: 1px solid var(--border); padding: 16px; border-radius: 8px; margin-bottom: 12px; }
    .channel-header { display: flex; align-items: center; gap: 8px; margin-bottom: 12px; }
    
    .toast { position: fixed; bottom: 20px; right: 20px; background: white; padding: 16px 20px; border-radius: 8px; box-shadow: 0 4px 12px rgba(0,0,0,0.15); display: none; align-items: center; gap: 12px; }
    .toast.show { display: flex; }
    .toast.success { border-left: 4px solid var(--success); }
    .toast.error { border-left: 4px solid var(--danger); }
  </style>
</head>
<body>
  <div class="login-container" id="loginContainer">
    <div class="login-box">
      <h2>🔐 管理员登录</h2>
      <form id="loginForm">
        <div class="form-group">
          <label>用户名</label>
          <input type="text" id="username" required>
        </div>
        <div class="form-group">
          <label>密码</label>
          <input type="password" id="password" required>
        </div>
        <button type="submit" class="btn btn-primary" style="width: 100%;">登录</button>
      </form>
    </div>
  </div>

  <div class="dashboard" id="dashboard">
    <div class="header">
      <h1>Netlib 保活控制面板</h1>
      <button class="btn btn-danger" onclick="logout()">退出</button>
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
        <h3>成功率</h3>
        <div class="value" id="successRate">0%</div>
      </div>
      <div class="stat-card">
        <h3>今日执行</h3>
        <div class="value" id="todayCount">0</div>
      </div>
    </div>

    <div class="section">
      <div class="section-header">
        <h2>账号管理</h2>
        <button class="btn btn-primary" onclick="showAddModal()">添加账号</button>
      </div>
      <table class="table" id="accountsTable">
        <thead>
          <tr>
            <th>名称</th>
            <th>用户名</th>
            <th>状态</th>
            <th>执行方式</th>
            <th>上次运行</th>
            <th>操作</th>
          </tr>
        </thead>
        <tbody id="accountsBody">\${/* 数据将通过JS动态加载 */}</tbody>
      </table>
    </div>

    <div class="section">
      <h2>今日执行记录</h2>
      <table class="table" id="historyTable">
        <thead>
          <tr>
            <th>账号</th>
            <th>状态</th>
            <th>消息</th>
            <th>时间</th>
          </tr>
        </thead>
        <tbody id="historyBody">\${/* 数据将通过JS动态加载 */}</tbody>
      </table>
    </div>
  </div>

  <!-- 添加账号模态框 -->
  <div class="modal" id="addModal">
    <div class="modal-content">
      <h2>添加账号</h2>
      <form id="addForm">
        <div class="form-group">
          <label>账号名称</label>
          <input type="text" id="addName" required>
        </div>
        <div class="form-group">
          <label>用户名</label>
          <input type="text" id="addUsername" required>
        </div>
        <div class="form-group">
          <label>密码</label>
          <input type="password" id="addPassword" required>
        </div>
        <div class="form-group">
          <label>执行方式</label>
          <select id="addScheduleType">
            <option value="interval">时间间隔</option>
            <option value="cron">Cron 表达式</option>
          </select>
        </div>
        <div class="form-group" id="intervalGroup">
          <label>间隔分钟数</label>
          <input type="number" id="addInterval" value="60" min="30">
        </div>
        <div class="form-group" id="cronGroup" style="display:none;">
          <label>Cron 表达式</label>
          <input type="text" id="addCron" value="0 */12 * * *">
        </div>
        
        <!-- 通知设置 -->
        <h3 style="margin: 20px 0 10px;">通知设置</h3>
        <div class="notification-channel">
          <div class="channel-header">
            <label class="switch">
              <input type="checkbox" id="enableNotify" onchange="toggleNotify(this)">
              <span class="slider"></span>
            </label>
            <strong>启用通知</strong>
          </div>
          
          <div id="notifyChannels" style="display:none;">
            <!-- Telegram -->
            <div class="notification-channel">
              <div class="channel-header">
                <label class="switch">
                  <input type="checkbox" id="enableTelegram">
                  <span class="slider"></span>
                </label>
                <strong>Telegram</strong>
              </div>
              <div class="form-group">
                <label>Bot Token</label>
                <input type="text" id="tgToken">
              </div>
              <div class="form-group">
                <label>Chat ID</label>
                <input type="text" id="tgChat">
              </div>
            </div>

            <!-- 企业微信 -->
            <div class="notification-channel">
              <div class="channel-header">
                <label class="switch">
                  <input type="checkbox" id="enableWechat">
                  <span class="slider"></span>
                </label>
                <strong>企业微信</strong>
              </div>
              <div class="form-group">
                <label>Webhook</label>
                <input type="text" id="wechatWebhook">
              </div>
            </div>

            <!-- WxPusher -->
            <div class="notification-channel">
              <div class="channel-header">
                <label class="switch">
                  <input type="checkbox" id="enableWxPusher">
                  <span class="slider"></span>
                </label>
                <strong>WxPusher</strong>
              </div>
              <div class="form-group">
                <label>App Token</label>
                <input type="text" id="wxToken">
              </div>
              <div class="form-group">
                <label>UID</label>
                <input type="text" id="wxUid">
              </div>
            </div>

            <!-- 钉钉 -->
            <div class="notification-channel">
              <div class="channel-header">
                <label class="switch">
                  <input type="checkbox" id="enableDingTalk">
                  <span class="slider"></span>
                </label>
                <strong>钉钉</strong>
              </div>
              <div class="form-group">
                <label>Webhook</label>
                <input type="text" id="dingWebhook">
              </div>
              <div class="form-group">
                <label>Secret (可选)</label>
                <input type="text" id="dingSecret">
              </div>
            </div>
          </div>
        </div>

        <div style="display:flex; gap: 10px; margin-top: 20px;">
          <button type="submit" class="btn btn-primary" style="flex:1;">保存</button>
          <button type="button" class="btn" onclick="closeModal('addModal')">取消</button>
        </div>
      </form>
    </div>
  </div>

  <div class="toast" id="toast"></div>

  <script>
    let token = localStorage.getItem('token');
    const API = axios.create({ baseURL: '/api' });
    
    API.interceptors.request.use(config => {
      if (token) config.headers.Authorization = 'Bearer ' + token;
      return config;
    });

    API.interceptors.response.use(
      response => response,
      error => {
        if (error.response?.status === 401) {
          logout();
        }
        return Promise.reject(error);
      }
    );

    // 登录
    document.getElementById('loginForm').onsubmit = async (e) => {
      e.preventDefault();
      try {
        const res = await API.post('/login', {
          username: document.getElementById('username').value,
          password: document.getElementById('password').value
        });
        token = res.data.token;
        localStorage.setItem('token', token);
        document.getElementById('loginContainer').style.display = 'none';
        document.getElementById('dashboard').style.display = 'block';
        loadDashboard();
        loadAccounts();
      } catch (err) {
        alert('登录失败: ' + err.response?.data?.error);
      }
    };

    function logout() {
      token = null;
      localStorage.removeItem('token');
      location.reload();
    }

    async function loadDashboard() {
      try {
        const res = await API.get('/dashboard');
        const data = res.data;
        document.getElementById('totalAccounts').textContent = data.totalAccounts;
        document.getElementById('activeAccounts').textContent = data.activeAccounts;
        document.getElementById('successRate').textContent = data.successRate + '%';
        document.getElementById('todayCount').textContent = data.todayHistory?.length || 0;
        
        // 填充历史记录
        const tbody = document.getElementById('historyBody');
        tbody.innerHTML = data.todayHistory?.map(h => \`
          <tr>
            <td>\${h.account_name}</td>
            <td><span style="color:\${h.success?'var(--success)':'var(--danger)'}">\${h.success?'成功':'失败'}</span></td>
            <td>\${h.message}</td>
            <td>\${new Date(h.created_at).toLocaleString()}</td>
          </tr>
        \`).join('') || '<tr><td colspan="4">暂无记录</td></tr>';
      } catch (err) {
        console.error('加载仪表板失败:', err);
      }
    }

    async function loadAccounts() {
      try {
        const res = await API.get('/accounts');
        const tbody = document.getElementById('accountsBody');
        tbody.innerHTML = res.data.map(a => \`
          <tr>
            <td>\${a.name}</td>
            <td>\${a.username}</td>
            <td><span style="color:\${a.enabled?'var(--success)':'var(--danger)'}">\${a.enabled?'启用':'禁用'}</span></td>
            <td>\${a.cron_expression || '每' + (a.interval_minutes || 60) + '分钟'}</td>
            <td>\${a.last_keepalive ? new Date(a.last_keepalive).toLocaleString() : '从未运行'}</td>
            <td>
              <button class="btn btn-primary btn-sm" onclick="manualKeepalive(\${a.id})">立即执行</button>
              <button class="btn btn-warning btn-sm" onclick="editAccount(\${a.id})">编辑</button>
              <button class="btn btn-danger btn-sm" onclick="deleteAccount(\${a.id})">删除</button>
            </td>
          </tr>
        \`).join('');
      } catch (err) {
        console.error('加载账号失败:', err);
      }
    }

    function showAddModal() {
      document.getElementById('addModal').classList.add('show');
    }

    function closeModal(id) {
      document.getElementById(id).classList.remove('show');
    }

    // 切换通知设置显示
    function toggleNotify(checkbox) {
      document.getElementById('notifyChannels').style.display = checkbox.checked ? 'block' : 'none';
    }

    // 切换计划方式
    document.getElementById('addScheduleType').onchange = (e) => {
      document.getElementById('intervalGroup').style.display = e.target.value === 'interval' ? 'block' : 'none';
      document.getElementById('cronGroup').style.display = e.target.value === 'cron' ? 'block' : 'none';
    };

    // 添加账号
    document.getElementById('addForm').onsubmit = async (e) => {
      e.preventDefault();
      try {
        const notification = {
          enabled: document.getElementById('enableNotify').checked,
          telegram: {
            enabled: document.getElementById('enableTelegram').checked,
            botToken: document.getElementById('tgToken').value,
            chatId: document.getElementById('tgChat').value
          },
          wechat: {
            enabled: document.getElementById('enableWechat').checked,
            webhook: document.getElementById('wechatWebhook').value
          },
          wxpusher: {
            enabled: document.getElementById('enableWxPusher').checked,
            appToken: document.getElementById('wxToken').value,
            uid: document.getElementById('wxUid').value
          },
          dingtalk: {
            enabled: document.getElementById('enableDingTalk').checked,
            webhook: document.getElementById('dingWebhook').value,
            secret: document.getElementById('dingSecret').value
          }
        };

        const data = {
          name: document.getElementById('addName').value,
          username: document.getElementById('addUsername').value,
          password: document.getElementById('addPassword').value,
          cron_expression: document.getElementById('addScheduleType').value === 'cron' ? document.getElementById('addCron').value : null,
          interval_minutes: document.getElementById('addScheduleType').value === 'interval' ? parseInt(document.getElementById('addInterval').value) : null,
          notification
        };

        await API.post('/accounts', data);
        showToast('账号添加成功', 'success');
        closeModal('addModal');
        loadAccounts();
      } catch (err) {
        showToast('添加失败: ' + err.response?.data?.error, 'error');
      }
    };

    async function manualKeepalive(id) {
      if (confirm('确定立即执行保活吗？')) {
        try {
          await API.post('/accounts/' + id + '/keepalive');
          showToast('保活任务已触发', 'success');
        } catch (err) {
          showToast('执行失败: ' + err.response?.data?.error, 'error');
        }
      }
    }

    async function deleteAccount(id) {
      if (confirm('确定删除该账号吗？')) {
        try {
          await API.delete('/accounts/' + id);
          showToast('账号删除成功', 'success');
          loadAccounts();
        } catch (err) {
          showToast('删除失败: ' + err.response?.data?.error, 'error');
        }
      }
    }

    function showToast(message, type = 'info') {
      const toast = document.getElementById('toast');
      toast.textContent = message;
      toast.className = 'toast show ' + type;
      setTimeout(() => toast.classList.remove('show'), 3000);
    }

    // 初始化
    if (token) {
      document.getElementById('loginContainer').style.display = 'none';
      document.getElementById('dashboard').style.display = 'block';
      loadDashboard();
      loadAccounts();
      setInterval(loadDashboard, 30000); // 每30秒刷新
    }
  </script>
</body>
</html>
`;

// ============================================================================
// 其他路由
// ============================================================================

// 健康检查
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok' });
});

// 获取账号详情（用于编辑）
app.get('/api/accounts/:id', authenticate, async (req, res) => {
  const db = new Database();
  await db.init();

  try {
    const account = await db.query('SELECT * FROM accounts WHERE id = ?', [req.params.id]);
    if (account[0]) {
      res.json(account[0]);
    } else {
      res.status(404).json({ error: '账号不存在' });
    }
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// 首页
app.get('/', (req, res) => {
  res.send(HTML_TEMPLATE);
});

// ============================================================================
// 启动服务
// ============================================================================
async function start() {
  const db = new Database();
  await db.init();

  const service = new KeepAliveService();
  service.start();

  app.listen(CONFIG.port, () => {
    console.log(`🚀 控制面板启动: http://localhost:${CONFIG.port}`);
    console.log(`📊 管理员账号: ${CONFIG.adminUsername}`);
    console.log(`🔑 管理员密码: ${CONFIG.adminPassword}`);
  });
}

start().catch(console.error);
