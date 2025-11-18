const express = require('express');
const cookieParser = require('cookie-parser');
const bodyParser = require('body-parser');
const { chromium } = require('playwright');
const axios = require('axios');
const crypto = require('crypto');
const cron = require('node-cron');
const mysql = require('mysql2/promise');
const sqlite3 = require('sqlite3').verbose();
const { promisify } = require('util');

const app = express();
const PORT = process.env.PORT || 3000;

// 环境变量配置
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || 'admin';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'admin123';
const MYSQL_DNS = process.env.MYSQL_DNS;
const MYSQL_MAX_RETRY = parseInt(process.env.MYSQL_MAX_RETRY || '20');
const SESSION_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');
const TIMEZONE = process.env.TIMEZONE || 'Asia/Shanghai';
const DEBUG = process.env.DEBUG !== 'false'; // 默认开启

// 调试日志函数
function debugLog(...args) {
  if (DEBUG) {
    console.log(`[DEBUG ${new Date().toLocaleString('zh-CN', { timeZone: TIMEZONE })}]`, ...args);
  }
}

// 数据库连接
let db;
let dbType = 'sqlite';
let dbPool; // MySQL 连接池
let retryCount = 0; // 当前重试次数

// 解析 MySQL DNS
function parseMySQLDNS(dns) {
  const regex = /mysql:\/\/([^:]+):([^@]+)@([^:]+):(\d+)\/([^?]+)(\?.*)?/;
  const match = dns.match(regex);
  
  if (!match) {
    throw new Error('Invalid MySQL DNS format');
  }
  
  const [, user, password, host, port, database, query] = match;
  const useSSL = query && query.includes('ssl=true');
  
  return {
    host,
    port: parseInt(port),
    user,
    password,
    database,
    ssl: useSSL ? { rejectUnauthorized: false } : undefined,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0,
    enableKeepAlive: true,
    keepAliveInitialDelay: 0
  };
}

// 指数退避重试连接
async function connectWithRetry(config, maxRetries = MYSQL_MAX_RETRY) {
  for (let i = 0; i < maxRetries; i++) {
    try {
      debugLog(`尝试连接 MySQL (${i + 1}/${maxRetries})...`);
      const pool = mysql.createPool(config);
      await pool.query('SELECT 1');
      retryCount = 0; // 重置重试次数
      console.log(`✅ MySQL 连接成功 (尝试 ${i + 1}/${maxRetries})`);
      return pool;
    } catch (error) {
      const waitTime = Math.min(1000 * Math.pow(2, i), 30000);
      console.log(`⚠️ MySQL 连接失败 (尝试 ${i + 1}/${maxRetries}), ${waitTime}ms 后重试...`);
      console.log(`   错误信息: ${error.message}`);
      debugLog('   详细错误:', error);
      
      if (i === maxRetries - 1) {
        throw new Error(`MySQL 连接失败,已重试 ${maxRetries} 次: ${error.message}`);
      }
      
      await new Promise(resolve => setTimeout(resolve, waitTime));
    }
  }
}

// 数据库操作包装函数 - 带重试逻辑
async function executeWithRetry(operation, operationName = '数据库操作') {
  let lastError;
  
  for (let i = 0; i < MYSQL_MAX_RETRY; i++) {
    try {
      debugLog(`执行${operationName} (尝试 ${i + 1}/${MYSQL_MAX_RETRY})`);
      const result = await operation();
      
      if (i > 0) {
        console.log(`✅ ${operationName}成功 (尝试 ${i + 1}/${MYSQL_MAX_RETRY})`);
        retryCount = 0; // 重置重试次数
      }
      
      return result;
    } catch (error) {
      lastError = error;
      const isConnectionError = error.code === 'ECONNRESET' || 
                               error.code === 'PROTOCOL_CONNECTION_LOST' ||
                               error.code === 'ECONNREFUSED' ||
                               error.errno === 'ETIMEDOUT';
      
      if (!isConnectionError) {
        // 非连接错误,直接抛出
        debugLog(`${operationName}遇到非连接错误:`, error.message);
        throw error;
      }
      
      const waitTime = Math.min(1000 * Math.pow(2, i), 30000);
      console.log(`⚠️ ${operationName}失败 (尝试 ${i + 1}/${MYSQL_MAX_RETRY}): ${error.message}`);
      debugLog('   错误详情:', error);
      
      if (i < MYSQL_MAX_RETRY - 1) {
        console.log(`   ${waitTime}ms 后重试...`);
        
        // 如果是 MySQL,尝试重新建立连接池
        if (dbType === 'mysql' && dbPool) {
          try {
            debugLog('尝试重新建立 MySQL 连接池...');
            await dbPool.end();
            const config = parseMySQLDNS(MYSQL_DNS);
            dbPool = await connectWithRetry(config, 3); // 使用较少的重试次数
            db = dbPool;
          } catch (reconnectError) {
            debugLog('重新连接失败:', reconnectError.message);
          }
        }
        
        await new Promise(resolve => setTimeout(resolve, waitTime));
      }
    }
  }
  
  throw new Error(`${operationName}失败,已重试 ${MYSQL_MAX_RETRY} 次: ${lastError.message}`);
}

// 初始化数据库
async function initDatabase() {
  if (MYSQL_DNS) {
    try {
      dbType = 'mysql';
      const config = parseMySQLDNS(MYSQL_DNS);
      console.log(`🔄 正在连接 MySQL: ${config.host}:${config.port}/${config.database}`);
      console.log(`   最大重试次数: ${MYSQL_MAX_RETRY}`);
      console.log(`   时区设置: ${TIMEZONE}`);
      debugLog('MySQL 配置:', { ...config, password: '***' });
      
      dbPool = await connectWithRetry(config);
      db = dbPool;
      
      // 创建表
      await executeWithRetry(async () => {
        await db.query(`
          CREATE TABLE IF NOT EXISTS accounts (
            id INT AUTO_INCREMENT PRIMARY KEY,
            username VARCHAR(255) NOT NULL UNIQUE,
            password VARCHAR(255) NOT NULL,
            enabled BOOLEAN DEFAULT true,
            cron_expression VARCHAR(100) DEFAULT '0 0 1 * *',
            last_keepalive DATETIME,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
          )
        `);
      }, '创建 accounts 表');
      
      await executeWithRetry(async () => {
        await db.query(`
          CREATE TABLE IF NOT EXISTS keepalive_logs (
            id INT AUTO_INCREMENT PRIMARY KEY,
            account_id INT NOT NULL,
            username VARCHAR(255) NOT NULL,
            success BOOLEAN NOT NULL,
            message TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            INDEX idx_account_id (account_id),
            INDEX idx_created_at (created_at)
          )
        `);
      }, '创建 keepalive_logs 表');
      
      await executeWithRetry(async () => {
        await db.query(`
          CREATE TABLE IF NOT EXISTS notification_channels (
            id INT AUTO_INCREMENT PRIMARY KEY,
            name VARCHAR(50) NOT NULL UNIQUE,
            type VARCHAR(50) NOT NULL,
            enabled BOOLEAN DEFAULT true,
            config JSON NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
          )
        `);
      }, '创建 notification_channels 表');
      
      await executeWithRetry(async () => {
        await db.query(`
          CREATE TABLE IF NOT EXISTS system_settings (
            key_name VARCHAR(100) PRIMARY KEY,
            value TEXT,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
          )
        `);
      }, '创建 system_settings 表');
      
      console.log('✅ MySQL 表初始化完成');
      
    } catch (error) {
      console.error('❌ MySQL 初始化失败:', error.message);
      debugLog('MySQL 初始化详细错误:', error);
      console.log('🔄 降级使用 SQLite');
      dbType = 'sqlite';
    }
  }
  
  if (dbType === 'sqlite') {
    db = new sqlite3.Database('./data/netlib.db');
    const run = promisify(db.run.bind(db));
    
    await run(`
      CREATE TABLE IF NOT EXISTS accounts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        password TEXT NOT NULL,
        enabled INTEGER DEFAULT 1,
        cron_expression TEXT DEFAULT '0 0 1 * *',
        last_keepalive DATETIME,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
      )
    `);
    
    await run(`
      CREATE TABLE IF NOT EXISTS keepalive_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        account_id INTEGER NOT NULL,
        username TEXT NOT NULL,
        success INTEGER NOT NULL,
        message TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
      )
    `);
    
    await run(`
      CREATE TABLE IF NOT EXISTS notification_channels (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL UNIQUE,
        type TEXT NOT NULL,
        enabled INTEGER DEFAULT 1,
        config TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
      )
    `);
    
    await run(`
      CREATE TABLE IF NOT EXISTS system_settings (
        key_name TEXT PRIMARY KEY,
        value TEXT,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
      )
    `);
    
    console.log('✅ SQLite 初始化成功');
    console.log(`   时区设置: ${TIMEZONE}`);
  }
}

// 数据库查询封装
async function query(sql, params = []) {
  return await executeWithRetry(async () => {
    if (dbType === 'mysql') {
      const [rows] = await db.query(sql, params);
      return rows;
    } else {
      const all = promisify(db.all.bind(db));
      return await all(sql, params);
    }
  }, `查询: ${sql.substring(0, 50)}...`);
}

async function execute(sql, params = []) {
  return await executeWithRetry(async () => {
    if (dbType === 'mysql') {
      const [result] = await db.query(sql, params);
      return result;
    } else {
      const run = promisify(db.run.bind(db));
      return await run(sql, params);
    }
  }, `执行: ${sql.substring(0, 50)}...`);
}

// 获取当前时间 (使用配置的时区)
function getCurrentTime() {
  return new Date().toLocaleString('zh-CN', { timeZone: TIMEZONE });
}

// 中间件
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(express.static('public'));

// 生成会话令牌
function generateToken(username) {
  const payload = {
    username,
    exp: Date.now() + 7 * 24 * 60 * 60 * 1000 // 7天
  };
  const token = crypto.createHmac('sha256', SESSION_SECRET)
    .update(JSON.stringify(payload))
    .digest('hex');
  return `${Buffer.from(JSON.stringify(payload)).toString('base64')}.${token}`;
}

// 验证会话令牌
function verifyToken(token) {
  try {
    const [payloadBase64, signature] = token.split('.');
    const payload = JSON.parse(Buffer.from(payloadBase64, 'base64').toString());
    
    const expectedSignature = crypto.createHmac('sha256', SESSION_SECRET)
      .update(JSON.stringify(payload))
      .digest('hex');
    
    if (signature !== expectedSignature) {
      return null;
    }
    
    if (Date.now() > payload.exp) {
      return null;
    }
    
    return payload;
  } catch {
    return null;
  }
}

// 认证中间件
function requireAuth(req, res, next) {
  const token = req.cookies.auth_token;
  
  if (!token) {
    return res.status(401).json({ error: '未登录' });
  }
  
  const payload = verifyToken(token);
  if (!payload) {
    return res.status(401).json({ error: '登录已过期' });
  }
  
  req.user = payload;
  next();
}

// 登录 API
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  debugLog('登录尝试:', { username });
  
  if (username === ADMIN_USERNAME && password === ADMIN_PASSWORD) {
    const token = generateToken(username);
    res.cookie('auth_token', token, {
      httpOnly: true,
      maxAge: 7 * 24 * 60 * 60 * 1000,
      sameSite: 'strict'
    });
    console.log(`✅ 用户 ${username} 登录成功 - ${getCurrentTime()}`);
    res.json({ success: true });
  } else {
    console.log(`❌ 用户 ${username} 登录失败 - ${getCurrentTime()}`);
    res.status(401).json({ error: '用户名或密码错误' });
  }
});

// 登出 API
app.post('/api/logout', (req, res) => {
  res.clearCookie('auth_token');
  debugLog('用户登出');
  res.json({ success: true });
});

// 检查登录状态
app.get('/api/auth/check', (req, res) => {
  const token = req.cookies.auth_token;
  if (!token) {
    return res.json({ authenticated: false });
  }
  
  const payload = verifyToken(token);
  if (!payload) {
    return res.json({ authenticated: false });
  }
  
  res.json({ authenticated: true, username: payload.username });
});

// 账号管理 API
app.get('/api/accounts', requireAuth, async (req, res) => {
  try {
    debugLog('获取账号列表');
    const accounts = await query('SELECT id, username, enabled, cron_expression, last_keepalive, created_at FROM accounts ORDER BY id DESC');
    res.json(accounts);
  } catch (error) {
    console.error('❌ 获取账号列表失败:', error.message);
    debugLog('详细错误:', error);
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/accounts', requireAuth, async (req, res) => {
  try {
    const { username, password, cron_expression = '0 0 1 * *' } = req.body;
    debugLog('添加账号:', { username, cron_expression });
    
    if (!username || !password) {
      return res.status(400).json({ error: '用户名和密码不能为空' });
    }
    
    const sql = dbType === 'mysql'
      ? 'INSERT INTO accounts (username, password, cron_expression) VALUES (?, ?, ?)'
      : 'INSERT INTO accounts (username, password, cron_expression) VALUES (?, ?, ?)';
    
    await execute(sql, [username, password, cron_expression]);
    
    console.log(`✅ 账号添加成功: ${username} - ${getCurrentTime()}`);
    
    // 重新加载定时任务
    await loadCronJobs();
    
    res.json({ success: true });
  } catch (error) {
    console.error('❌ 添加账号失败:', error.message);
    debugLog('详细错误:', error);
    res.status(500).json({ error: error.message });
  }
});

app.put('/api/accounts/:id', requireAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const { username, password, cron_expression, enabled } = req.body;
    debugLog('更新账号:', { id, username, cron_expression, enabled });
    
    const updates = [];
    const params = [];
    
    if (username) {
      updates.push('username = ?');
      params.push(username);
    }
    if (password) {
      updates.push('password = ?');
      params.push(password);
    }
    if (cron_expression) {
      updates.push('cron_expression = ?');
      params.push(cron_expression);
    }
    if (enabled !== undefined) {
      updates.push('enabled = ?');
      params.push(enabled ? 1 : 0);
    }
    
    if (updates.length === 0) {
      return res.status(400).json({ error: '没有要更新的字段' });
    }
    
    params.push(id);
    const sql = `UPDATE accounts SET ${updates.join(', ')} WHERE id = ?`;
    
    await execute(sql, params);
    
    console.log(`✅ 账号更新成功: ID=${id} - ${getCurrentTime()}`);
    
    // 重新加载定时任务
    await loadCronJobs();
    
    res.json({ success: true });
  } catch (error) {
    console.error('❌ 更新账号失败:', error.message);
    debugLog('详细错误:', error);
    res.status(500).json({ error: error.message });
  }
});

app.delete('/api/accounts/:id', requireAuth, async (req, res) => {
  try {
    const { id } = req.params;
    debugLog('删除账号:', { id });
    
    await execute('DELETE FROM accounts WHERE id = ?', [id]);
    await execute('DELETE FROM keepalive_logs WHERE account_id = ?', [id]);
    
    console.log(`✅ 账号删除成功: ID=${id} - ${getCurrentTime()}`);
    
    // 重新加载定时任务
    await loadCronJobs();
    
    res.json({ success: true });
  } catch (error) {
    console.error('❌ 删除账号失败:', error.message);
    debugLog('详细错误:', error);
    res.status(500).json({ error: error.message });
  }
});

// 保活日志 API
app.get('/api/logs', requireAuth, async (req, res) => {
  try {
    const { limit = 100, offset = 0 } = req.query;
    debugLog('获取日志:', { limit, offset });
    
    const logs = await query(
      'SELECT * FROM keepalive_logs ORDER BY created_at DESC LIMIT ? OFFSET ?',
      [parseInt(limit), parseInt(offset)]
    );
    const [{ total }] = await query('SELECT COUNT(*) as total FROM keepalive_logs');
    res.json({ logs, total });
  } catch (error) {
    console.error('❌ 获取日志失败:', error.message);
    debugLog('详细错误:', error);
    res.status(500).json({ error: error.message });
  }
});

app.delete('/api/logs', requireAuth, async (req, res) => {
  try {
    const { ids } = req.body;
    debugLog('删除日志:', { ids });
    
    if (!ids || !Array.isArray(ids) || ids.length === 0) {
      return res.status(400).json({ error: '请提供要删除的日志ID' });
    }
    
    const placeholders = ids.map(() => '?').join(',');
    await execute(`DELETE FROM keepalive_logs WHERE id IN (${placeholders})`, ids);
    
    console.log(`✅ 删除 ${ids.length} 条日志成功 - ${getCurrentTime()}`);
    res.json({ success: true });
  } catch (error) {
    console.error('❌ 删除日志失败:', error.message);
    debugLog('详细错误:', error);
    res.status(500).json({ error: error.message });
  }
});

// 统计数据 API
app.get('/api/stats', requireAuth, async (req, res) => {
  try {
    debugLog('获取统计数据');
    
    const [{ total_accounts }] = await query('SELECT COUNT(*) as total_accounts FROM accounts');
    const [{ enabled_accounts }] = await query('SELECT COUNT(*) as enabled_accounts FROM accounts WHERE enabled = 1');
    const [{ total_keepalives }] = await query('SELECT COUNT(*) as total_keepalives FROM keepalive_logs');
    const [{ success_keepalives }] = await query('SELECT COUNT(*) as success_keepalives FROM keepalive_logs WHERE success = 1');
    
    // 最近7天的保活记录
    let recentLogs;
    if (dbType === 'mysql') {
      recentLogs = await query(`
        SELECT DATE(created_at) as date, 
               COUNT(*) as total,
               SUM(CASE WHEN success = 1 THEN 1 ELSE 0 END) as success
        FROM keepalive_logs 
        WHERE created_at >= DATE_SUB(NOW(), INTERVAL 7 DAY)
        GROUP BY DATE(created_at)
        ORDER BY date DESC
      `);
    } else {
      recentLogs = await query(`
        SELECT DATE(created_at) as date, 
               COUNT(*) as total,
               SUM(CASE WHEN success = 1 THEN 1 ELSE 0 END) as success
        FROM keepalive_logs 
        WHERE created_at >= datetime('now', '-7 days')
        GROUP BY DATE(created_at)
        ORDER BY date DESC
      `);
    }
    
    res.json({
      total_accounts,
      enabled_accounts,
      total_keepalives,
      success_keepalives,
      success_rate: total_keepalives > 0 ? (success_keepalives / total_keepalives * 100).toFixed(2) : 0,
      recent_logs: recentLogs
    });
  } catch (error) {
    console.error('❌ 获取统计数据失败:', error.message);
    debugLog('详细错误:', error);
    res.status(500).json({ error: error.message });
  }
});

// 通知渠道 API
app.get('/api/notifications', requireAuth, async (req, res) => {
  try {
    debugLog('获取通知渠道列表');
    const channels = await query('SELECT * FROM notification_channels ORDER BY id');
    const result = channels.map(ch => ({
      ...ch,
      config: typeof ch.config === 'string' ? JSON.parse(ch.config) : ch.config
    }));
    res.json(result);
  } catch (error) {
    console.error('❌ 获取通知渠道失败:', error.message);
    debugLog('详细错误:', error);
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/notifications', requireAuth, async (req, res) => {
  try {
    const { name, type, config, enabled = true } = req.body;
    debugLog('添加通知渠道:', { name, type, enabled });
    
    const sql = 'INSERT INTO notification_channels (name, type, config, enabled) VALUES (?, ?, ?, ?)';
    await execute(sql, [name, type, JSON.stringify(config), enabled ? 1 : 0]);
    
    console.log(`✅ 通知渠道添加成功: ${name} - ${getCurrentTime()}`);
    res.json({ success: true });
  } catch (error) {
    console.error('❌ 添加通知渠道失败:', error.message);
    debugLog('详细错误:', error);
    res.status(500).json({ error: error.message });
  }
});

app.put('/api/notifications/:id', requireAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const { name, type, config, enabled } = req.body;
    debugLog('更新通知渠道:', { id, name, type, enabled });
    
    const updates = [];
    const params = [];
    
    if (name) {
      updates.push('name = ?');
      params.push(name);
    }
    if (type) {
      updates.push('type = ?');
      params.push(type);
    }
    if (config) {
      updates.push('config = ?');
      params.push(JSON.stringify(config));
    }
    if (enabled !== undefined) {
      updates.push('enabled = ?');
      params.push(enabled ? 1 : 0);
    }
    
    params.push(id);
    const sql = `UPDATE notification_channels SET ${updates.join(', ')} WHERE id = ?`;
    
    await execute(sql, params);
    console.log(`✅ 通知渠道更新成功: ID=${id} - ${getCurrentTime()}`);
    res.json({ success: true });
  } catch (error) {
    console.error('❌ 更新通知渠道失败:', error.message);
    debugLog('详细错误:', error);
    res.status(500).json({ error: error.message });
  }
});

app.delete('/api/notifications/:id', requireAuth, async (req, res) => {
  try {
    const { id } = req.params;
    debugLog('删除通知渠道:', { id });
    
    await execute('DELETE FROM notification_channels WHERE id = ?', [id]);
    console.log(`✅ 通知渠道删除成功: ID=${id} - ${getCurrentTime()}`);
    res.json({ success: true });
  } catch (error) {
    console.error('❌ 删除通知渠道失败:', error.message);
    debugLog('详细错误:', error);
    res.status(500).json({ error: error.message });
  }
});

// 测试通知
app.post('/api/notifications/:id/test', requireAuth, async (req, res) => {
  try {
    const { id } = req.params;
    debugLog('测试通知渠道:', { id });
    
    const [channel] = await query('SELECT * FROM notification_channels WHERE id = ?', [id]);
    
    if (!channel) {
      return res.status(404).json({ error: '通知渠道不存在' });
    }
    
    const config = typeof channel.config === 'string' ? JSON.parse(channel.config) : channel.config;
    const result = await sendNotification(channel.type, config, '测试通知', '这是来自 Netlib 保活系统的测试通知。如果您收到此消息,说明您的通知设置正常工作!');
    
    console.log(`${result.success ? '✅' : '❌'} 测试通知发送${result.success ? '成功' : '失败'}: ${channel.name} - ${getCurrentTime()}`);
    res.json({ success: result.success, message: result.message });
  } catch (error) {
    console.error('❌ 测试通知失败:', error.message);
    debugLog('详细错误:', error);
    res.status(500).json({ error: error.message });
  }
});

// 手动执行保活
app.post('/api/keepalive/:id', requireAuth, async (req, res) => {
  try {
    const { id } = req.params;
    debugLog('手动执行保活:', { id });
    
    const [account] = await query('SELECT * FROM accounts WHERE id = ?', [id]);
    
    if (!account) {
      return res.status(404).json({ error: '账号不存在' });
    }
    
    const result = await performKeepalive(account);
    res.json(result);
  } catch (error) {
    console.error('❌ 手动保活失败:', error.message);
    debugLog('详细错误:', error);
    res.status(500).json({ error: error.message });
  }
});

// 保活逻辑
async function performKeepalive(account) {
  console.log(`\n🚀 开始保活账号: ${account.username} - ${getCurrentTime()}`);
  debugLog('账号信息:', { id: account.id, username: account.username, cron: account.cron_expression });
  
  const browser = await chromium.launch({ 
    headless: true,
    args: [
      '--no-sandbox',
      '--disable-setuid-sandbox', 
      '--disable-dev-shm-usage',
      '--disable-gpu',
      '--disable-web-security'
    ]
  });

  let page;
  let result = { success: false, message: '' };
  
  try {
    page = await browser.newPage();
    page.setDefaultTimeout(30000);
    
    console.log(`📱 ${account.username} - 正在访问网站...`);
    await page.goto('https://www.netlib.re/', { waitUntil: 'networkidle' });
    await page.waitForTimeout(3000);
    debugLog(`${account.username} - 网站加载完成`);
    
    console.log(`🔑 ${account.username} - 点击登录按钮...`);
    await page.click('text=Login', { timeout: 5000 });
    await page.waitForTimeout(2000);
    
    console.log(`📝 ${account.username} - 填写用户名...`);
    await page.fill('input[name="username"], input[type="text"]', account.username);
    await page.waitForTimeout(1000);
    
    console.log(`🔒 ${account.username} - 填写密码...`);
    await page.fill('input[name="password"], input[type="password"]', account.password);
    await page.waitForTimeout(1000);
    
    console.log(`📤 ${account.username} - 提交登录...`);
    await page.click('button:has-text("Validate"), input[type="submit"]');
    
    await page.waitForLoadState('networkidle');
    await page.waitForTimeout(5000);
    
    const pageContent = await page.content();
    debugLog(`${account.username} - 页面内容长度: ${pageContent.length}`);
    
    if (pageContent.includes('exclusive owner') || pageContent.includes(account.username)) {
      console.log(`✅ ${account.username} - 保活成功 - ${getCurrentTime()}`);
      result.success = true;
      result.message = `✅ ${account.username} 保活成功`;
    } else {
      console.log(`❌ ${account.username} - 保活失败 - ${getCurrentTime()}`);
      result.message = `❌ ${account.username} 保活失败`;
      debugLog(`${account.username} - 页面未包含预期内容`);
    }
    
  } catch (e) {
    console.log(`❌ ${account.username} - 保活异常: ${e.message} - ${getCurrentTime()}`);
    debugLog(`${account.username} - 详细异常:`, e);
    result.message = `❌ ${account.username} 保活异常: ${e.message}`;
  } finally {
    if (page) await page.close();
    await browser.close();
    debugLog(`${account.username} - 浏览器已关闭`);
  }
  
  // 记录日志 - 使用重试逻辑
  try {
    await execute(
      'INSERT INTO keepalive_logs (account_id, username, success, message) VALUES (?, ?, ?, ?)',
      [account.id, account.username, result.success ? 1 : 0, result.message]
    );
    debugLog(`${account.username} - 日志记录成功`);
  } catch (error) {
    console.error(`❌ ${account.username} - 记录日志失败:`, error.message);
    debugLog('详细错误:', error);
  }
  
  // 更新最后保活时间 - 使用重试逻辑
  try {
    const updateSql = dbType === 'mysql' 
      ? 'UPDATE accounts SET last_keepalive = NOW() WHERE id = ?'
      : 'UPDATE accounts SET last_keepalive = datetime("now") WHERE id = ?';
    await execute(updateSql, [account.id]);
    debugLog(`${account.username} - 更新保活时间成功`);
  } catch (error) {
    console.error(`❌ ${account.username} - 更新保活时间失败:`, error.message);
    debugLog('详细错误:', error);
  }
  
  // 发送通知
  try {
    await sendNotifications(result.message);
    debugLog(`${account.username} - 通知发送完成`);
  } catch (error) {
    console.error(`❌ ${account.username} - 发送通知失败:`, error.message);
    debugLog('详细错误:', error);
  }
  
  return result;
}

// 发送通知到所有启用的渠道
async function sendNotifications(message) {
  try {
    const channels = await query('SELECT * FROM notification_channels WHERE enabled = 1');
    debugLog(`发送通知到 ${channels.length} 个渠道`);
    
    for (const channel of channels) {
      try {
        const config = typeof channel.config === 'string' ? JSON.parse(channel.config) : channel.config;
        await sendNotification(channel.type, config, 'Netlib 保活通知', message);
        debugLog(`通知发送成功: ${channel.name}`);
      } catch (error) {
        console.error(`发送通知到 ${channel.name} 失败:`, error.message);
        debugLog('详细错误:', error);
      }
    }
  } catch (error) {
    console.error('获取通知渠道失败:', error.message);
    debugLog('详细错误:', error);
  }
}

// 发送单个通知
async function sendNotification(type, config, title, message) {
  const timestamp = getCurrentTime();
  
  try {
    switch (type) {
      case 'telegram':
        return await sendTelegramNotification(config, title, message, timestamp);
      case 'wechat':
        return await sendWeChatNotification(config, title, message, timestamp);
      case 'wxpusher':
        return await sendWxPusherNotification(config, title, message, timestamp);
      case 'dingtalk':
        return await sendDingTalkNotification(config, title, message, timestamp);
      default:
        return { success: false, message: '未知的通知类型' };
    }
  } catch (error) {
    console.error(`发送 ${type} 通知失败:`, error.message);
    debugLog('详细错误:', error);
    return { success: false, message: error.message };
  }
}

async function sendTelegramNotification(config, title, message, timestamp) {
  const baseUrl = config.baseUrl || 'https://api.telegram.org';
  const url = `${baseUrl}/bot${config.botToken}/sendMessage`;
  
  const text = `📢 ${title}\n\n${message}\n\n⏰ ${timestamp}`;
  
  const response = await axios.post(url, {
    chat_id: config.chatId,
    text,
    disable_web_page_preview: true
  }, { timeout: 10000 });
  
  return { success: response.data.ok, message: '发送成功' };
}

async function sendWeChatNotification(config, title, message, timestamp) {
  const baseUrl = config.baseUrl || 'https://qyapi.weixin.qq.com';
  const url = `${baseUrl}/cgi-bin/webhook/send?key=${config.webhookKey}`;
  
  const content = `【${title}】\n\n${message}\n\n⏰ ${timestamp}`;
  
  const response = await axios.post(url, {
    msgtype: 'text',
    text: { content }
  }, { timeout: 10000 });
  
  return { success: response.data.errcode === 0, message: response.data.errmsg || '发送成功' };
}

async function sendWxPusherNotification(config, title, message, timestamp) {
  const baseUrl = config.baseUrl || 'https://wxpusher.zjiecode.com';
  const url = `${baseUrl}/api/send/message`;
  
  const htmlContent = `
    <div style="padding: 10px; color: #2c3e50; background: #ffffff;">
      <h2 style="color: inherit; margin: 0;">${title}</h2>
      <div style="margin-top: 10px; padding: 10px; background: #f8f9fa; border-radius: 5px; color: #2c3e50;">
        <pre style="white-space: pre-wrap; word-wrap: break-word; margin: 0; color: inherit;">${message}</pre>
      </div>
      <div style="margin-top: 10px; color: #7f8c8d; font-size: 12px;">发送时间: ${timestamp}</div>
    </div>
  `;
  
  const response = await axios.post(url, {
    appToken: config.appToken,
    content: htmlContent,
    summary: title,
    contentType: 2,
    uids: config.uids,
    verifyPayType: 0
  }, { timeout: 10000 });
  
  return { success: response.data.code === 1000, message: response.data.msg || '发送成功' };
}

async function sendDingTalkNotification(config, title, message, timestamp) {
  const baseUrl = config.baseUrl || 'https://oapi.dingtalk.com';
  
  // 计算签名
  const timestampMs = Date.now();
  const stringToSign = `${timestampMs}\n${config.secret}`;
  const sign = crypto.createHmac('sha256', config.secret)
    .update(stringToSign)
    .digest('base64');
  
  const url = `${baseUrl}/robot/send?access_token=${config.accessToken}&timestamp=${timestampMs}&sign=${encodeURIComponent(sign)}`;
  
  const content = `【${title}】\n${message}\n\n⏰ ${timestamp}`;
  
  const response = await axios.post(url, {
    msgtype: 'text',
    text: { content },
    at: { isAtAll: false }
  }, { timeout: 10000 });
  
  return { success: response.data.errcode === 0, message: response.data.errmsg || '发送成功' };
}

// 定时任务管理
const cronJobs = new Map();

async function loadCronJobs() {
  console.log(`\n🔄 重新加载定时任务 - ${getCurrentTime()}`);
  
  // 清除所有现有任务
  cronJobs.forEach((job, accountId) => {
    job.stop();
    debugLog(`停止定时任务: 账号ID=${accountId}`);
  });
  cronJobs.clear();
  
  // 加载所有启用的账号
  try {
    const accounts = await query('SELECT * FROM accounts WHERE enabled = 1');
    console.log(`📋 找到 ${accounts.length} 个启用的账号`);
    
    for (const account of accounts) {
      try {
        debugLog(`加载定时任务: ${account.username} (${account.cron_expression})`);
        
        // 验证 cron 表达式
        if (!cron.validate(account.cron_expression)) {
          console.error(`❌ 无效的 Cron 表达式: ${account.username} - ${account.cron_expression}`);
          continue;
        }
        
        const job = cron.schedule(account.cron_expression, async () => {
          console.log(`\n⏰ 定时任务触发: ${account.username} - ${getCurrentTime()}`);
          try {
            await performKeepalive(account);
          } catch (error) {
            console.error(`❌ 定时任务执行失败: ${account.username}`, error.message);
            debugLog('详细错误:', error);
          }
        }, {
          scheduled: true,
          timezone: TIMEZONE
        });
        
        cronJobs.set(account.id, job);
        console.log(`✅ 已加载定时任务: ${account.username} (${account.cron_expression}) [时区: ${TIMEZONE}]`);
      } catch (error) {
        console.error(`❌ 加载定时任务失败: ${account.username}`, error.message);
        debugLog('详细错误:', error);
      }
    }
    
    console.log(`✅ 定时任务加载完成,共 ${cronJobs.size} 个任务\n`);
  } catch (error) {
    console.error('❌ 加载定时任务失败:', error.message);
    debugLog('详细错误:', error);
  }
}

// HTML 页面 (修改部分)
app.get('/', (req, res) => {
  const html = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Netlib 保活系统</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
  <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.0/font/bootstrap-icons.css" rel="stylesheet">
  <script src="https://cdn.jsdelivr.net/npm/echarts@5.4.3/dist/echarts.min.js"></script>
  <style>
    :root {
      --primary-color: #667eea;
      --secondary-color: #764ba2;
      --success-color: #10b981;
      --danger-color: #ef4444;
      --warning-color: #f59e0b;
      --dark-color: #1f2937;
      --light-color: #f9fafb;
    }
    
    body {
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
      min-height: 100vh;
      font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
    }
    
    .login-container {
      display: flex;
      justify-content: center;
      align-items: center;
      min-height: 100vh;
      padding: 20px;
    }
    
    .login-card {
      background: white;
      border-radius: 20px;
      box-shadow: 0 20px 60px rgba(0,0,0,0.3);
      padding: 40px;
      width: 100%;
      max-width: 400px;
      animation: fadeInUp 0.5s ease;
    }
    
    @keyframes fadeInUp {
      from {
        opacity: 0;
        transform: translateY(30px);
      }
      to {
        opacity: 1;
        transform: translateY(0);
      }
    }
    
    .login-title {
      text-align: center;
      margin-bottom: 30px;
      color: var(--dark-color);
      font-weight: 700;
      font-size: 28px;
    }
    
    .login-icon {
      text-align: center;
      margin-bottom: 20px;
    }
    
    .login-icon i {
      font-size: 60px;
      background: linear-gradient(135deg, var(--primary-color), var(--secondary-color));
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
    }
    
    .app-container {
      display: none;
      background: var(--light-color);
      min-height: 100vh;
    }
    
    .sidebar {
      background: white;
      height: 100vh;
      position: fixed;
      left: 0;
      top: 0;
      width: 250px;
      box-shadow: 2px 0 10px rgba(0,0,0,0.1);
      overflow-y: auto;
      transition: all 0.3s ease;
      z-index: 1000;
    }
    
    .sidebar-header {
      padding: 30px 20px;
      background: linear-gradient(135deg, var(--primary-color), var(--secondary-color));
      color: white;
      text-align: center;
      position: relative;
    }
    
    .sidebar-header h3 {
      margin: 0;
      font-size: 20px;
      font-weight: 700;
    }
    
    .sidebar-close {
      display: none;
      position: absolute;
      right: 10px;
      top: 10px;
      background: rgba(255,255,255,0.2);
      border: none;
      color: white;
      width: 30px;
      height: 30px;
      border-radius: 5px;
      cursor: pointer;
      font-size: 20px;
      line-height: 1;
    }
    
    .sidebar-menu {
      padding: 20px 0;
    }
    
    .menu-item {
      padding: 15px 25px;
      cursor: pointer;
      transition: all 0.3s ease;
      display: flex;
      align-items: center;
      color: var(--dark-color);
      text-decoration: none;
    }
    
    .menu-item:hover, .menu-item.active {
      background: linear-gradient(90deg, var(--primary-color), transparent);
      color: var(--primary-color);
      border-left: 4px solid var(--primary-color);
    }
    
    .menu-item i {
      margin-right: 15px;
      font-size: 20px;
    }
    
    .main-content {
      margin-left: 250px;
      padding: 30px;
      transition: all 0.3s ease;
    }
    
    .top-bar {
      background: white;
      padding: 20px 30px;
      border-radius: 15px;
      box-shadow: 0 2px 10px rgba(0,0,0,0.05);
      margin-bottom: 30px;
      display: flex;
      justify-content: space-between;
      align-items: center;
    }
    
    .page-section {
      display: none;
    }
    
    .page-section.active {
      display: block;
      animation: fadeIn 0.3s ease;
    }
    
    @keyframes fadeIn {
      from { opacity: 0; }
      to { opacity: 1; }
    }
    
    .stat-card {
      background: white;
      border-radius: 15px;
      padding: 25px;
      box-shadow: 0 2px 10px rgba(0,0,0,0.05);
      transition: all 0.3s ease;
    }
    
    .stat-card:hover {
      transform: translateY(-5px);
      box-shadow: 0 5px 20px rgba(0,0,0,0.1);
    }
    
    .stat-icon {
      width: 60px;
      height: 60px;
      border-radius: 15px;
      display: flex;
      align-items: center;
      justify-content: center;
      font-size: 30px;
      margin-bottom: 15px;
    }
    
    .stat-value {
      font-size: 32px;
      font-weight: 700;
      color: var(--dark-color);
      margin: 10px 0;
    }
    
    .stat-label {
      color: #6b7280;
      font-size: 14px;
    }
    
    .btn-gradient {
      background: linear-gradient(135deg, var(--primary-color), var(--secondary-color));
      border: none;
      color: white;
      transition: all 0.3s ease;
    }
    
    .btn-gradient:hover {
      transform: translateY(-2px);
      box-shadow: 0 5px 15px rgba(102, 126, 234, 0.4);
      color: white;
    }
    
    .table-container {
      background: white;
      border-radius: 15px;
      padding: 25px;
      box-shadow: 0 2px 10px rgba(0,0,0,0.05);
    }
    
    .mobile-menu-toggle {
      display: none;
      background: white;
      border: none;
      font-size: 24px;
      color: var(--primary-color);
      padding: 10px;
      border-radius: 10px;
      cursor: pointer;
    }
    
    .sidebar-overlay {
      display: none;
      position: fixed;
      top: 0;
      left: 0;
      right: 0;
      bottom: 0;
      background: rgba(0,0,0,0.5);
      z-index: 999;
    }
    
    @media (max-width: 768px) {
      .sidebar {
        left: -250px;
      }
      
      .sidebar.show {
        left: 0;
      }
      
      .sidebar-close {
        display: block;
      }
      
      .sidebar-overlay.show {
        display: block;
      }
      
      .main-content {
        margin-left: 0;
        padding: 15px;
      }
      
      .mobile-menu-toggle {
        display: block;
      }
      
      .top-bar {
        flex-direction: column;
        gap: 15px;
      }
    }
    
    .chart-container {
      background: white;
      border-radius: 15px;
      padding: 25px;
      box-shadow: 0 2px 10px rgba(0,0,0,0.05);
      margin-top: 20px;
    }
    
    .badge-success {
      background: var(--success-color);
    }
    
    .badge-danger {
      background: var(--danger-color);
    }
    
    .form-control:focus, .form-select:focus {
      border-color: var(--primary-color);
      box-shadow: 0 0 0 0.2rem rgba(102, 126, 234, 0.25);
    }
    
    .modal-header {
      background: linear-gradient(135deg, var(--primary-color), var(--secondary-color));
      color: white;
      border-radius: 15px 15px 0 0;
    }
    
    .modal-content {
      border-radius: 15px;
      border: none;
    }
  </style>
</head>
<body>
  <!-- 登录页面 -->
  <div id="loginPage" class="login-container">
    <div class="login-card">
      <div class="login-icon">
        <i class="bi bi-shield-lock"></i>
      </div>
      <h2 class="login-title">Netlib 保活系统</h2>
      <form id="loginForm">
        <div class="mb-3">
          <label class="form-label">用户名</label>
          <input type="text" class="form-control" id="username" required>
        </div>
        <div class="mb-3">
          <label class="form-label">密码</label>
          <input type="password" class="form-control" id="password" required>
        </div>
        <button type="submit" class="btn btn-gradient w-100">登录</button>
      </form>
    </div>
  </div>

  <!-- 主应用 -->
  <div id="appContainer" class="app-container">
    <!-- 侧边栏遮罩 -->
    <div class="sidebar-overlay" id="sidebarOverlay"></div>
    
    <!-- 侧边栏 -->
    <div class="sidebar" id="sidebar">
      <div class="sidebar-header">
        <button class="sidebar-close" id="sidebarClose">
          <i class="bi bi-x"></i>
        </button>
        <h3><i class="bi bi-shield-check"></i> Netlib</h3>
      </div>
      <div class="sidebar-menu">
        <div class="menu-item active" data-page="dashboard">
          <i class="bi bi-speedometer2"></i>
          <span>仪表板</span>
        </div>
        <div class="menu-item" data-page="accounts">
          <i class="bi bi-people"></i>
          <span>账号管理</span>
        </div>
        <div class="menu-item" data-page="logs">
          <i class="bi bi-journal-text"></i>
          <span>保活日志</span>
        </div>
        <div class="menu-item" data-page="notifications">
          <i class="bi bi-bell"></i>
          <span>通知设置</span>
        </div>
        <div class="menu-item" id="logoutBtn">
          <i class="bi bi-box-arrow-right"></i>
          <span>退出登录</span>
        </div>
      </div>
    </div>

    <!-- 主内容区 -->
    <div class="main-content">
      <div class="top-bar">
        <button class="mobile-menu-toggle" id="menuToggle">
          <i class="bi bi-list"></i>
        </button>
        <h4 class="mb-0"><span id="pageTitle">仪表板</span></h4>
        <div>
          <span class="text-muted">欢迎回来</span>
        </div>
      </div>

      <!-- 仪表板 -->
      <div id="dashboardPage" class="page-section active">
        <div class="row g-4 mb-4">
          <div class="col-md-3 col-sm-6">
            <div class="stat-card">
              <div class="stat-icon" style="background: rgba(102, 126, 234, 0.1); color: var(--primary-color);">
                <i class="bi bi-people"></i>
              </div>
              <div class="stat-value" id="totalAccounts">0</div>
              <div class="stat-label">总账号数</div>
            </div>
          </div>
          <div class="col-md-3 col-sm-6">
            <div class="stat-card">
              <div class="stat-icon" style="background: rgba(16, 185, 129, 0.1); color: var(--success-color);">
                <i class="bi bi-check-circle"></i>
              </div>
              <div class="stat-value" id="enabledAccounts">0</div>
              <div class="stat-label">已启用账号</div>
            </div>
          </div>
          <div class="col-md-3 col-sm-6">
            <div class="stat-card">
              <div class="stat-icon" style="background: rgba(245, 158, 11, 0.1); color: var(--warning-color);">
                <i class="bi bi-clock-history"></i>
              </div>
              <div class="stat-value" id="totalKeepalives">0</div>
              <div class="stat-label">总保活次数</div>
            </div>
          </div>
          <div class="col-md-3 col-sm-6">
            <div class="stat-card">
              <div class="stat-icon" style="background: rgba(239, 68, 68, 0.1); color: var(--danger-color);">
                <i class="bi bi-graph-up"></i>
              </div>
              <div class="stat-value" id="successRate">0%</div>
              <div class="stat-label">成功率</div>
            </div>
          </div>
        </div>

        <div class="chart-container">
          <h5 class="mb-4">最近7天保活记录</h5>
          <div id="recentLogsChart" style="height: 400px;"></div>
        </div>
      </div>

      <!-- 账号管理 -->
      <div id="accountsPage" class="page-section">
        <div class="table-container">
          <div class="d-flex justify-content-between align-items-center mb-4">
            <h5 class="mb-0">账号列表</h5>
            <button class="btn btn-gradient" data-bs-toggle="modal" data-bs-target="#accountModal" onclick="openAccountModal()">
              <i class="bi bi-plus-circle"></i> 添加账号
            </button>
          </div>
          <div class="table-responsive">
            <table class="table table-hover">
              <thead>
                <tr>
                  <th>ID</th>
                  <th>用户名</th>
                  <th>状态</th>
                  <th>定时表达式</th>
                  <th>最后保活</th>
                  <th>操作</th>
                </tr>
              </thead>
              <tbody id="accountsTableBody">
              </tbody>
            </table>
          </div>
        </div>
      </div>

      <!-- 保活日志 -->
      <div id="logsPage" class="page-section">
        <div class="table-container">
          <div class="d-flex justify-content-between align-items-center mb-4">
            <h5 class="mb-0">保活日志</h5>
            <button class="btn btn-danger" onclick="deleteSelectedLogs()">
              <i class="bi bi-trash"></i> 删除选中
            </button>
          </div>
          <div class="table-responsive">
            <table class="table table-hover">
              <thead>
                <tr>
                  <th><input type="checkbox" id="selectAllLogs" onchange="toggleAllLogs(this)"></th>
                  <th>ID</th>
                  <th>用户名</th>
                  <th>状态</th>
                  <th>消息</th>
                  <th>时间</th>
                </tr>
              </thead>
              <tbody id="logsTableBody">
              </tbody>
            </table>
          </div>
        </div>
      </div>

      <!-- 通知设置 -->
      <div id="notificationsPage" class="page-section">
        <div class="table-container">
          <div class="d-flex justify-content-between align-items-center mb-4">
            <h5 class="mb-0">通知渠道</h5>
            <button class="btn btn-gradient" data-bs-toggle="modal" data-bs-target="#notificationModal" onclick="openNotificationModal()">
              <i class="bi bi-plus-circle"></i> 添加渠道
            </button>
          </div>
          <div class="table-responsive">
            <table class="table table-hover">
              <thead>
                <tr>
                  <th>名称</th>
                  <th>类型</th>
                  <th>状态</th>
                  <th>操作</th>
                </tr>
              </thead>
              <tbody id="notificationsTableBody">
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  </div>

  <!-- 账号模态框 -->
  <div class="modal fade" id="accountModal" tabindex="-1">
    <div class="modal-dialog">
      <div class="modal-content">
        <div class="modal-header">
          <h5 class="modal-title" id="accountModalTitle">添加账号</h5>
          <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
        </div>
        <div class="modal-body">
          <form id="accountForm">
            <input type="hidden" id="accountId">
            <div class="mb-3">
              <label class="form-label">用户名</label>
              <input type="text" class="form-control" id="accountUsername" required>
            </div>
            <div class="mb-3">
              <label class="form-label">密码</label>
              <input type="password" class="form-control" id="accountPassword" required>
            </div>
            <div class="mb-3">
              <label class="form-label">Cron 表达式</label>
              <input type="text" class="form-control" id="accountCron" value="0 0 1 * *" required>
              <small class="text-muted">默认每月1号凌晨执行 (时区: ${TIMEZONE})</small>
            </div>
            <div class="mb-3 form-check">
              <input type="checkbox" class="form-check-input" id="accountEnabled" checked>
              <label class="form-check-label">启用账号</label>
            </div>
          </form>
        </div>
        <div class="modal-footer">
          <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">取消</button>
          <button type="button" class="btn btn-gradient" onclick="saveAccount()">保存</button>
        </div>
      </div>
    </div>
  </div>

  <!-- 通知渠道模态框 -->
  <div class="modal fade" id="notificationModal" tabindex="-1">
    <div class="modal-dialog modal-lg">
      <div class="modal-content">
        <div class="modal-header">
          <h5 class="modal-title" id="notificationModalTitle">添加通知渠道</h5>
          <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
        </div>
        <div class="modal-body">
          <form id="notificationForm">
            <input type="hidden" id="notificationId">
            <div class="mb-3">
              <label class="form-label">名称</label>
              <input type="text" class="form-control" id="notificationName" required>
            </div>
            <div class="mb-3">
              <label class="form-label">类型</label>
              <select class="form-select" id="notificationType" onchange="updateNotificationFields()" required>
                <option value="">请选择</option>
                <option value="telegram">Telegram</option>
                <option value="wechat">企业微信</option>
                <option value="wxpusher">WxPusher</option>
                <option value="dingtalk">钉钉</option>
              </select>
            </div>
            <div id="notificationFields"></div>
            <div class="mb-3 form-check">
              <input type="checkbox" class="form-check-input" id="notificationEnabled" checked>
              <label class="form-check-label">启用渠道</label>
            </div>
          </form>
        </div>
        <div class="modal-footer">
          <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">取消</button>
          <button type="button" class="btn btn-gradient" onclick="saveNotification()">保存</button>
        </div>
      </div>
    </div>
  </div>

  <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
  <script>
    let currentAccountId = null;
    let currentNotificationId = null;
    
    // 检查登录状态
    async function checkAuth() {
      try {
        const res = await fetch('/api/auth/check');
        const data = await res.json();
        if (data.authenticated) {
          document.getElementById('loginPage').style.display = 'none';
          document.getElementById('appContainer').style.display = 'block';
          loadDashboard();
        }
      } catch (error) {
        console.error('检查登录状态失败:', error);
      }
    }
    
    // 登录
    document.getElementById('loginForm').addEventListener('submit', async (e) => {
      e.preventDefault();
      const username = document.getElementById('username').value;
      const password = document.getElementById('password').value;
      
      try {
        const res = await fetch('/api/login', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ username, password })
        });
        
        if (res.ok) {
          document.getElementById('loginPage').style.display = 'none';
          document.getElementById('appContainer').style.display = 'block';
          loadDashboard();
        } else {
          alert('用户名或密码错误');
        }
      } catch (error) {
        alert('登录失败: ' + error.message);
      }
    });
    
    // 登出
    document.getElementById('logoutBtn').addEventListener('click', async () => {
      await fetch('/api/logout', { method: 'POST' });
      location.reload();
    });
    
    // 菜单切换
    document.querySelectorAll('.menu-item[data-page]').forEach(item => {
      item.addEventListener('click', () => {
        const page = item.dataset.page;
        
        document.querySelectorAll('.menu-item').forEach(i => i.classList.remove('active'));
        item.classList.add('active');
        
        document.querySelectorAll('.page-section').forEach(p => p.classList.remove('active'));
        document.getElementById(page + 'Page').classList.add('active');
        
        const titles = {
          dashboard: '仪表板',
          accounts: '账号管理',
          logs: '保活日志',
          notifications: '通知设置'
        };
        document.getElementById('pageTitle').textContent = titles[page];
        
        // 关闭移动端侧边栏
        closeSidebar();
        
        if (page === 'dashboard') loadDashboard();
        if (page === 'accounts') loadAccounts();
        if (page === 'logs') loadLogs();
        if (page === 'notifications') loadNotifications();
      });
    });
    
    // 移动端菜单控制
    document.getElementById('menuToggle').addEventListener('click', () => {
      document.getElementById('sidebar').classList.add('show');
      document.getElementById('sidebarOverlay').classList.add('show');
    });
    
    document.getElementById('sidebarClose').addEventListener('click', closeSidebar);
    document.getElementById('sidebarOverlay').addEventListener('click', closeSidebar);
    
    function closeSidebar() {
      document.getElementById('sidebar').classList.remove('show');
      document.getElementById('sidebarOverlay').classList.remove('show');
    }
    
    // 加载仪表板
    async function loadDashboard() {
      try {
        const res = await fetch('/api/stats');
        const data = await res.json();
        
        document.getElementById('totalAccounts').textContent = data.total_accounts;
        document.getElementById('enabledAccounts').textContent = data.enabled_accounts;
        document.getElementById('totalKeepalives').textContent = data.total_keepalives;
        document.getElementById('successRate').textContent = data.success_rate + '%';
        
        // 绘制图表
        const chart = echarts.init(document.getElementById('recentLogsChart'));
        const dates = data.recent_logs.map(log => log.date).reverse();
        const total = data.recent_logs.map(log => log.total).reverse();
        const success = data.recent_logs.map(log => log.success).reverse();
        
        chart.setOption({
          tooltip: { trigger: 'axis' },
          legend: { data: ['总数', '成功'] },
          xAxis: { type: 'category', data: dates },
          yAxis: { type: 'value' },
          series: [
            { name: '总数', type: 'line', data: total, smooth: true },
            { name: '成功', type: 'line', data: success, smooth: true }
          ],
          color: ['#667eea', '#10b981']
        });
      } catch (error) {
        console.error('加载仪表板失败:', error);
      }
    }
    
    // 加载账号列表
    async function loadAccounts() {
      try {
        const res = await fetch('/api/accounts');
        const accounts = await res.json();
        
        const tbody = document.getElementById('accountsTableBody');
        tbody.innerHTML = accounts.map(acc => \`
          <tr>
            <td>\${acc.id}</td>
            <td>\${acc.username}</td>
            <td><span class="badge \${acc.enabled ? 'badge-success' : 'badge-danger'}">\${acc.enabled ? '启用' : '禁用'}</span></td>
            <td>\${acc.cron_expression}</td>
            <td>\${acc.last_keepalive || '从未'}</td>
            <td>
              <button class="btn btn-sm btn-primary" onclick="editAccount(\${acc.id})"><i class="bi bi-pencil"></i></button>
              <button class="btn btn-sm btn-success" onclick="manualKeepalive(\${acc.id})"><i class="bi bi-play-circle"></i></button>
              <button class="btn btn-sm btn-danger" onclick="deleteAccount(\${acc.id})"><i class="bi bi-trash"></i></button>
            </td>
          </tr>
        \`).join('');
      } catch (error) {
        console.error('加载账号失败:', error);
      }
    }
    
    // 打开账号模态框
    function openAccountModal() {
      currentAccountId = null;
      document.getElementById('accountModalTitle').textContent = '添加账号';
      document.getElementById('accountForm').reset();
      document.getElementById('accountCron').value = '0 0 1 * *';
      document.getElementById('accountEnabled').checked = true;
    }
    
    // 编辑账号
    async function editAccount(id) {
      try {
        const res = await fetch('/api/accounts');
        const accounts = await res.json();
        const account = accounts.find(a => a.id === id);
        
        if (account) {
          currentAccountId = id;
          document.getElementById('accountModalTitle').textContent = '编辑账号';
          document.getElementById('accountUsername').value = account.username;
          document.getElementById('accountPassword').value = '';
          document.getElementById('accountCron').value = account.cron_expression;
          document.getElementById('accountEnabled').checked = account.enabled;
          
          new bootstrap.Modal(document.getElementById('accountModal')).show();
        }
      } catch (error) {
        console.error('加载账号失败:', error);
      }
    }
    
    // 保存账号
    async function saveAccount() {
      const username = document.getElementById('accountUsername').value;
      const password = document.getElementById('accountPassword').value;
      const cron = document.getElementById('accountCron').value;
      const enabled = document.getElementById('accountEnabled').checked;
      
      if (!username || (!currentAccountId && !password)) {
        alert('请填写必填字段');
        return;
      }
      
      try {
        const data = { username, cron_expression: cron, enabled };
        if (password) data.password = password;
        
        const url = currentAccountId ? \`/api/accounts/\${currentAccountId}\` : '/api/accounts';
        const method = currentAccountId ? 'PUT' : 'POST';
        
        const res = await fetch(url, {
          method,
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(data)
        });
        
        if (res.ok) {
          bootstrap.Modal.getInstance(document.getElementById('accountModal')).hide();
          loadAccounts();
          alert('保存成功');
        } else {
          const error = await res.json();
          alert('保存失败: ' + error.error);
        }
      } catch (error) {
        alert('保存失败: ' + error.message);
      }
    }
    
    // 删除账号
    async function deleteAccount(id) {
      if (!confirm('确定要删除此账号吗?')) return;
      
      try {
        const res = await fetch(\`/api/accounts/\${id}\`, { method: 'DELETE' });
        if (res.ok) {
          loadAccounts();
          alert('删除成功');
        }
      } catch (error) {
        alert('删除失败: ' + error.message);
      }
    }
    
    // 手动保活
    async function manualKeepalive(id) {
      if (!confirm('确定要手动执行保活吗?')) return;
      
      try {
        const res = await fetch(\`/api/keepalive/\${id}\`, { method: 'POST' });
        const result = await res.json();
        alert(result.message || '保活完成');
        loadAccounts();
        loadLogs();
      } catch (error) {
        alert('保活失败: ' + error.message);
      }
    }
    
    // 加载日志
    async function loadLogs() {
      try {
        const res = await fetch('/api/logs?limit=100');
        const data = await res.json();
        
        const tbody = document.getElementById('logsTableBody');
        tbody.innerHTML = data.logs.map(log => \`
          <tr>
            <td><input type="checkbox" class="log-checkbox" value="\${log.id}"></td>
            <td>\${log.id}</td>
            <td>\${log.username}</td>
            <td><span class="badge \${log.success ? 'badge-success' : 'badge-danger'}">\${log.success ? '成功' : '失败'}</span></td>
            <td>\${log.message}</td>
            <td>\${log.created_at}</td>
          </tr>
        \`).join('');
      } catch (error) {
        console.error('加载日志失败:', error);
      }
    }
    
    // 全选日志
    function toggleAllLogs(checkbox) {
      document.querySelectorAll('.log-checkbox').forEach(cb => {
        cb.checked = checkbox.checked;
      });
    }
    
    // 删除选中日志
    async function deleteSelectedLogs() {
      const selected = Array.from(document.querySelectorAll('.log-checkbox:checked')).map(cb => parseInt(cb.value));
      
      if (selected.length === 0) {
        alert('请选择要删除的日志');
        return;
      }
      
      if (!confirm(\`确定要删除 \${selected.length} 条日志吗?\`)) return;
      
      try {
        const res = await fetch('/api/logs', {
          method: 'DELETE',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ ids: selected })
        });
        
        if (res.ok) {
          loadLogs();
          alert('删除成功');
        }
      } catch (error) {
        alert('删除失败: ' + error.message);
      }
    }
    
    // 加载通知渠道
    async function loadNotifications() {
      try {
        const res = await fetch('/api/notifications');
        const channels = await res.json();
        
        const tbody = document.getElementById('notificationsTableBody');
        tbody.innerHTML = channels.map(ch => \`
          <tr>
            <td>\${ch.name}</td>
            <td>\${ch.type}</td>
            <td><span class="badge \${ch.enabled ? 'badge-success' : 'badge-danger'}">\${ch.enabled ? '启用' : '禁用'}</span></td>
            <td>
              <button class="btn btn-sm btn-primary" onclick="editNotification(\${ch.id})"><i class="bi bi-pencil"></i></button>
              <button class="btn btn-sm btn-info" onclick="testNotification(\${ch.id})"><i class="bi bi-send"></i></button>
              <button class="btn btn-sm btn-danger" onclick="deleteNotification(\${ch.id})"><i class="bi bi-trash"></i></button>
            </td>
          </tr>
        \`).join('');
      } catch (error) {
        console.error('加载通知渠道失败:', error);
      }
    }
    
    // 打开通知模态框
    function openNotificationModal() {
      currentNotificationId = null;
      document.getElementById('notificationModalTitle').textContent = '添加通知渠道';
      document.getElementById('notificationForm').reset();
      document.getElementById('notificationFields').innerHTML = '';
      document.getElementById('notificationEnabled').checked = true;
    }
    
    // 更新通知字段
    function updateNotificationFields() {
      const type = document.getElementById('notificationType').value;
      const container = document.getElementById('notificationFields');
      
      const fields = {
        telegram: \`
          <div class="mb-3">
            <label class="form-label">Bot Token</label>
            <input type="text" class="form-control" id="botToken" required>
          </div>
          <div class="mb-3">
            <label class="form-label">Chat ID</label>
            <input type="text" class="form-control" id="chatId" required>
          </div>
          <div class="mb-3">
            <label class="form-label">API 基础地址 (可选)</label>
            <input type="text" class="form-control" id="baseUrl" placeholder="https://api.telegram.org">
          </div>
        \`,
        wechat: \`
          <div class="mb-3">
            <label class="form-label">Webhook Key</label>
            <input type="text" class="form-control" id="webhookKey" required>
          </div>
          <div class="mb-3">
            <label class="form-label">API 基础地址 (可选)</label>
            <input type="text" class="form-control" id="baseUrl" placeholder="https://qyapi.weixin.qq.com">
          </div>
        \`,
        wxpusher: \`
          <div class="mb-3">
            <label class="form-label">App Token</label>
            <input type="text" class="form-control" id="appToken" required>
          </div>
          <div class="mb-3">
            <label class="form-label">UIDs (逗号分隔)</label>
            <input type="text" class="form-control" id="uids" required>
          </div>
          <div class="mb-3">
            <label class="form-label">API 基础地址 (可选)</label>
            <input type="text" class="form-control" id="baseUrl" placeholder="https://wxpusher.zjiecode.com">
          </div>
        \`,
        dingtalk: \`
          <div class="mb-3">
            <label class="form-label">Access Token</label>
            <input type="text" class="form-control" id="accessToken" required>
          </div>
          <div class="mb-3">
            <label class="form-label">Secret</label>
            <input type="text" class="form-control" id="secret" required>
          </div>
          <div class="mb-3">
            <label class="form-label">API 基础地址 (可选)</label>
            <input type="text" class="form-control" id="baseUrl" placeholder="https://oapi.dingtalk.com">
          </div>
        \`
      };
      
      container.innerHTML = fields[type] || '';
    }
    
    // 编辑通知渠道
    async function editNotification(id) {
      try {
        const res = await fetch('/api/notifications');
        const channels = await res.json();
        const channel = channels.find(c => c.id === id);
        
        if (channel) {
          currentNotificationId = id;
          document.getElementById('notificationModalTitle').textContent = '编辑通知渠道';
          document.getElementById('notificationName').value = channel.name;
          document.getElementById('notificationType').value = channel.type;
          document.getElementById('notificationEnabled').checked = channel.enabled;
          
          updateNotificationFields();
          
          // 填充配置
          setTimeout(() => {
            Object.keys(channel.config).forEach(key => {
              const input = document.getElementById(key);
              if (input) {
                if (Array.isArray(channel.config[key])) {
                  input.value = channel.config[key].join(',');
                } else {
                  input.value = channel.config[key];
                }
              }
            });
          }, 100);
          
          new bootstrap.Modal(document.getElementById('notificationModal')).show();
        }
      } catch (error) {
        console.error('加载通知渠道失败:', error);
      }
    }
    
    // 保存通知渠道
    async function saveNotification() {
      const name = document.getElementById('notificationName').value;
      const type = document.getElementById('notificationType').value;
      const enabled = document.getElementById('notificationEnabled').checked;
      
      if (!name || !type) {
        alert('请填写必填字段');
        return;
      }
      
      const config = {};
      const fields = document.getElementById('notificationFields').querySelectorAll('input');
      fields.forEach(field => {
        if (field.value) {
          if (field.id === 'uids') {
            config[field.id] = field.value.split(',').map(s => s.trim());
          } else {
            config[field.id] = field.value;
          }
        }
      });
      
      try {
        const url = currentNotificationId ? \`/api/notifications/\${currentNotificationId}\` : '/api/notifications';
        const method = currentNotificationId ? 'PUT' : 'POST';
        
        const res = await fetch(url, {
          method,
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ name, type, config, enabled })
        });
        
        if (res.ok) {
          bootstrap.Modal.getInstance(document.getElementById('notificationModal')).hide();
          loadNotifications();
          alert('保存成功');
        } else {
          const error = await res.json();
          alert('保存失败: ' + error.error);
        }
      } catch (error) {
        alert('保存失败: ' + error.message);
      }
    }
    
    // 测试通知
    async function testNotification(id) {
      try {
        const res = await fetch(\`/api/notifications/\${id}/test\`, { method: 'POST' });
        const result = await res.json();
        alert(result.success ? '测试消息发送成功' : '测试消息发送失败: ' + result.message);
      } catch (error) {
        alert('测试失败: ' + error.message);
      }
    }
    
    // 删除通知渠道
    async function deleteNotification(id) {
      if (!confirm('确定要删除此通知渠道吗?')) return;
      
      try {
        const res = await fetch(\`/api/notifications/\${id}\`, { method: 'DELETE' });
        if (res.ok) {
          loadNotifications();
          alert('删除成功');
        }
      } catch (error) {
        alert('删除失败: ' + error.message);
      }
    }
    
    // 初始化
    checkAuth();
  </script>
</body>
</html>`;
  
  res.send(html);
});

// 启动服务器
async function start() {
  try {
    console.log('\n===== Application Startup =====');
    console.log(`启动时间: ${getCurrentTime()}`);
    console.log(`时区设置: ${TIMEZONE}`);
    console.log(`DEBUG 模式: ${DEBUG ? '开启' : '关闭'}`);
    console.log('===============================\n');
    
    await initDatabase();
    await loadCronJobs();
    
    app.listen(PORT, () => {
      console.log(`\n✅ 服务器启动成功: http://localhost:${PORT}`);
      console.log(`📊 数据库类型: ${dbType.toUpperCase()}`);
      console.log(`👤 管理员账号: ${ADMIN_USERNAME}`);
      console.log(`🔄 MySQL 最大重试次数: ${MYSQL_MAX_RETRY}`);
      console.log(`🌍 时区: ${TIMEZONE}`);
      console.log(`🐛 DEBUG 模式: ${DEBUG ? '开启' : '关闭'}`);
      console.log('\n==========================================\n');
    });
  } catch (error) {
    console.error('❌ 启动失败:', error);
    debugLog('详细错误:', error);
    process.exit(1);
  }
}

start();
