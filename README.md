# Netlib 自动保活控制面板

一个基于 Node.js 和 Playwright 的 Netlib 自动登录保活系统，支持多种数据库和多渠道通知。

## 功能特性

- ✅ **自动保活**：定时自动登录 Netlib 账号
- ✅ **多种调度方式**：支持 Cron 表达式和时间间隔
- ✅ **数据库支持**：MySQL 和 SQLite 自动切换
- ✅ **通知系统**：Telegram、企业微信、WxPusher、钉钉
- ✅ **Web 控制面板**：账号管理、实时监控、手动执行
- ✅ **JWT 认证**：7天有效期，安全访问
- ✅ **Docker 支持**：一键部署

## 快速开始

### 方式1: Docker 部署

```bash
# 克隆项目
git clone https://github.com/yourusername/netlib-keepalive.git
cd netlib-keepalive

# 配置环境变量
cp .env.example .env
# 编辑 .env 文件

# 启动
docker-compose up -d
```

方式2: 本地运行

```bash
# 安装依赖
npm install

# 配置环境变量
cp .env.example .env
# 编辑 .env 文件

# 启动
npm start
```

访问: http://localhost:3000

管理员账号: admin
管理员密码: 在 .env 中配置

数据库配置

MySQL

```bash
MYSQL_DSN=mysql://username:password@host:port/dbname?ssl=false
```

SQLite（默认）
如果不配置 MYSQL_DSN，自动使用 SQLite，数据存储在 `./data/netlib.db`

通知配置

支持四种通知方式：
1. Telegram: Bot Token + Chat ID
2. 企业微信: Webhook URL
3. WxPusher: App Token + UID
4. 钉钉: Webhook + Secret（可选）

调度配置

两种方式任选：
- 时间间隔：每 N 分钟执行一次
- Cron 表达式：灵活的定时规则（0 /12 *  * 表示每12小时）

手动执行

在账号列表点击"立即执行"按钮，可触发单次保活任务。

日志查看

在"今日执行记录"中可以查看最新执行结果和错误信息。

安全建议

1. 修改默认管理员密码
2. 使用强 JWT 密钥
3. 生产环境使用 HTTPS
4. 限制 Docker 容器资源
5. 定期备份数据库

故障排查

```bash
# 查看日志
docker logs netlib-keepalive

# 进入容器调试
docker exec -it netlib-keepalive sh
```

## 主要特性说明

1. **数据库自动切换**：优先使用 MySQL，如果连接失败自动回退到 SQLite
2. **智能任务调度**：支持 Cron 和时间间隔两种模式，自动计算下次执行时间
3. **通知系统**：参考 Python 代码实现，支持四种渠道，可独立配置
4. **Playwright 优化**：使用无头模式，添加超时控制，自动清理浏览器实例
5. **缓存机制**：频繁查询的数据使用 Map 缓存，减少数据库压力
6. **错误处理**：完整的错误捕获和重试机制
7. **前端界面**：现代化 UI，响应式设计，实时刷新
8. **Docker 优化**：分层构建，减少镜像体积，添加健康检查

## 部署建议

1. **生产环境**：
   - 使用 MySQL 数据库
   - 配置 HTTPS 反向代理
   - 设置复杂的 JWT_SECRET
   - 使用 `--restart unless-stopped` 策略

2. **开发环境**：
   - 使用 SQLite 方便调试
   - 设置 `PLAYWRIGHT_HEADLESS=false` 查看浏览器操作
   - 使用 `npm run dev` 自动重启

3. **监控告警**：
   - 配置通知渠道
   - 监控 Docker 健康状态
   - 定期查看执行日志
