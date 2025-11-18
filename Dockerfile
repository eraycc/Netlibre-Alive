# 使用多阶段构建减小镜像大小
FROM mcr.microsoft.com/playwright:v1.40.0-jammy AS playwright

# 阶段1: 构建阶段
FROM node:18-alpine AS builder

# 安装构建依赖
RUN apk add --no-cache \
    python3 \
    make \
    g++ \
    chromium \
    nss \
    freetype \
    harfbuzz \
    ca-certificates \
    ttf-freefont

WORKDIR /app

# 复制依赖文件
COPY package*.json ./

# 安装npm依赖（包含Playwright）
RUN npm install --only=production --legacy-peer-deps && \
    npx playwright install chromium --with-deps && \
    # 清理缓存减小体积
    npm cache clean --force && \
    rm -rf /root/.cache/ms-playwright/ffmpeg-*

# 阶段2: 最终运行镜像
FROM node:18-alpine

# 安装运行时依赖（精简）
RUN apk add --no-cache \
    chromium \
    nss \
    freetype \
    harfbuzz \
    ca-certificates \
    ttf-freefont \
    # 添加Playwright需要的额外库
    libstdc++ \
    libgcc \
    dbus-glib \
    nss-tools \
    && rm -rf /var/cache/apk/*

# 创建非root用户提升安全性
RUN addgroup -g 1001 -S nodejs && \
    adduser -S nodejs -u 1001

# 设置环境变量
ENV NODE_ENV=production \
    PLAYWRIGHT_BROWSERS_PATH=/ms-playwright \
    PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1

# 从builder阶段复制浏览器
COPY --from=builder /root/.cache/ms-playwright /ms-playwright

# 复制应用代码
WORKDIR /app
COPY --from=builder --chown=nodejs:nodejs /app/node_modules ./node_modules
COPY --chown=nodejs:nodejs . .

# 创建数据目录
RUN mkdir -p /app/data && \
    chown -R nodejs:nodejs /app/data

# 暴露端口
EXPOSE 3000

# 切换到非root用户
USER nodejs

# 健康检查
HEALTHCHECK --interval=30s --timeout=3s --start-period=40s --retries=3 \
  CMD node -e "require('http').get('http://localhost:3000/api/auth/check', (r) => {process.exit(r.statusCode === 200 ? 0 : 1)})"

# 启动应用
CMD ["node", "app.js"]
