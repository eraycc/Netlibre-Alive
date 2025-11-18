# 阶段1: 构建阶段
FROM node:18-slim AS builder

WORKDIR /app

# 复制依赖文件
COPY package*.json ./

# 使用 npm install 而不是 ci
RUN npm install --only=production --legacy-peer-deps && \
    npx playwright install chromium && \
    npm cache clean --force && \
    rm -rf /root/.cache/ms-playwright/ffmpeg-*

# 阶段2: 最终镜像
FROM node:18-slim

# 安装必要的运行时依赖
RUN apt-get update && apt-get install -y \
    libglib2.0-0 libnss3 libxss1 libasound2 \
    libatk-bridge2.0-0 libgtk-3-0 libdrm2 \
    libxkbcommon0 libatspi2.0-0 fonts-liberation \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# 设置环境变量
ENV PLAYWRIGHT_BROWSERS_PATH=/ms-playwright \
    PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1

# 复制浏览器
COPY --from=builder /root/.cache/ms-playwright /ms-playwright

WORKDIR /app
COPY --from=builder /app/node_modules ./node_modules
COPY . .

# 创建数据目录
RUN mkdir -p /app/data

EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=3s --start-period=40s --retries=3 \
  CMD node -e "require('http').get('http://localhost:3000/api/auth/check', (r) => {process.exit(r.statusCode === 200 ? 0 : 1)})"

CMD ["node", "app.js"]
