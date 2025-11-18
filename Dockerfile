FROM node:18-alpine

# 安装 Playwright 的依赖
RUN apk add --no-cache \
    chromium \
    nss \
    freetype \
    freetype-dev \
    harfbuzz \
    ca-certificates \
    ttf-freefont

# 设置 Playwright 环境变量
ENV PLAYWRIGHT_BROWSERS_PATH=/usr/lib/node_modules/playwright/.local-browsers
ENV PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1

# 创建工作目录
WORKDIR /app

# 复制项目文件
COPY package*.json ./
RUN npm install --legacy-peer-deps
COPY app.js ./

# 创建数据目录
RUN mkdir -p /app/data

# 健康检查
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s \
    CMD node -e "require('http').get('http://localhost:3000/api/health', (res) => { process.exit(res.statusCode === 200 ? 0 : 1) })"

# 暴露端口
EXPOSE 3000

# 启动应用
CMD ["npm", "start"]
