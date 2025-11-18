# 阶段1: 构建阶段
FROM node:18-slim AS builder

WORKDIR /app

COPY package*.json ./

RUN npm install --only=production --legacy-peer-deps && \
    npx playwright install chromium --with-deps && \
    npm cache clean --force

# 阶段2: 最终镜像  
FROM node:18-slim

RUN apt-get update && apt-get install -y \
    libglib2.0-0 libnss3 libxss1 libasound2 \
    libatk-bridge2.0-0 libgtk-3-0 libdrm2 \
    libxkbcommon0 libatspi2.0-0 fonts-liberation \
    libgbm1 \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

WORKDIR /app

COPY --from=builder /root/.cache/ms-playwright /root/.cache/ms-playwright
COPY --from=builder /app/node_modules ./node_modules
COPY . .

RUN mkdir -p /app/data

EXPOSE 3000
CMD ["node", "app.js"]
