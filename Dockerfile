FROM node:20-slim

WORKDIR /app

RUN corepack enable && corepack prepare pnpm@10.30.1 --activate

COPY package.json pnpm-lock.yaml ./
RUN pnpm install --frozen-lockfile --prod

COPY tsconfig.json ./
COPY src/ ./src/

RUN mkdir -p /app/data

ENV PORT=3001
ENV DB_PATH=/app/data/licenses.sqlite

EXPOSE 3001

CMD ["npx", "tsx", "src/index.ts"]
