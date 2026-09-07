# syntax=docker/dockerfile:1.7
FROM node:22-bookworm-slim AS builder

ENV PNPM_HOME=/pnpm
ENV PATH=$PNPM_HOME:$PATH
WORKDIR /app

RUN corepack enable && corepack prepare pnpm@11.19.0 --activate
COPY package.json pnpm-workspace.yaml pnpm-lock.yaml ./
COPY frontend/package.json ./frontend/package.json
RUN pnpm install --filter toy-sast-frontend... --frozen-lockfile

ARG VITE_API_BASE_URL=http://localhost:8000
ENV VITE_API_BASE_URL=$VITE_API_BASE_URL

COPY frontend ./frontend
RUN pnpm --dir frontend build

FROM nginxinc/nginx-unprivileged:1.29-alpine AS runner
COPY frontend/nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=builder /app/frontend/dist /usr/share/nginx/html
EXPOSE 8080
