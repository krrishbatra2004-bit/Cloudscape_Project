# Build stage
FROM node:20-slim AS builder
WORKDIR /app
COPY package*.json ./
RUN npm install
COPY . .
RUN npm run build

# Serve stage
FROM node:20-slim
WORKDIR /app
RUN npm install -g serve
COPY --from=builder /app/dist ./dist
# EXPOSE 5173
# In production, Cloudscape might be served via nginx. We use simple serve here.
CMD ["serve", "-s", "dist", "-l", "5173"]
