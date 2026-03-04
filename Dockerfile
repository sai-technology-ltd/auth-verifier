FROM node:22-alpine AS deps
WORKDIR /app
COPY package*.json ./
# CI arm64 under QEMU can crash on optional/native postinstall scripts
# from dev dependencies; tsc build does not require those scripts.
RUN npm ci --ignore-scripts

FROM deps AS build
COPY tsconfig.json ./
COPY src ./src
RUN npm run build

FROM node:22-alpine AS runtime
WORKDIR /app
COPY package*.json ./
RUN npm ci --omit=dev
COPY --from=build /app/dist ./dist
EXPOSE 3001
CMD ["node", "dist/index.js"]
