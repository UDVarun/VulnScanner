FROM node:20-alpine

WORKDIR /app

# Install dependencies first for layer caching
COPY package.json package-lock.json* ./
RUN npm install --production

# Copy source
COPY . .

EXPOSE 5000

CMD ["node", "server.js"]
