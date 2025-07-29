FROM node:20-alpine

WORKDIR /app

COPY package*.json ./
RUN npm ci

COPY . .

RUN chmod +x ./entrypoint.sh

EXPOSE 3000

ENV NODE_ENV=development

ENTRYPOINT ["./entrypoint.sh"]