FROM node:18-alpine

ARG NEXT_PUBLIC_API_URL
ENV NEXT_PUBLIC_API_URL=$NEXT_PUBLIC_API_URL

WORKDIR /app

RUN apk add --no-cache \
    libc6-compat \
    curl

COPY package*.json ./

RUN npm install

COPY . .

EXPOSE 3001

ENV NODE_ENV=development
ENV PORT=3001
ENV HOSTNAME="0.0.0.0"

CMD ["npm", "run", "dev"]
