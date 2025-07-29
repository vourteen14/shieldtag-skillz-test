FROM node:20-alpine

WORKDIR /app

COPY package*.json ./
RUN npm install

COPY . .

RUN echo '#!/bin/sh' > /entrypoint.sh && \
    echo 'exec "$@"' >> /entrypoint.sh && \
    chmod +x /entrypoint.sh

EXPOSE 3000

ENV NODE_ENV=development

ENTRYPOINT ["/entrypoint.sh"]
CMD ["npm", "run", "dev"]
