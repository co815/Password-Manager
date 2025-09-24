FROM node:20-alpine AS build
WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci

COPY . .

ARG VITE_API_ORIGIN=""
ENV VITE_API_ORIGIN=$VITE_API_ORIGIN
RUN npm run build

FROM nginx:1.27-alpine
WORKDIR /usr/share/nginx/html

COPY --from=build /app/dist .

COPY nginx.conf /etc/nginx/conf.d/default.conf

RUN apk add --no-cache openssl \
    && mkdir -p /etc/nginx/ssl \
    && openssl req -x509 -nodes -days 365 \
        -newkey rsa:2048 \
        -keyout /etc/nginx/ssl/local.key \
        -out /etc/nginx/ssl/local.crt \
        -subj "/CN=localhost" \
    && chmod 600 /etc/nginx/ssl/local.key

EXPOSE 80 443

CMD ["nginx", "-g", "daemon off;"]