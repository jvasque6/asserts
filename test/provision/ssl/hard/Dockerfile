FROM nginx:alpine

ENV FLAVOR hard

EXPOSE 443/tcp

COPY nginx-tls-hard.conf /etc/nginx/conf.d/
COPY nginx-hard.crt /etc/nginx/ssl/nginx.crt
COPY nginx-hard.ky /etc/nginx/ssl/nginx.key
COPY index.html /usr/share/nginx/html/index.html

RUN chmod 600 /etc/nginx/ssl/nginx.key && chmod 644 /etc/nginx/ssl/nginx.crt && \
    chmod 644 /usr/share/nginx/html/index.html
