FROM nginx:alpine 

ENV FLAVOR weak 

EXPOSE 443/tcp

COPY nginx-tls-weak.conf /etc/nginx/conf.d/
COPY nginx-weak.crt /etc/nginx/ssl/nginx.crt
COPY nginx-weak.ky /etc/nginx/ssl/nginx.key
COPY index.html /usr/share/nginx/html/index.html

RUN chmod 600 /etc/nginx/ssl/nginx.key && chmod 644 /etc/nginx/ssl/nginx.crt && \
    chmod 644 /usr/share/nginx/html/index.html
