FROM nginx:1.25-alpine

# Generate a self-signed cert with wrong CN (cert mismatch scanner)
RUN apk add --no-cache openssl && \
    mkdir -p /etc/nginx/ssl && \
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout /etc/nginx/ssl/server.key \
        -out /etc/nginx/ssl/server.crt \
        -subj "/C=DE/ST=Test/L=Lab/O=BadSSL/CN=wrong.domain.example"

COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY html /usr/share/nginx/html
