FROM python:3.12-alpine

ENV PORT=8080

# Install OpenSSL
RUN apk add --no-cache openssl

# Generate certificate
RUN openssl req -x509 -newkey rsa:2048 \
    -keyout key.pem \
    -out cert.pem \
    -days 365 -nodes \
    -subj "/C=ES/ST=State/L=City/O=Organization/OU=Unit/CN=localhost"


EXPOSE $PORT

COPY https_server.py .

CMD python3 https_server.py ${PORT}
