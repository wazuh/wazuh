FROM nginx

COPY nginx.conf /etc/nginx/nginx.conf

ADD entrypoint.sh /scripts/entrypoint.sh

HEALTHCHECK --interval=1s --timeout=3s --retries=10 CMD curl --fail http://localhost/ || exit 1
