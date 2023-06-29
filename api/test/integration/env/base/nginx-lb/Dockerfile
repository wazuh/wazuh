FROM nginx

COPY nginx.conf /etc/nginx/nginx.conf

ADD entrypoint.sh /scripts/entrypoint.sh

HEALTHCHECK --interval=30s --timeout=3s CMD curl --fail http://localhost/ || exit 1