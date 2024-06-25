FROM python:3.12-alpine

ENV PORT=4041

EXPOSE $PORT

COPY . .

CMD python3 http_server.py ${PORT}
