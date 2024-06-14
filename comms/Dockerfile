FROM python:3.10-alpine

RUN apk --update add redis

COPY requirements.txt .

RUN pip install --no-cache-dir --upgrade -r requirements.txt

COPY . .

COPY redis.conf /usr/local/etc/redis/redis.conf

RUN chmod +x ./entrypoint.sh

EXPOSE 5000

ENTRYPOINT ["./entrypoint.sh"]
