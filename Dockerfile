# netext:v1
FROM python:3.7.0-alpine3.8

COPY  . /Network_Exporter

EXPOSE 9116

WORKDIR /Network_Exporter

ENV LANG C.UTF-8

RUN apk add --no-cache tzdata  --repository http://mirrors.aliyun.com/alpine/v3.8/main/
ENV TZ Asia/Shanghai

RUN apk add --no-cache libcurl --repository http://mirrors.aliyun.com/alpine/v3.8/main/

# Needed for pycurl
ENV PYCURL_SSL_LIBRARY=openssl

# Install packages only needed for building, install and clean on a single layer
RUN apk add --no-cache --virtual .build-dependencies build-base curl-dev --repository http://mirrors.aliyun.com/alpine/v3.8/main/\
    && pip install pycurl -i https://pypi.tuna.tsinghua.edu.cn/simple\
    && apk del .build-dependencies

RUN pip install --no-cache-dir -r requirements.txt -i https://pypi.tuna.tsinghua.edu.cn/simple

CMD python network_exporter.py --addr="0.0.0.0" --port=9116 --log_dir="/tmp/network_log"
