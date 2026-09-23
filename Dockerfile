# Build with: docker build --build-arg TARGETARCH=amd64 -t sing-box-secure .
FROM alpine:3.22
ARG TARGETARCH
RUN apk add --no-cache ca-certificates curl python3 openssl tzdata \
    && addgroup -g 10001 sb && adduser -D -u 10001 -G sb sb \
    && mkdir /data && chown sb:sb /data
RUN set -eu; \
    case "$TARGETARCH" in \
      amd64) digest=b907365b154e4a7e3e40be15c2cd83433c0fa65c7dc736bdb1b5face2afe4501;; \
      arm64) digest=d94fc9704372ca2fa2854e54c20b406e4b8779b5ccdd0c557da90ea9344e9631;; \
      *) echo 'Only amd64/arm64 supported by this container'; exit 1;; \
    esac; \
    curl -fLsS --proto '=https' --proto-redir '=https' --retry 2 --max-time 300 \
      "https://github.com/SagerNet/sing-box/releases/download/v1.14.1/sing-box-1.14.1-linux-$TARGETARCH-musl.tar.gz" -o /tmp/core.tgz; \
    echo "$digest  /tmp/core.tgz" | sha256sum -c -; \
    tar xzf /tmp/core.tgz -O "sing-box-1.14.1-linux-$TARGETARCH-musl/sing-box" > /usr/local/bin/sing-box; \
    chmod 755 /usr/local/bin/sing-box; /usr/local/bin/sing-box version; rm /tmp/core.tgz
WORKDIR /app
COPY secure.py portable.py ./
USER 10001:10001
ENV SB_DATA_DIR=/data TZ=Etc/UTC PYTHONDONTWRITEBYTECODE=1
EXPOSE 25809/tcp 29687/tcp 32695/udp 41781/udp 16134/tcp 34443/tcp
VOLUME ["/data"]
STOPSIGNAL SIGTERM
ENTRYPOINT ["python3", "/app/portable.py"]
