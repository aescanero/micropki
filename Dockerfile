FROM docker.io/golang:alpine3.17 AS builder

LABEL org.opencontainers.image.authors="Alejandro Escanero Blanco <alejandro.escanero@disasterproject.com>"

USER 0

RUN apk --no-cache add ca-certificates && mkdir /data

WORKDIR /data/
COPY . .
#COPY go.sum .
#COPY app.go .

RUN go build -a -installsuffix cgo -o micropki .

FROM docker.io/debian:stable-20230227-slim

LABEL org.opencontainers.image.authors="Alejandro Escanero Blanco <alejandro.escanero@disasterproject.com>"

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install --no-install-recommends -y \
        slapd ldap-utils gettext-base procps ca-certificates && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* && \
    mv /etc/ldap /etc/openldap && \
    rm -f /var/lib/ldap/*

COPY --from=builder /data/micropki /.

USER 1001

WORKDIR /

ENTRYPOINT ["/micropki"]
CMD ["ca","new"]
