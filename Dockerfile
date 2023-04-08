FROM docker.io/golang:alpine3.17 AS builder

LABEL org.opencontainers.image.authors="Alejandro Escanero Blanco <alejandro.escanero@disasterproject.com>"

USER 0

RUN apk --no-cache add ca-certificates && mkdir /data

WORKDIR /data/
COPY . .

RUN go build -a -installsuffix cgo -o micropki .

# Use distroless as minimal base image to package the manager binary
# Refer to https://github.com/GoogleContainerTools/distroless for more details
FROM gcr.io/distroless/static:nonroot
LABEL org.opencontainers.image.authors="Alejandro Escanero Blanco <alejandro.escanero@disasterproject.com>"
WORKDIR /
COPY --from=builder /data/micropki /.
USER 65532:65532
ENTRYPOINT ["/micropki"]
CMD ["ca","new"]
