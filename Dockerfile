FROM golang:1.23 AS builder

WORKDIR /app/
ADD . .
RUN CGO_ENABLED=0 GOOS=linux \
  go build -ldflags '-extldflags "-static"' \
  -o aws-cvpn-pki-manager cmd/main.go

# FROM debian:bullseye-slim
# RUN apt update && apt -y install ca-certificates

FROM alpine:3.20

RUN apk --no-cache add ca-certificates && update-ca-certificates

WORKDIR /app/

COPY --from=builder /app/aws-cvpn-pki-manager /app/aws-cvpn-pki-manager

EXPOSE 8080
ENTRYPOINT [ "/app/aws-cvpn-pki-manager", "server" ]