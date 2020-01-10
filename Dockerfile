FROM debian:buster-slim
ARG release

RUN apt update && apt -y install ca-certificates
COPY build/aws-cvpn-pki-manager_amd64_${release} /aws-cvpn-pki-manager

EXPOSE 8080
ENTRYPOINT [ "/aws-cvpn-pki-manager", "server" ]