FROM vault:1.12.3 as builder
RUN mkdir -p /etc/vault/vault_plugins
RUN apk add --no-cache alpine-sdk
COPY --from=golang:1.18.2-alpine3.14 /usr/local/go /usr/local/go
RUN echo $PATH
ENV PATH="$PATH:/usr/local/go/bin"
RUN echo path: $PATH
RUN ls -l /usr/local/go/bin && /usr/local/go/bin/go version
WORKDIR /go/src/app
COPY . .
RUN ls -la
RUN make build && sha256sum /go/src/app/build/vault/plugins/vault-plugin-secrets-nats > /vault-plugin-secrets-nats.sha256

FROM vault:1.12.3
RUN mkdir -p /etc/vault/vault_plugins
RUN mkdir -p /etc/vault/vault_plugins_checksums
COPY --from=builder /vault-plugin-secrets-nats.sha256 /etc/vault/vault_plugins_checksums
RUN cat /etc/vault/vault_plugins_checksums/*
COPY --from=builder /go/src/app/build/vault/plugins/vault-plugin-secrets-nats /etc/vault/vault_plugins

