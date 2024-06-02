FROM vault:1.12.5
RUN mkdir -p /etc/vault/vault_plugins
RUN mkdir -p /etc/vault/vault_plugins_checksums
COPY build/vault/plugins/vault-plugin-secrets-nats-linux-amd64 /etc/vault/vault_plugins
RUN sha256sum /etc/vault/vault_plugins/vault-plugin-secrets-nats-linux-amd64 > /etc/vault/vault_plugins_checksums/vault-plugin-secrets-nats.sha256
RUN cat /etc/vault/vault_plugins_checksums/*

