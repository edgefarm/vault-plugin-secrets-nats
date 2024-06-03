#!/bin/sh
set -e
NEXTVERSION=$1
sha256sum build/vault/plugins/vault-plugin-secrets-nats > build/vault/plugins/vault-plugin-secrets-nats.sha256
export SHA256SUM=$(cat build/vault/plugins/vault-plugin-secrets-nats.sha256 | cut -d ' ' -f1)
sed -i "s#sha256: .*#sha256: ${SHA256SUM}#g" README.md
sed -i "s#image: ghcr.io/edgefarm/vault-plugin-secrets-nats/vault-with-nats-secrets:.*#image: ghcr.io/edgefarm/vault-plugin-secrets-nats/vault-with-nats-secrets:${NEXTVERSION}#g" README.md
sed -i "s#sha256: .*#sha256: ${SHA256SUM}#g" dev/manifests/vault/vault.yaml
sed -i "s#image: ghcr.io/edgefarm/vault-plugin-secrets-nats/vault-with-nats-secrets:.*#image: ghcr.io/edgefarm/vault-plugin-secrets-nats/vault-with-nats-secrets:${NEXTVERSION}#g" dev/manifests/vault/vault.yaml
