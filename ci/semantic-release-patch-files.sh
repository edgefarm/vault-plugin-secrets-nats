#!/bin/sh
set -e
NEXTVERSION=$1
for file in build/vault/plugins/vault-plugin-secrets-nats*; do
  sha256sum $file > $file.sha256
    # this is to retain backward compatibility with the old naming convention
    if echo "$file" | grep -q "amd64"; then
        copy $file build/vault/plugins/vault-plugin-secrets-nats
        copy $file.sha256 build/vault/plugins/vault-plugin-secrets-nats.sha256
    fi
done
# only use x86 for the README.md and dev/manifests/vault/vault.yaml
export SHA256SUM=$(cat build/vault/plugins/vault-plugin-secrets-nats.sha256 | cut -d ' ' -f1)
sed -i "s#sha256: .*#sha256: ${SHA256SUM}#g" README.md
sed -i "s#image: ghcr.io/edgefarm/vault-plugin-secrets-nats/vault-with-nats-secrets:.*#image: ghcr.io/edgefarm/vault-plugin-secrets-nats/vault-with-nats-secrets:${NEXTVERSION}#g" README.md
sed -i "s#sha256: .*#sha256: ${SHA256SUM}#g" dev/manifests/vault/vault.yaml
sed -i "s#image: ghcr.io/edgefarm/vault-plugin-secrets-nats/vault-with-nats-secrets:.*#image: ghcr.io/edgefarm/vault-plugin-secrets-nats/vault-with-nats-secrets:${NEXTVERSION}#g" dev/manifests/vault/vault.yaml
