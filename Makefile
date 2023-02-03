GOARCH = amd64

UNAME = $(shell uname -s)

ifndef OS
	ifeq ($(UNAME), Linux)
		OS = linux
	else ifeq ($(UNAME), Darwin)
		OS = darwin
	endif
endif

.DEFAULT_GOAL := all

all: fmt build start

build:
	GOOS=$(OS) GOARCH="$(GOARCH)" go build -o build/vault/plugins/vault-plugin-secrets-nats -gcflags "all=-N -l" cmd/vault-plugin-secrets-nats/main.go

operator:
	vault write -force nats-secrets/issue/operator/myop
	vault read nats-secrets/issue/operator/myop

sysaccount:
	vault write -force nats-secrets/issue/operator/myop/account/sys
	vault read nats-secrets/issue/operator/myop/account/sys

pushuser:
	vault write -force nats-secrets/issue/operator/myop/account/sys/user/default-push
	vault read nats-secrets/issue/operator/myop/account/sys/user/default-push

account:
	vault write -force nats-secrets/issue/operator/myop/account/myaccount
	vault read nats-secrets/issue/operator/myop/account/myaccount

user:
	vault write -force nats-secrets/issue/operator/myop/account/myaccount/user/myuser
	vault read nats-secrets/issue/operator/myop/account/myaccount/user/myuser

start:
	vault server -dev -dev-root-token-id=root -dev-plugin-dir=./build/vault/plugins -log-level=trace -dev-listen-address=127.0.0.1:8200

enable:
	VAULT_ADDR='http://127.0.0.1:8200' vault secrets enable -path=nats-secrets vault-plugin-secrets-nats

clean:
	rm -f ./build/vault/plugins/vault-plugin-secrets-nats

fmt:
	go fmt $$(go list ./...)

test:
	go clean -testcache
	go test ./...
	go vet ./...

.PHONY: build clean fmt start enable test
