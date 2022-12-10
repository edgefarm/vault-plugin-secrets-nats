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

account:
	vault write nats-secrets/cmd/operator nkey_id=op
	vault write nats-secrets/cmd/operator/account/myAccount nkey_id=myAccountKey

user:
	vault write nats-secrets/cmd/operator/account/myAccount/user/myuser nkey_id=myuser
	vault read nats-secrets/cmd/operator/account/myAccount/user/myuser

start:
	vault server -dev -dev-root-token-id=root -dev-plugin-dir=./build/vault/plugins -log-level=trace -dev-listen-address=127.0.0.1:8200

enable:
	vault secrets enable -path=nats-secrets vault-plugin-secrets-nats

clean:
	rm -f ./build/vault/plugins/vault-plugin-secrets-nats

fmt:
	go fmt $$(go list ./...)

test:
	go clean -testcache
	go test ./...
	go vet ./...

.PHONY: build clean fmt start enable test
