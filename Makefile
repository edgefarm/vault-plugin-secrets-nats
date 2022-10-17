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
	GOOS=$(OS) GOARCH="$(GOARCH)" go build -o vault/plugins/vault-plugin-secrets-nats cmd/vault-plugin-secrets-nats/main.go

start:
	vault server -dev -dev-root-token-id=root -dev-plugin-dir=./vault/plugins

enable:
	vault secrets enable -path=nats-secrets vault-plugin-secrets-nats

clean:
	rm -f ./vault/plugins/vault-plugin-secrets-nats

fmt:
	go fmt $$(go list ./...)

.PHONY: build clean fmt start enable
