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

DOCKER_REGISTRY ?= siredmar
VERSION ?= $(shell git describe --tags --always --dirty)

generate:
	go generate ./...

all: fmt build start

build: generate
	CGO_ENABLED=0 GOOS=$(OS) GOARCH="$(GOARCH)" go build -o build/vault/plugins/vault-plugin-secrets-nats-$(OS)-$(GOARCH) -gcflags "all=-N -l" -ldflags '-extldflags "-static"' cmd/vault-plugin-secrets-nats/main.go

docker: build
	docker build -t $(DOCKER_REGISTRY)/vault-with-nats-secrets:$(VERSION) -f build/vault/Dockerfile .

push: docker
	docker push $(DOCKER_REGISTRY)/vault-with-nats-secrets:$(VERSION)

start:
	vault server -dev -dev-root-token-id=root -dev-plugin-dir=./build/vault/plugins -log-level=trace -dev-listen-address=127.0.0.1:8200

enable:
	VAULT_ADDR='http://127.0.0.1:8200' vault secrets enable -path=nats-secrets vault-plugin-secrets-nats

clean:
	rm -f ./build/vault/plugins/vault-plugin-secrets-nats-*

fmt:
	go fmt $$(go list ./...)

test:
	go clean -testcache
	go test ./...
	go vet ./...


e2e:
	hack/e2e_script.sh

.PHONY: build clean fmt start enable test generate
