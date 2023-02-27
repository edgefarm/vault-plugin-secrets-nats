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
	CGO_ENABLED=0  GOOS=$(OS) GOARCH="$(GOARCH)" go build -o build/vault/plugins/vault-plugin-secrets-nats -gcflags "all=-N -l" -ldflags '-extldflags "-static"' cmd/vault-plugin-secrets-nats/main.go

docker: build
	docker build -t $(DOCKER_REGISTRY)/vault-plugin-secrets-nats:$(VERSION) -f build/vault/Dockerfile .

push: docker
	docker push $(DOCKER_REGISTRY)/vault-plugin-secrets-nats:$(VERSION)

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

e2e: 
	vault write nats-secrets/issue/operator/myop -<<EOF
	{
		"account_server_url": "nats://localhost:4222", 
		"sync_account_server": true,
		"seed": "U09BSktRT1pVWTJFSTRUUlBPMkhWWE41NzJVRk5CTkRaS0xVRU1HSkNIUDNXTkJVUzczV0hDSVVQVQ=="
	}
	EOF
	vault write nats-secrets/nkey/operator/myop/account/sys seed="U0FBSVZRVEpFTjRGUjRFV00zVU9KWFdIN1JURkRKUVpNQlg0WVNaNkVSR0paNE1IRE5OVEpBQVNYNAo="
	vault write nats-secrets/nkey/operator/myop/account/sys/user/default-push seed="U1VBTjRMVVBFQUVVQUhETUNKWE9FVkVFSklGU1RLSElTWkRPS0RVWUw1Q1NESUhFRk9BUzdWNUg2RQo="
	vault write nats-secrets/jwt/operator/myop/account/sys/user/default-push jwt="eyJ0eXAiOiJKV1QiLCJhbGciOiJlZDI1NTE5LW5rZXkifQ.eyJqdGkiOiIySUE1QTY1VVhISko0WTYyTUZaT1VCNUdWWE81VUQ3STRYSk9SR1E0NFlCVUNJSkFNU1pBIiwiaWF0IjoxNjczODcyNTc1LCJpc3MiOiJBREhUNk4ySVpTV0JRRENOV1dTS1ZHVUhFNDREREdLNTZDUEYySkNIVEQ0UkZFVVJUSkVYUFJCQSIsIm5hbWUiOiJzeXMiLCJzdWIiOiJVQU5HSE02T0xQUDM0RFAzUUhWT05aQ0wyUUpCSEM1UDUzM0RUUFFBNU9QV1UyV1JSTjdOUUtERiIsIm5hdHMiOnsicHViIjp7fSwic3ViIjp7fSwic3VicyI6LTEsImRhdGEiOi0xLCJwYXlsb2FkIjotMSwiaXNzdWVyX2FjY291bnQiOiJBRElVTTIzS0xLUURFNkVQMkZJWkRQSFBERU9VUEgyVUNFNExGVkY0UkpCU1laT1FaTU1BTk8zQiIsInR5cGUiOiJ1c2VyIiwidmVyc2lvbiI6Mn19.z9wQ9INlHW5Bn2JWXPEmlBJtqJ9l3eic6wtIK9f64Wy1-g1SMA7kW3yh1BU7mzfEoBQYsXqMv6gx4SGxlxbfAQ"
	vault write nats-secrets/jwt/operator/myop/account/sys jwt="eyJ0eXAiOiJKV1QiLCJhbGciOiJlZDI1NTE5LW5rZXkifQ.eyJqdGkiOiJaUVJZMjNMR1NCWFM0SUZXQjJKMk9XVk5BN1k3UFJHVEpSSEJLSklWNlFSNFZWT1VWS0NBIiwiaWF0IjoxNjczODcyNTc1LCJpc3MiOiJPRDRIQVBLU0pDUFE2U1c2UjdKU0VWQjNZUks3UlBUVFhXWU81NjZWNEpDTDU2TkpKR0NGQUI2RyIsIm5hbWUiOiJTWVMiLCJzdWIiOiJBRElVTTIzS0xLUURFNkVQMkZJWkRQSFBERU9VUEgyVUNFNExGVkY0UkpCU1laT1FaTU1BTk8zQiIsIm5hdHMiOnsiZXhwb3J0cyI6W3sibmFtZSI6ImFjY291bnQtbW9uaXRvcmluZy1zdHJlYW1zIiwic3ViamVjdCI6IiRTWVMuQUNDT1VOVC4qLlx1MDAzZSIsInR5cGUiOiJzdHJlYW0iLCJhY2NvdW50X3Rva2VuX3Bvc2l0aW9uIjozLCJkZXNjcmlwdGlvbiI6IkFjY291bnQgc3BlY2lmaWMgbW9uaXRvcmluZyBzdHJlYW0iLCJpbmZvX3VybCI6Imh0dHBzOi8vZG9jcy5uYXRzLmlvL25hdHMtc2VydmVyL2NvbmZpZ3VyYXRpb24vc3lzX2FjY291bnRzIn0seyJuYW1lIjoiYWNjb3VudC1tb25pdG9yaW5nLXNlcnZpY2VzIiwic3ViamVjdCI6IiRTWVMuUkVRLkFDQ09VTlQuKi4qIiwidHlwZSI6InNlcnZpY2UiLCJyZXNwb25zZV90eXBlIjoiU3RyZWFtIiwiYWNjb3VudF90b2tlbl9wb3NpdGlvbiI6NCwiZGVzY3JpcHRpb24iOiJSZXF1ZXN0IGFjY291bnQgc3BlY2lmaWMgbW9uaXRvcmluZyBzZXJ2aWNlcyBmb3I6IFNVQlNaLCBDT05OWiwgTEVBRlosIEpTWiBhbmQgSU5GTyIsImluZm9fdXJsIjoiaHR0cHM6Ly9kb2NzLm5hdHMuaW8vbmF0cy1zZXJ2ZXIvY29uZmlndXJhdGlvbi9zeXNfYWNjb3VudHMifV0sImxpbWl0cyI6eyJzdWJzIjotMSwiZGF0YSI6LTEsInBheWxvYWQiOi0xLCJpbXBvcnRzIjotMSwiZXhwb3J0cyI6LTEsIndpbGRjYXJkcyI6dHJ1ZSwiY29ubiI6LTEsImxlYWYiOi0xfSwic2lnbmluZ19rZXlzIjpbIkFESFQ2TjJJWlNXQlFEQ05XV1NLVkdVSEU0NERER0s1NkNQRjJKQ0hURDRSRkVVUlRKRVhQUkJBIl0sImRlZmF1bHRfcGVybWlzc2lvbnMiOnsicHViIjp7fSwic3ViIjp7fX0sInR5cGUiOiJhY2NvdW50IiwidmVyc2lvbiI6Mn19.bSHd7kemlnW1cG4xQXWytLhaUxkwkWQrt6yFel5oDGNYS7Lanv-MyYGZxSqPOC0BVO4jVLbYklg9_0ZFmT9rBw"
	
	vault write nats-secrets/issue/operator/myop -account_server_url="nats://localhost:4222" -sync_account_server=true
	vault write -force nats-secrets/issue/operator/myop/account/ac1
	vault write -force nats-secrets/issue/operator/myop/account/ac1/user/user1

.PHONY: build clean fmt start enable test generate
