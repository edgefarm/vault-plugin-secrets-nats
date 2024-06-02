//go:build generate

package natsbackend

// Generate deepcopy methodsets
//go:generate env GOOS=linux GOARCH=amd64 go run -tags generate sigs.k8s.io/controller-tools/cmd/controller-gen object:headerFile=./hack/boilerplate.go.txt paths=./...

import (
	_ "sigs.k8s.io/controller-tools/cmd/controller-gen" //nolint:typecheck
)
