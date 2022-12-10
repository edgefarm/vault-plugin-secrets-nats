package natsbackend

import (
	"context"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func pathIssue(b *NatsBackend) []*framework.Path {
	paths := []*framework.Path{}
	paths = append(paths, pathOperatorIssue(b)...)
	paths = append(paths, pathAccountIssue(b)...)
	paths = append(paths, pathUserIssue(b)...)
	return paths
}

func listIssues(ctx context.Context, storage logical.Storage, path string) ([]string, error) {
	return storage.List(ctx, path)
}
