package natsbackend

import (
	"context"
	"regexp"

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
	l, err := storage.List(ctx, path)
	if err != nil {
		return nil, err
	}
	var issues []string
	re := regexp.MustCompile(`\/`)
	for _, v := range l {
		if !re.Match([]byte(v)) {
			issues = append(issues, v)
		}
	}
	return issues, nil
}
