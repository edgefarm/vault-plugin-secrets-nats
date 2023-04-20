package natsbackend

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/edgefarm/vault-plugin-secrets-nats/pkg/stm"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// natsBackend defines an object that
// extends the Vault backend and stores the
// target API's client.
type NatsBackend struct {
	*framework.Backend
	lock   sync.RWMutex
	client *NatsClient
}

func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := backend()
	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}
	return b, nil
}

// backend defines the target API backend
// for Vault. It must include each path
// and the secrets it will store.
func backend() *NatsBackend {
	var b = NatsBackend{}

	b.Backend = &framework.Backend{
		Help: strings.TrimSpace(backendHelp),
		PathsSpecial: &logical.Paths{
			LocalStorage: []string{},
			SealWrapStorage: []string{
				"config",
				"role/*",
			},
		},
		Paths: framework.PathAppend(
			pathNkey(&b),
			pathJWT(&b),
			pathIssue(&b),
			pathCreds(&b),
			[]*framework.Path{},
		),
		Secrets: []*framework.Secret{
			// b.hashiCupsToken(),
		},
		BackendType:       logical.TypeLogical,
		Invalidate:        b.invalidate,
		WALRollbackMinAge: 30 * time.Second,
		PeriodicFunc:      b.periodicFunc,
	}
	return &b
}

// backendHelp should contain help information for the backend
const backendHelp = `
The HashiCups secrets backend dynamically generates user tokens.
After mounting this backend, credentials to manage HashiCups user tokens
must be configured with the "config/" endpoints.
`

// reset clears any client configuration for a new
// backend to be configured
func (b *NatsBackend) reset() {
	b.lock.Lock()
	defer b.lock.Unlock()
	b.client = nil
}

// invalidate clears an existing client configuration in
// the backend
func (b *NatsBackend) invalidate(ctx context.Context, key string) {
	if key == "config" {
		b.reset()
	}
}

// getClient locks the backend as it configures and creates a
// a new client for the target API
func (b *NatsBackend) getClient(ctx context.Context, s logical.Storage) (*NatsClient, error) {
	b.lock.RLock()
	unlockFunc := b.lock.RUnlock
	defer func() { unlockFunc() }()

	if b.client != nil {
		return b.client, nil
	}

	b.lock.RUnlock()
	b.lock.Lock()
	unlockFunc = b.lock.Unlock
	return b.client, nil
}

func (b *NatsBackend) put(ctx context.Context, s logical.Storage, path string, data interface{}) error {
	b.lock.Lock()
	defer b.lock.Unlock()

	entry, err := logical.StorageEntryJSON(path, data)
	if err != nil {
		return fmt.Errorf("error creating storage entry: %w", err)
	}

	if err := s.Put(ctx, entry); err != nil {
		return fmt.Errorf("error writing to backend: %w", err)
	}

	return nil
}

func getFromStorage[T any](ctx context.Context, s logical.Storage, path string) (*T, error) {
	if path == "" {
		return nil, fmt.Errorf("missing path")
	}

	// get data entry from storage backend
	entry, err := s.Get(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("error retrieving Data: %w", err)
	}

	if entry == nil {
		return nil, nil
	}

	// convert json data to T
	var t T
	if err := entry.DecodeJSON(&t); err != nil {
		return nil, fmt.Errorf("error decoding JWT data: %w", err)
	}
	return &t, nil
}

func deleteFromStorage(ctx context.Context, s logical.Storage, path string) error {
	if err := s.Delete(ctx, path); err != nil {
		return fmt.Errorf("error deleting data: %w", err)
	}
	return nil
}

func storeInStorage[T any](ctx context.Context, s logical.Storage, path string, t *T) error {
	entry, err := logical.StorageEntryJSON(path, t)
	if err != nil {
		return err
	}

	if err := s.Put(ctx, entry); err != nil {
		return err
	}

	return nil
}

func readOperation[T any](ctx context.Context, s logical.Storage, path string) (*logical.Response, error) {
	t, err := getFromStorage[T](ctx, s, path)
	if err != nil {
		return nil, err
	}

	if t == nil {
		return nil, nil
	}

	var groupMap map[string]interface{}
	err = stm.StructToMap(t, &groupMap)
	if err != nil {
		return nil, err
	}

	return &logical.Response{
		Data: groupMap,
	}, nil
}

func (b *NatsBackend) periodicFunc(ctx context.Context, sys *logical.Request) error {
	b.Logger().Info("Periodic: starting periodic func for syncing accounts to nats")
	operators, err := listOperatorIssues(ctx, sys.Storage)
	if err != nil {
		return err
	}
	for _, operator := range operators {
		operatorIssue, err := readOperatorIssue(ctx, sys.Storage, IssueOperatorParameters{
			Operator: operator,
		})
		if err != nil {
			return err
		}
		if operatorIssue != nil {
			if !operatorIssue.SyncAccountServer {
				b.Logger().Info(fmt.Sprintf("Periodic: operator %s not configured for auto syncing to account server", operator))
			}
			b.Logger().Debug(fmt.Sprintf("Periodic: operator %s selected for auto sync to account server", operator))
			accountNames, err := listAccountIssues(ctx, sys.Storage, operator)
			if err != nil {
				return err
			}
			for _, account := range accountNames {
				b.Logger().Debug(fmt.Sprintf("Periodic: account %s in operator %s syncing to acount server", account, operator))
				accountIssue, err := readAccountIssue(ctx, sys.Storage, IssueAccountParameters{
					Operator: operator,
					Account:  account,
				})
				if err != nil {
					return err
				}
				err = refreshAccountResolver(ctx, sys.Storage, accountIssue, "push")
				if err != nil {
					return err
				}
			}
		}

	}
	return nil
}
