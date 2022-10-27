package natsbackend

import (
	"context"
	"fmt"
	"strings"
	"sync"

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
			[]*framework.Path{},
		),
		Secrets: []*framework.Secret{
			// b.hashiCupsToken(),
		},
		BackendType: logical.TypeLogical,
		Invalidate:  b.invalidate,
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
