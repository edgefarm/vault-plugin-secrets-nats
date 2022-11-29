package natsbackend

import (
	"context"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
	claim "github.com/nats-io/jwt/v2"
	"github.com/stretchr/testify/assert"
)

// TestCmdAccount mocks the read
// of the account configuration for Nats.
func TestCmdOperatorSpecificSysaccount(t *testing.T) {
	b, reqStorage := getTestBackend(t)

	t.Run("Create operator with provided sysaccount name", func(t *testing.T) {
		// create a new operator jwt/key
		var err error
		_, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.CreateOperation,
			Path:      "cmd/operator",
			Data: map[string]interface{}{
				"nkey_id":                  "myoperator",
				"operator_signing_keys":    "",
				"strict_signing_key_usage": false,
				"account_server_url":       "http://localhost:9090",
				"system_account":           "mysys",
			},

			Storage: reqStorage,
		})
		assert.NoError(t, err)

		operatorNKeyResp, err := b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ReadOperation,
			Path:      "nkey/operator/myoperator",
			Storage:   reqStorage,
		})
		assert.NoError(t, err)

		// read account params
		resp, err := b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ReadOperation,
			Path:      "nkey/account/mysys",
			Storage:   reqStorage,
		})
		assert.NoError(t, err)
		accountPubKey := resp.Data["public_key"].(string)

		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ReadOperation,
			Path:      "jwt/operator/account/mysys",
			Storage:   reqStorage,
		})
		assert.NoError(t, err)
		claims, err := claim.Decode(resp.Data["jwt"].(string))
		assert.NoError(t, err)
		accountClaims := claims.(*claim.AccountClaims)
		assert.Equal(t, "mysys", accountClaims.Name)
		assert.Equal(t, accountPubKey, accountClaims.Subject)
		assert.Equal(t, 2, accountClaims.Version)
		assert.Equal(t, operatorNKeyResp.Data["public_key"].(string), accountClaims.Issuer)
		assert.Equal(t, int64(-1), accountClaims.Limits.Subs)
		assert.Equal(t, int64(-1), accountClaims.Limits.NatsLimits.Data)
		assert.Equal(t, int64(-1), accountClaims.Limits.NatsLimits.Payload)
		assert.Equal(t, int64(-1), accountClaims.Limits.AccountLimits.Imports)
		assert.Equal(t, int64(-1), accountClaims.Limits.AccountLimits.Exports)
		assert.Equal(t, true, accountClaims.Limits.AccountLimits.WildcardExports)
		assert.Equal(t, int64(-1), accountClaims.Limits.AccountLimits.Conn)
		assert.Equal(t, int64(-1), accountClaims.Limits.AccountLimits.LeafNodeConn)
		assert.Equal(t, int64(-1), accountClaims.Limits.JetStreamLimits.MemoryStorage)
		assert.Equal(t, int64(-1), accountClaims.Limits.JetStreamLimits.DiskStorage)
		assert.Equal(t, int64(-1), accountClaims.Limits.JetStreamLimits.Streams)
		assert.Equal(t, int64(-1), accountClaims.Limits.JetStreamLimits.Consumer)
		assert.Equal(t, int64(-1), accountClaims.Limits.JetStreamLimits.MaxAckPending)
		assert.Equal(t, int64(0), accountClaims.Limits.JetStreamLimits.MemoryMaxStreamBytes)
		assert.Equal(t, int64(0), accountClaims.Limits.JetStreamLimits.DiskMaxStreamBytes)
		assert.Equal(t, false, accountClaims.Limits.JetStreamLimits.MaxBytesRequired)
	})
}

func TestCmdOperatorDefaultSysaccount(t *testing.T) {
	b, reqStorage := getTestBackend(t)

	t.Run("Create operator with default sysaccount name", func(t *testing.T) {
		var err error
		_, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.CreateOperation,
			Path:      "cmd/operator",
			Data: map[string]interface{}{
				"nkey_id":                  "myoperator",
				"operator_signing_keys":    "",
				"strict_signing_key_usage": false,
				"account_server_url":       "http://localhost:9090",
			},

			Storage: reqStorage,
		})
		assert.NoError(t, err)

		operatorNKeyResp, err := b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ReadOperation,
			Path:      "nkey/operator/myoperator",
			Storage:   reqStorage,
		})
		assert.NoError(t, err)

		// read account params
		resp, err := b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ReadOperation,
			Path:      "nkey/account/SYS",
			Storage:   reqStorage,
		})
		assert.NoError(t, err)
		accountPubKey := resp.Data["public_key"].(string)

		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ReadOperation,
			Path:      "jwt/operator/account/SYS",
			Storage:   reqStorage,
		})
		assert.NoError(t, err)
		claims, err := claim.Decode(resp.Data["jwt"].(string))
		assert.NoError(t, err)
		accountClaims := claims.(*claim.AccountClaims)
		assert.Equal(t, "SYS", accountClaims.Name)
		assert.Equal(t, accountPubKey, accountClaims.Subject)
		assert.Equal(t, 2, accountClaims.Version)
		assert.Equal(t, operatorNKeyResp.Data["public_key"].(string), accountClaims.Issuer)
		assert.Equal(t, int64(-1), accountClaims.Limits.Subs)
		assert.Equal(t, int64(-1), accountClaims.Limits.NatsLimits.Data)
		assert.Equal(t, int64(-1), accountClaims.Limits.NatsLimits.Payload)
		assert.Equal(t, int64(-1), accountClaims.Limits.AccountLimits.Imports)
		assert.Equal(t, int64(-1), accountClaims.Limits.AccountLimits.Exports)
		assert.Equal(t, true, accountClaims.Limits.AccountLimits.WildcardExports)
		assert.Equal(t, int64(-1), accountClaims.Limits.AccountLimits.Conn)
		assert.Equal(t, int64(-1), accountClaims.Limits.AccountLimits.LeafNodeConn)
		assert.Equal(t, int64(-1), accountClaims.Limits.JetStreamLimits.MemoryStorage)
		assert.Equal(t, int64(-1), accountClaims.Limits.JetStreamLimits.DiskStorage)
		assert.Equal(t, int64(-1), accountClaims.Limits.JetStreamLimits.Streams)
		assert.Equal(t, int64(-1), accountClaims.Limits.JetStreamLimits.Consumer)
		assert.Equal(t, int64(-1), accountClaims.Limits.JetStreamLimits.MaxAckPending)
		assert.Equal(t, int64(0), accountClaims.Limits.JetStreamLimits.MemoryMaxStreamBytes)
		assert.Equal(t, int64(0), accountClaims.Limits.JetStreamLimits.DiskMaxStreamBytes)
		assert.Equal(t, false, accountClaims.Limits.JetStreamLimits.MaxBytesRequired)
	})
}

func TestCmdOperatorWithSigningKeysOneDoesNotExist(t *testing.T) {
	b, reqStorage := getTestBackend(t)

	var err error
	_, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "nkey/operator/sk1",
		Data:      map[string]interface{}{},
		Storage:   reqStorage,
	})
	assert.NoError(t, err)

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "cmd/operator",
		Data: map[string]interface{}{
			"nkey_id":                  "myoperator",
			"operator_signing_keys":    "sk1,sk2",
			"strict_signing_key_usage": false,
			"account_server_url":       "http://localhost:9090",
		},

		Storage: reqStorage,
	})
	assert.NoError(t, err)
	assert.Error(t, resp.Error())
	assert.Contains(t, resp.Error().Error(), "sk2")
}

func TestCmdOperatorWithSigningKeysAllExist(t *testing.T) {
	b, reqStorage := getTestBackend(t)

	var err error
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "nkey/operator/sk1",
		Data:      map[string]interface{}{},
		Storage:   reqStorage,
	})
	assert.NoError(t, err)
	assert.NoError(t, resp.Error())

	_, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "nkey/operator/sk2",
		Data:      map[string]interface{}{},
		Storage:   reqStorage,
	})
	assert.NoError(t, err)

	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "cmd/operator",
		Data: map[string]interface{}{
			"nkey_id":                  "myoperator",
			"operator_signing_keys":    "sk1,sk2",
			"strict_signing_key_usage": false,
			"account_server_url":       "http://localhost:9090",
		},

		Storage: reqStorage,
	})
	assert.NoError(t, err)
	assert.NoError(t, resp.Error())
}
