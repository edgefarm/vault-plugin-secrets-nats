package natsbackend

import (
	"context"
	"errors"
	"testing"

	"github.com/edgefarm/vault-plugin-secrets-nats/pkg/validate"
	"github.com/hashicorp/vault/sdk/logical"
	claim "github.com/nats-io/jwt/v2"
	"github.com/stretchr/testify/assert"
)

func TestCmdAccountInvalidKeys(t *testing.T) {
	b, reqStorage := getTestBackend(t)

	t.Run("Create account with an invalid key", func(t *testing.T) {
		// create a new operator jwt/key
		var err error
		resp, err := b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.CreateOperation,
			Path:      "cmd/operator",
			Data: map[string]interface{}{
				"nkey_id":                  "operator1",
				"operator_signing_keys":    "",
				"strict_signing_key_usage": false,
				"account_server_url":       "http://localhost:9090",
				"system_account":           "sys",
			},

			Storage: reqStorage,
		})
		assert.NoError(t, err)
		assert.NoError(t, resp.Error())

		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.CreateOperation,
			Path:      "cmd/operator/account/invalid",
			Data: map[string]interface{}{
				"nkey_id":        "invalid",
				"my_invalid_key": "invalid_value",
			},
			Storage: reqStorage,
		})
		assert.NoError(t, err)
		assert.Error(t, resp.Error())
		assert.Equal(t, resp.Error().Error(), errors.New(validate.InvalidKeysError+": \"my_invalid_key\"").Error())

	})
}

func TestCmdAccount(t *testing.T) {
	b, reqStorage := getTestBackend(t)

	t.Run("Create account with limits set and default values", func(t *testing.T) {
		// create a new operator jwt/key
		var err error
		resp, err := b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.CreateOperation,
			Path:      "cmd/operator",
			Data: map[string]interface{}{
				"nkey_id":                  "operator1",
				"operator_signing_keys":    "",
				"strict_signing_key_usage": false,
				"account_server_url":       "http://localhost:9090",
				"system_account":           "sys",
			},

			Storage: reqStorage,
		})
		assert.NoError(t, err)
		assert.NoError(t, resp.Error())

		// create account, test setting all fields
		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.CreateOperation,
			Path:      "cmd/operator/account/everything_set",
			Data: map[string]interface{}{
				"nkey_id":                                  "everything_set",
				"limits_nats_subs":                         "10",
				"limits_nats_data":                         "100",
				"limits_nats_payload":                      "200",
				"limits_account_imports":                   "300",
				"limits_account_exports":                   "400",
				"limits_account_wildcards":                 false,
				"limits_account_conn":                      "500",
				"limits_account_leaf":                      "600",
				"limits_jetstream_mem_storage":             "700",
				"limits_jetstream_disk_storage":            "800",
				"limits_jetstream_streams":                 "900",
				"limits_jetstream_consumer":                "1000",
				"limits_jetstream_max_ack_pending":         "1100",
				"limits_jetstream_memory_max_stream_bytes": "1200",
				"limits_jetstream_disk_max_stream_bytes":   "1300",
				"limits_jetstream_max_bytes_required":      true,
			},
			Storage: reqStorage,
		})
		assert.NoError(t, err)
		assert.NoError(t, resp.Error())

		operatorNKeyResp, err := b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ReadOperation,
			Path:      "nkey/operator/operator1",
			Storage:   reqStorage,
		})
		assert.NoError(t, err)
		assert.NoError(t, resp.Error())

		// read account params
		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ReadOperation,
			Path:      "nkey/account/everything_set",
			Storage:   reqStorage,
		})
		assert.NoError(t, err)
		assert.NoError(t, resp.Error())
		accountPubKey := resp.Data["public_key"].(string)

		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ReadOperation,
			Path:      "jwt/operator/account/everything_set",
			Storage:   reqStorage,
		})
		assert.NoError(t, err)
		assert.NoError(t, resp.Error())
		claims, err := claim.Decode(resp.Data["jwt"].(string))
		assert.NoError(t, err)
		accountClaims := claims.(*claim.AccountClaims)
		assert.Equal(t, "everything_set", accountClaims.Name)
		assert.Equal(t, accountPubKey, accountClaims.Subject)
		assert.Equal(t, 2, accountClaims.Version)
		assert.Equal(t, operatorNKeyResp.Data["public_key"].(string), accountClaims.Issuer)
		assert.Equal(t, int64(10), accountClaims.Limits.Subs)
		assert.Equal(t, int64(100), accountClaims.Limits.NatsLimits.Data)
		assert.Equal(t, int64(200), accountClaims.Limits.NatsLimits.Payload)
		assert.Equal(t, int64(300), accountClaims.Limits.AccountLimits.Imports)
		assert.Equal(t, int64(400), accountClaims.Limits.AccountLimits.Exports)
		assert.Equal(t, false, accountClaims.Limits.AccountLimits.WildcardExports)
		assert.Equal(t, int64(500), accountClaims.Limits.AccountLimits.Conn)
		assert.Equal(t, int64(600), accountClaims.Limits.AccountLimits.LeafNodeConn)
		assert.Equal(t, int64(700), accountClaims.Limits.JetStreamLimits.MemoryStorage)
		assert.Equal(t, int64(800), accountClaims.Limits.JetStreamLimits.DiskStorage)
		assert.Equal(t, int64(900), accountClaims.Limits.JetStreamLimits.Streams)
		assert.Equal(t, int64(1000), accountClaims.Limits.JetStreamLimits.Consumer)
		assert.Equal(t, int64(1100), accountClaims.Limits.JetStreamLimits.MaxAckPending)
		assert.Equal(t, int64(1200), accountClaims.Limits.JetStreamLimits.MemoryMaxStreamBytes)
		assert.Equal(t, int64(1300), accountClaims.Limits.JetStreamLimits.DiskMaxStreamBytes)
		assert.Equal(t, true, accountClaims.Limits.JetStreamLimits.MaxBytesRequired)
		// create account, test setting no fields
		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.CreateOperation,
			Path:      "cmd/operator/account/default_values",
			Data: map[string]interface{}{
				"nkey_id": "default_values",
			},
			Storage: reqStorage,
		})
		assert.NoError(t, err)
		assert.NoError(t, resp.Error())

		// read account params
		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ReadOperation,
			Path:      "nkey/account/default_values",
			Storage:   reqStorage,
		})
		assert.NoError(t, err)
		assert.NoError(t, resp.Error())
		accountPubKey = resp.Data["public_key"].(string)

		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ReadOperation,
			Path:      "jwt/operator/account/default_values",
			Storage:   reqStorage,
		})
		assert.NoError(t, err)
		assert.NoError(t, resp.Error())
		claims, err = claim.Decode(resp.Data["jwt"].(string))
		assert.NoError(t, err)
		accountClaims = claims.(*claim.AccountClaims)
		assert.Equal(t, "default_values", accountClaims.Name)
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

func TestCmdWithMissingOperator(t *testing.T) {
	b, reqStorage := getTestBackend(t)
	t.Run("Create account with missing operator", func(t *testing.T) {
		resp, err := b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.CreateOperation,
			Path:      "cmd/operator/account/myaccount",
			Data: map[string]interface{}{
				"nkey_id": "myaccount",
			},
			Storage: reqStorage,
		})
		assert.NoError(t, err)
		assert.Error(t, resp.Error())
		assert.Equal(t, resp.Error().Error(), OperatorNotConfiguredError)
	})
}

func TestCmdWithOperatorSigningKeysUsage(t *testing.T) {
	b, reqStorage := getTestBackend(t)
	t.Run("Create account with operator that has signing keys set, no strict signing key usage, using signing key", func(t *testing.T) {
		resp, err := b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.CreateOperation,
			Path:      "nkey/operator/sk1",
			Data:      map[string]interface{}{},
			Storage:   reqStorage,
		})
		assert.NoError(t, err)
		assert.NoError(t, resp.Error())

		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ReadOperation,
			Path:      "nkey/operator/sk1",
			Data:      map[string]interface{}{},
			Storage:   reqStorage,
		})
		assert.NoError(t, err)
		assert.NoError(t, resp.Error())
		sk1 := resp.Data["public_key"].(string)

		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.CreateOperation,
			Path:      "nkey/operator/sk2",
			Data:      map[string]interface{}{},
			Storage:   reqStorage,
		})
		assert.NoError(t, err)
		assert.NoError(t, resp.Error())

		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.CreateOperation,
			Path:      "cmd/operator",
			Data: map[string]interface{}{
				"nkey_id":                  "operator1",
				"operator_signing_keys":    "sk1,sk2",
				"strict_signing_key_usage": false,
				"account_server_url":       "http://localhost:9090",
				"system_account":           "sys",
			},

			Storage: reqStorage,
		})
		assert.NoError(t, err)
		assert.NoError(t, resp.Error())

		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.CreateOperation,
			Path:      "cmd/operator/account/myaccount",
			Data: map[string]interface{}{
				"nkey_id":              "myaccount",
				"operator_signing_key": "sk1",
			},
			Storage: reqStorage,
		})
		assert.NoError(t, err)
		assert.NoError(t, resp.Error())

		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ReadOperation,
			Path:      "nkey/account/myaccount",
			Data:      map[string]interface{}{},
			Storage:   reqStorage,
		})
		assert.NoError(t, err)
		assert.NoError(t, resp.Error())
		accountPubKey := resp.Data["public_key"].(string)

		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ReadOperation,
			Path:      "jwt/operator/account/myaccount",
			Storage:   reqStorage,
		})
		assert.NoError(t, err)
		assert.NoError(t, resp.Error())
		claims, err := claim.Decode(resp.Data["jwt"].(string))
		assert.NoError(t, err)
		accountClaims := claims.(*claim.AccountClaims)
		assert.Equal(t, "myaccount", accountClaims.Name)
		assert.Equal(t, accountPubKey, accountClaims.Subject)
		assert.Equal(t, sk1, accountClaims.Issuer)

	})

	t.Run("Create account with operator that has signing keys set, no strict signing key usage, not using signing key", func(t *testing.T) {
		var err error
		resp, err := b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.CreateOperation,
			Path:      "nkey/operator/sk1",
			Data:      map[string]interface{}{},
			Storage:   reqStorage,
		})
		assert.NoError(t, err)
		assert.NoError(t, resp.Error())

		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.CreateOperation,
			Path:      "nkey/operator/sk2",
			Data:      map[string]interface{}{},
			Storage:   reqStorage,
		})
		assert.NoError(t, err)
		assert.NoError(t, resp.Error())

		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.CreateOperation,
			Path:      "cmd/operator",
			Data: map[string]interface{}{
				"nkey_id":                  "operator1",
				"operator_signing_keys":    "sk1,sk2",
				"strict_signing_key_usage": false,
				"account_server_url":       "http://localhost:9090",
				"system_account":           "sys",
			},

			Storage: reqStorage,
		})
		assert.NoError(t, err)
		assert.NoError(t, resp.Error())

		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ReadOperation,
			Path:      "nkey/operator/operator1",
			Data:      map[string]interface{}{},
			Storage:   reqStorage,
		})
		assert.NoError(t, err)
		assert.NoError(t, resp.Error())
		operator1Key := resp.Data["public_key"].(string)

		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.CreateOperation,
			Path:      "cmd/operator/account/myaccount",
			Data: map[string]interface{}{
				"nkey_id": "myaccount",
			},
			Storage: reqStorage,
		})
		assert.NoError(t, err)
		assert.NoError(t, resp.Error())

		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ReadOperation,
			Path:      "nkey/account/myaccount",
			Data:      map[string]interface{}{},
			Storage:   reqStorage,
		})
		assert.NoError(t, err)
		assert.NoError(t, resp.Error())
		accountPubKey := resp.Data["public_key"].(string)

		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ReadOperation,
			Path:      "jwt/operator/account/myaccount",
			Storage:   reqStorage,
		})
		assert.NoError(t, err)
		assert.NoError(t, resp.Error())
		claims, err := claim.Decode(resp.Data["jwt"].(string))
		assert.NoError(t, err)
		accountClaims := claims.(*claim.AccountClaims)
		assert.Equal(t, "myaccount", accountClaims.Name)
		assert.Equal(t, accountPubKey, accountClaims.Subject)
		assert.Equal(t, operator1Key, accountClaims.Issuer)

	})

	t.Run("Create account with operator that has signing keys set, strict signing key usage set, using signing key, account not providing signing keys", func(t *testing.T) {
		resp, err := b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.CreateOperation,
			Path:      "nkey/operator/sk1",
			Data:      map[string]interface{}{},
			Storage:   reqStorage,
		})
		assert.NoError(t, err)
		assert.NoError(t, resp.Error())

		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.CreateOperation,
			Path:      "nkey/operator/sk2",
			Data:      map[string]interface{}{},
			Storage:   reqStorage,
		})
		assert.NoError(t, err)
		assert.NoError(t, resp.Error())

		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.CreateOperation,
			Path:      "cmd/operator",
			Data: map[string]interface{}{
				"nkey_id":                  "operator1",
				"operator_signing_keys":    "sk1,sk2",
				"strict_signing_key_usage": true,
				"account_server_url":       "http://localhost:9090",
				"system_account":           "sys",
			},
			Storage: reqStorage,
		})
		assert.NoError(t, err)
		assert.NoError(t, resp.Error())

		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.CreateOperation,
			Path:      "cmd/operator/account/myaccount",
			Data: map[string]interface{}{
				"nkey_id":              "myaccount",
				"operator_signing_key": "sk1",
			},
			Storage: reqStorage,
		})
		assert.Error(t, err)
		assert.Equal(t, err.Error(), StrictSigningKeyUsageButNoKeyDefinedError)
		assert.NoError(t, resp.Error())
	})

	t.Run("Create account with operator that has signing keys set, strict signing key usage set, using signing key, account providing signing keys", func(t *testing.T) {
		resp, err := b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.CreateOperation,
			Path:      "nkey/operator/sk1",
			Data:      map[string]interface{}{},
			Storage:   reqStorage,
		})
		assert.NoError(t, err)
		assert.NoError(t, resp.Error())

		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ReadOperation,
			Path:      "nkey/operator/sk1",
			Data:      map[string]interface{}{},
			Storage:   reqStorage,
		})
		assert.NoError(t, err)
		assert.NoError(t, resp.Error())
		sk1 := resp.Data["public_key"].(string)

		_, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.CreateOperation,
			Path:      "nkey/account/ask1",
			Data:      map[string]interface{}{},
			Storage:   reqStorage,
		})
		assert.NoError(t, err)
		assert.NoError(t, resp.Error())

		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ReadOperation,
			Path:      "nkey/account/ask1",
			Data:      map[string]interface{}{},
			Storage:   reqStorage,
		})
		assert.NoError(t, err)
		assert.NoError(t, resp.Error())
		ask1 := resp.Data["public_key"].(string)

		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.CreateOperation,
			Path:      "nkey/operator/sk2",
			Data:      map[string]interface{}{},
			Storage:   reqStorage,
		})
		assert.NoError(t, err)
		assert.NoError(t, resp.Error())

		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.CreateOperation,
			Path:      "cmd/operator",
			Data: map[string]interface{}{
				"nkey_id":                  "operator1",
				"operator_signing_keys":    "sk1,sk2",
				"strict_signing_key_usage": true,
				"account_server_url":       "http://localhost:9090",
				"system_account":           "sys",
			},

			Storage: reqStorage,
		})
		assert.NoError(t, err)
		assert.NoError(t, resp.Error())

		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.CreateOperation,
			Path:      "cmd/operator/account/myaccount",
			Data: map[string]interface{}{
				"nkey_id":              "myaccount",
				"account_signing_keys": "ask1",
				"operator_signing_key": "sk1",
			},
			Storage: reqStorage,
		})
		assert.NoError(t, err)
		assert.NoError(t, resp.Error())

		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ReadOperation,
			Path:      "nkey/account/myaccount",
			Data:      map[string]interface{}{},
			Storage:   reqStorage,
		})
		assert.NoError(t, err)
		assert.NoError(t, resp.Error())
		accountPubKey := resp.Data["public_key"].(string)

		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ReadOperation,
			Path:      "jwt/operator/account/myaccount",
			Storage:   reqStorage,
		})
		assert.NoError(t, err)
		assert.NoError(t, resp.Error())
		claims, err := claim.Decode(resp.Data["jwt"].(string))
		assert.NoError(t, err)
		accountClaims := claims.(*claim.AccountClaims)
		assert.Equal(t, "myaccount", accountClaims.Name)
		assert.Equal(t, accountPubKey, accountClaims.Subject)
		assert.Equal(t, sk1, accountClaims.Issuer)
		assert.Contains(t, accountClaims.SigningKeys, ask1)
	})

	t.Run("Create account with operator that has signing keys set, strict signing key usage set, not using signing key", func(t *testing.T) {
		resp, err := b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.CreateOperation,
			Path:      "nkey/operator/sk1",
			Data:      map[string]interface{}{},
			Storage:   reqStorage,
		})
		assert.NoError(t, err)
		assert.NoError(t, resp.Error())

		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.CreateOperation,
			Path:      "nkey/operator/sk2",
			Data:      map[string]interface{}{},
			Storage:   reqStorage,
		})
		assert.NoError(t, err)
		assert.NoError(t, resp.Error())

		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.CreateOperation,
			Path:      "cmd/operator",
			Data: map[string]interface{}{
				"nkey_id":                  "operator1",
				"operator_signing_keys":    "sk1,sk2",
				"strict_signing_key_usage": true,
				"account_server_url":       "http://localhost:9090",
				"system_account":           "sys",
			},
			Storage: reqStorage,
		})
		assert.NoError(t, err)
		assert.NoError(t, resp.Error())

		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.CreateOperation,
			Path:      "cmd/operator/account/myaccount",
			Data: map[string]interface{}{
				"nkey_id": "myaccount",
			},
			Storage: reqStorage,
		})
		assert.Error(t, err)
		assert.Equal(t, err.Error(), StrictSigningKeyUsageButNoKeyDefinedError)
		assert.NoError(t, resp.Error())
	})
}
