package natssecretsengine

import (
	"context"
	"fmt"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/assert"
)

const (
	name = "operator-name"
)

// TestOperator mocks the read
// of the operator configuration for Nats.
func TestOperator(t *testing.T) {
	b, reqStorage := getTestBackend(t)

	t.Run("Test Operator", func(t *testing.T) {

		_, err := testOperatorGenerate(t, b, reqStorage, map[string]interface{}{
			"name": name,
		})

		assert.NoError(t, err)

		err = testOperatorRead(t, b, reqStorage, map[string]interface{}{
			"name": name,
		})

		assert.NoError(t, err)
	})
}

func testOperatorGenerate(t *testing.T, b *natsBackend, s logical.Storage, d map[string]interface{}) (*logical.Response, error) {
	t.Helper()
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "operator/generate",
		Data:      d,
		Storage:   s,
	})

	if err != nil {
		return nil, err
	}

	return resp, nil
}

func testOperatorRead(t *testing.T, b logical.Backend, s logical.Storage, expected map[string]interface{}) error {
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      operatorStoragePath,
		Storage:   s,
	})

	if err != nil {
		return err
	}

	if resp == nil && expected == nil {
		return nil
	}

	if resp.IsError() {
		return resp.Error()
	}

	if len(expected) != len(resp.Data) {
		return fmt.Errorf("read data mismatch (expected %d values, got %d)", len(expected), len(resp.Data))
	}

	t.Log(resp.Data)

	for k, expectedV := range expected {
		actualV, ok := resp.Data[k]

		if !ok {
			return fmt.Errorf(`expected data["%s"] = %v but was not included in read output"`, k, expectedV)
		} else if expectedV != actualV {
			return fmt.Errorf(`expected data["%s"] = %v, instead got %v"`, k, expectedV, actualV)
		}
	}

	return nil
}
