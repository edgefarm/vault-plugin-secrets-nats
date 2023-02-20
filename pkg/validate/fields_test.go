package validate

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestCmdAccount mocks the read
// of the account configuration for Nats.
func TestValidateFieldsPositive(t *testing.T) {
	valid := []string{"a", "b", "c"}
	data := map[string]interface{}{"a": "a", "b": "b", "c": "c"}
	err := ValidateFields(data, valid)
	assert.NoError(t, err)
}

func TestValidateFieldsNegative(t *testing.T) {
	valid := []string{"a", "z", "c"}
	data := map[string]interface{}{"a": "a", "b": "b", "c": "c"}
	err := ValidateFields(data, valid)
	assert.Error(t, err)
	assert.EqualError(t, err, "invalid keys: \"b\"")
}
