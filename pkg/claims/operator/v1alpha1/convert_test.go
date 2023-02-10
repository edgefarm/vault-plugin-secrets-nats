package v1alpha1

import (
	"testing"

	"github.com/edgefarm/vault-plugin-secrets-nats/pkg/claims/common"
	"github.com/nats-io/jwt/v2"
	"github.com/stretchr/testify/assert"
)

func TestConvert(t *testing.T) {
	assert := assert.New(t)
	claims := &OperatorClaims{
		Operator: Operator{
			SigningKeys:           []string{"sk1", "sk2"},
			AccountServerURL:      "nats://localhost:4222",
			OperatorServiceURLs:   []string{"tls://host:port"},
			SystemAccount:         "systemaccount",
			AssertServerVersion:   "serverversion",
			StrictSigningKeyUsage: true,
			GenericFields: common.GenericFields{
				Tags:    []string{"tag1", "tag2"},
				Type:    "claimtype",
				Version: 100,
			},
		},
	}

	nats := Convert(claims)
	assert.Equal(nats.SigningKeys, jwt.StringList{"sk1", "sk2"})
	assert.Equal(nats.AccountServerURL, "nats://localhost:4222")
	assert.Equal(nats.OperatorServiceURLs, jwt.StringList{"tls://host:port"})
	assert.Equal(nats.SystemAccount, "systemaccount")
	assert.Equal(nats.AssertServerVersion, "serverversion")
	assert.Equal(nats.StrictSigningKeyUsage, true)
	assert.Equal(nats.GenericFields.Tags, jwt.TagList{"tag1", "tag2"})
	assert.Equal(nats.GenericFields.Type, jwt.ClaimType("claimtype"))
	assert.Equal(nats.GenericFields.Version, int(100))
}
