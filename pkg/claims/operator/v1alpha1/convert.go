// +k8s:deepcopy-gen=package
package v1alpha1

import (
	"github.com/edgefarm/vault-plugin-secrets-nats/pkg/claims/common"
	"github.com/nats-io/jwt/v2"
)

func Convert(claims *OperatorClaims) *jwt.OperatorClaims {
	nats := &jwt.OperatorClaims{
		Operator: jwt.Operator{
			SigningKeys:           claims.SigningKeys,
			AccountServerURL:      claims.AccountServerURL,
			OperatorServiceURLs:   claims.OperatorServiceURLs,
			SystemAccount:         claims.SystemAccount,
			AssertServerVersion:   claims.AssertServerVersion,
			StrictSigningKeyUsage: claims.StrictSigningKeyUsage,
		},
	}
	nats.ClaimsData = common.ConvertClaimsData(&claims.ClaimsData)
	nats.GenericFields = common.ConvertGenericFields(&claims.GenericFields)
	return nats
}
