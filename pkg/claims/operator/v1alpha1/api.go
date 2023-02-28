// +k8s:deepcopy-gen=package
package v1alpha1

import (
	"github.com/edgefarm/vault-plugin-secrets-nats/pkg/claims/common"
)

// +kubebuilder:object:generate=true
// Specifies claims of the JWT
type OperatorClaims struct {
	common.ClaimsData `json:",inline"`
	// Operator specific claims
	// +kubebuilder:validation:Optional
	Operator `json:"operator,omitempty"`
}

// Operator represents JWT claims for an operator.
type Operator struct {
	// Slice of other operator NKey names that can be used to sign on behalf of the main
	// operator identity.
	// +kubebuilder:validation:Optional
	SigningKeys []string `json:"signingKeys,omitempty"`
	// AccountServerURL is a partial URL like "https://host.domain.org:<port>/jwt/v1"
	// tools will use the prefix and build queries by appending /accounts/<account_id>
	// or /operator to the path provided. Note this assumes that the account server
	// can handle requests in a nats-account-server compatible way. See
	// https://github.com/nats-io/nats-account-server.
	// +kubebuilder:validation:Optional
	AccountServerURL string `json:"accountServerUrl,omitempty"`
	// A list of NATS urls (tls://host:port) where tools can connect to the server
	// using proper credentials.
	// +kubebuilder:validation:Optional
	OperatorServiceURLs []string `json:"operatorServiceUrls,omitempty"`
	// Identity of the system account by its name
	// +kubebuilder:validation:Optional
	SystemAccount string `json:"systemAccount,omitempty"`
	// Min Server version
	// +kubebuilder:validation:Optional
	AssertServerVersion string `json:"assertServerVersion,omitempty"`
	// Signing of subordinate objects will require signing keys
	// +kubebuilder:validation:Optional
	StrictSigningKeyUsage bool `json:"strictSigningKeyUsage,omitempty"`
	common.GenericFields  `json:",inline"`
}
