package v1alpha1

import (
	"github.com/edgefarm/vault-plugin-secrets-nats/pkg/claims/common"
)

// UserClaims defines a user JWT
// +kubebuilder:object:generate=true
type UserClaims struct {
	common.ClaimsData `json:",inline"`
	User              `json:"user,omitempty"`
}

type User struct {
	UserPermissionLimits `json:",inline"`
	IssuerAccount        string `json:"issuerAccount,omitempty"`
	common.GenericFields `json:",inline"`
}

type UserPermissionLimits struct {
	common.Permissions `json:",inline"`
	Limits             `json:",inline"`
	BearerToken        bool `json:"bearerToken,omitempty"`
	// allowed values STANDARD, WEBSOCKET, LEAFNODE, LEAFNODE_WS, MQTT, MQTT_WS
	AllowedConnectionTypes []string `json:"allowedConnectionTypes,omitempty"`
}

type Limits struct {
	UserLimits        `json:",inline"`
	common.NatsLimits `json:",inline"`
}

type UserLimits struct {
	Src    []string    `json:"src,omitempty"`
	Times  []TimeRange `json:"times,omitempty"`
	Locale string      `json:"timesLocation,omitempty"`
}

type TimeRange struct {
	Start string `json:"start,omitempty"`
	End   string `json:"end,omitempty"`
}
