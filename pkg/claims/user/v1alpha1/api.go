package v1alpha1

import (
	"github.com/edgefarm/vault-plugin-secrets-nats/pkg/claims/common"
)

// UserClaims defines a user JWT
type UserClaims struct {
	common.ClaimsData
	User `json:"user,omitempty"`
}

type User struct {
	UserPermissionLimits
	IssuerAccount string `json:"issuerAccount,omitempty"`
	common.GenericFields
}

type UserPermissionLimits struct {
	common.Permissions
	Limits
	BearerToken bool `json:"bearerToken,omitempty"`
	// allowed values STANDARD, WEBSOCKET, LEAFNODE, LEAFNODE_WS, MQTT, MQTT_WS
	AllowedConnectionTypes []string `json:"allowedConnectionTypes,omitempty"`
}

type Limits struct {
	UserLimits
	common.NatsLimits
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
