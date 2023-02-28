package v1alpha1

import (
	"github.com/edgefarm/vault-plugin-secrets-nats/pkg/claims/common"
)

// Specifies claims of the JWT
// +kubebuilder:object:generate=true
type UserClaims struct {
	// Common data for all JWTs
	common.ClaimsData `json:",inline"`
	// Specifies the user specific part of the JWT
	// +kubebuilder:validation:Optional
	User `json:"user,omitempty"`
}

// User holds user specific claims data
type User struct {
	// The account that issued this user JWT
	// +kubebuilder:validation:Optional
	IssuerAccount        string `json:"issuerAccount,omitempty"`
	UserPermissionLimits `json:",inline"`
	common.GenericFields `json:",inline"`
}

// UserPermissionLimits Specifies the permissions and limits for this user
type UserPermissionLimits struct {
	common.Permissions `json:",inline"`
	Limits             `json:",inline"`
	// Specifies if this user is allowed to use a bearer token to connect
	// +kubebuilder:validation:Optional
	BearerToken bool `json:"bearerToken,omitempty"`
	// Specifies the allowed connection types for this user
	// Allowed values are STANDARD, WEBSOCKET, LEAFNODE, LEAFNODE_WS, MQTT, MQTT_WS
	// +kubebuilder:validation:Enum=STANDARD;WEBSOCKET;LEAFNODE;LEAFNODE_WS;MQTT;MQTT_WS
	// +kubebuilder:validation:Optional
	AllowedConnectionTypes []string `json:"allowedConnectionTypes,omitempty"`
}

// Limits Specifies the limits for this user
type Limits struct {
	UserLimits        `json:",inline"`
	common.NatsLimits `json:",inline"`
}

// UserLimits Specifies the limits for this user
type UserLimits struct {
	// A list of CIDR specifications the user is allowed to connect from
	// Example: 192.168.1.0/24, 192.168.1.1/1 or 2001:db8:a0b:12f0::1/32
	// +kubebuilder:validation:Optional
	Src []string `json:"src,omitempty"`
	// Represents allowed time ranges the user is allowed to interact with the system
	Times []TimeRange `json:"times,omitempty"`
	// The locale for the times in the format "Europe/Berlin"
	// +kubebuilder:validation:Optional
	Locale string `json:"timesLocation,omitempty"`
}

type TimeRange struct {
	// The start time in the format HH:MM:SS
	// +kubebuilder:validation:Pattern="^(((([0-1][0-9])|(2[0-3])):?[0-5][0-9]:?[0-5][0-9]+$))"
	// +kubebuilder:validation:Optional
	Start string `json:"start,omitempty"`
	// The end time in the format HH:MM:SS
	// +kubebuilder:validation:Pattern="^(((([0-1][0-9])|(2[0-3])):?[0-5][0-9]:?[0-5][0-9]+$))"
	// +kubebuilder:validation:Optional
	End string `json:"end,omitempty"`
}
