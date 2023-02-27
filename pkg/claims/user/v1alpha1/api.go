package v1alpha1

import (
	"github.com/edgefarm/vault-plugin-secrets-nats/pkg/claims/common"
)

// UserClaims defines a user JWT
// +kubebuilder:object:generate=true
type UserClaims struct {
	// Common data for all JWTs
	common.ClaimsData `json:",inline"`
	// UserClaims is the user specific part of the JWT
	// +kubebuilder:validation:Optional
	User `json:"user,omitempty"`
}

// User holds user specific claims data
type User struct {
	// IssuerAccount is the account that issued this user JWT
	// +kubebuilder:validation:Optional
	IssuerAccount        string `json:"issuerAccount,omitempty"`
	UserPermissionLimits `json:",inline"`
	common.GenericFields `json:",inline"`
}

// UserPermissionLimits defines the permissions and limits for this user
type UserPermissionLimits struct {
	common.Permissions `json:",inline"`
	Limits             `json:",inline"`
	// BearerToken defines if this user is allowed to use a bearer token to connect
	// +kubebuilder:validation:Optional
	BearerToken bool `json:"bearerToken,omitempty"`
	// AllowedConnectionTypes defines the allowed connection types for this user
	// Allowed values are STANDARD, WEBSOCKET, LEAFNODE, LEAFNODE_WS, MQTT, MQTT_WS
	// +kubebuilder:validation:Enum=STANDARD;WEBSOCKET;LEAFNODE;LEAFNODE_WS;MQTT;MQTT_WS
	// +kubebuilder:validation:Optional
	AllowedConnectionTypes []string `json:"allowedConnectionTypes,omitempty"`
}

// Limits defines the limits for this user
type Limits struct {
	UserLimits        `json:",inline"`
	common.NatsLimits `json:",inline"`
}

// UserLimits defines the limits for this user
type UserLimits struct {
	// Src is a list of CIDR specifications the user is allowed to connect from
	// Example: 192.168.1.0/24, 192.168.1.1/1 or 2001:db8:a0b:12f0::1/32
	// +kubebuilder:validation:Optional
	Src []string `json:"src,omitempty"`
	// Times represent allowed time ranges the user is allowed to interact with the system
	Times []TimeRange `json:"times,omitempty"`
	// Locale is the locale for the times in the format "Europe/Berlin"
	// +kubebuilder:validation:Optional
	Locale string `json:"timesLocation,omitempty"`
}

// TimeRange is used to represent a start and end time
type TimeRange struct {
	// Start is the start time in the format HH:MM:SS
	// +kubebuilder:validation:Optional
	Start string `json:"start,omitempty"`
	// End is the end time in the format HH:MM:SS
	// +kubebuilder:validation:Optional
	End string `json:"end,omitempty"`
}
