// +kubebuilder:object:generate=true
package common

// +kubebuilder:object:generate=true
type GenericFields struct {
	// Do not set manually
	// +kubebuilder:validation:Optional
	Tags []string `json:"tags,omitempty"`
	// Do not set manually
	// +kubebuilder:validation:Optional
	Type string `json:"type,omitempty"`
	// Do not set manually
	// +kubebuilder:validation:Optional
	Version int `json:"version,omitempty"`
}

type Info struct {
	// A human readable description
	Description string `json:"description,omitempty"`
	// This is a URL to more information
	InfoURL string `json:"infoURL,omitempty"`
}

type ClaimsData struct {
	// Do not set manually
	Audience string `json:"aud,omitempty"`
	// Do not set manually
	Expires int64 `json:"exp,omitempty"`
	// Do not set manually
	ID string `json:"jti,omitempty"`
	// Do not set manually
	IssuedAt int64 `json:"iat,omitempty"`
	// Do not set manually
	Issuer string `json:"iss,omitempty"`
	// Do not set manually
	Name string `json:"name,omitempty"`
	// Do not set manually
	NotBefore int64 `json:"nbf,omitempty"`
	// Do not set manually
	Subject string `json:"sub,omitempty"`
}

type Permissions struct {
	// Specifies the publish permissions
	// +kubebuilder:validation:Optional
	Pub Permission `json:"pub,omitempty"`
	// Specifies the subscribe permissions
	// +kubebuilder:validation:Optional
	Sub Permission `json:"sub,omitempty"`
	// Specifies the response permissions
	// +kubebuilder:validation:Optional
	Resp *ResponsePermission `json:"resp,omitempty"`
}

// ResponsePermission Specifies the response permissions
type ResponsePermission struct {
	// The maximum number of messages
	MaxMsgs int `json:"max"`
	// Specifies the time to live for the response
	Expires string `json:"ttl"`
}

// Permission Specifies allow/deny subjects
type Permission struct {
	// Specifies allowed subjects
	// +kubebuilder:validation:Optional
	Allow []string `json:"allow,omitempty"`
	// Specifies denied subjects
	// +kubebuilder:validation:Optional
	Deny []string `json:"deny,omitempty"`
}

type NatsLimits struct {
	// Specifies the maximum number of subscriptions
	// +kubebuilder:validation:Optional
	Subs int64 `json:"subs,omitempty"`
	// Specifies the maximum number of bytes
	// +kubebuilder:validation:Optional
	Data int64 `json:"data,omitempty"`
	// Specifies the maximum message payload
	// +kubebuilder:validation:Optional
	Payload int64 `json:"payload,omitempty"`
}
