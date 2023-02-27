// +kubebuilder:object:generate=true
package common

// +kubebuilder:object:generate=true
type GenericFields struct {
	// Tags are used to categorize the JWT. Gets set automatically.
	// +kubebuilder:validation:Optional
	Tags []string `json:"tags,omitempty"`
	// Type is the type of the JWT. Gets set automatically.
	// +kubebuilder:validation:Optional
	Type string `json:"type,omitempty"`
	// Version is the version of the JWT. Gets set automatically.
	// +kubebuilder:validation:Optional
	Version int `json:"version,omitempty"`
}

type Info struct {
	// Description is a human readable description
	Description string `json:"description,omitempty"`
	// InfoURL is a URL to more information
	InfoURL string `json:"infoURL,omitempty"`
}

type ClaimsData struct {
	// Audience is the intended audience of the JWT
	Audience string `json:"aud,omitempty"`
	// Expires defines the time to live for the JWT
	Expires int64 `json:"exp,omitempty"`
	// ID is the unique identifier for the JWT
	ID string `json:"jti,omitempty"`
	// IssuedAt defines the time the JWT was issued
	IssuedAt int64 `json:"iat,omitempty"`
	// Issuer is the issuer of the JWT
	Issuer string `json:"iss,omitempty"`
	// Name is a human readable name
	Name string `json:"name,omitempty"`
	// NotBefore defines the time before which the JWT is not valid
	NotBefore int64 `json:"nbf,omitempty"`
	// Subject defines for whom the JWT is intended
	Subject string `json:"sub,omitempty"`
}

type Permissions struct {
	// Pub defines the publish permissions
	// +kubebuilder:validation:Optional
	Pub Permission `json:"pub,omitempty"`
	// Sub defines the subscribe permissions
	// +kubebuilder:validation:Optional
	Sub Permission `json:"sub,omitempty"`
	// Resp defines the response permissions
	// +kubebuilder:validation:Optional
	Resp *ResponsePermission `json:"resp,omitempty"`
}

// ResponsePermission defines the response permissions
type ResponsePermission struct {
	// MaxMsgs is the maximum number of messages
	MaxMsgs int `json:"max"`
	// Expires defines the time to live for the response
	Expires string `json:"ttl"`
}

// Permission defines allow/deny subjects
type Permission struct {
	// Allow defines the subjects that are allowed
	// +kubebuilder:validation:Optional
	Allow []string `json:"allow,omitempty"`
	// Deny defines the subjects that are denied
	// +kubebuilder:validation:Optional
	Deny []string `json:"deny,omitempty"`
}

type NatsLimits struct {
	// Subs defines the maximum number of subscriptions
	// +kubebuilder:validation:Optional
	Subs int64 `json:"subs,omitempty"`
	// Data defines the maximum number of bytes
	// +kubebuilder:validation:Optional
	Data int64 `json:"data,omitempty"`
	// Payload defines the maximum message payload
	// +kubebuilder:validation:Optional
	Payload int64 `json:"payload,omitempty"`
}
