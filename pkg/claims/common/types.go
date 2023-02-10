package common

type GenericFields struct {
	Tags    []string `json:"tags,omitempty"`
	Type    string   `json:"type,omitempty"`
	Version int      `json:"version,omitempty"`
}

type Info struct {
	Description string `json:"description,omitempty"`
	InfoURL     string `json:"infoURL,omitempty"`
}

type ClaimsData struct {
	Audience  string `json:"aud,omitempty"`
	Expires   int64  `json:"exp,omitempty"`
	ID        string `json:"jti,omitempty"`
	IssuedAt  int64  `json:"iat,omitempty"`
	Issuer    string `json:"iss,omitempty"`
	Name      string `json:"name,omitempty"`
	NotBefore int64  `json:"nbf,omitempty"`
	Subject   string `json:"sub,omitempty"`
}

type Permissions struct {
	Pub  Permission          `json:"pub,omitempty"`
	Sub  Permission          `json:"sub,omitempty"`
	Resp *ResponsePermission `json:"resp,omitempty"`
}

type ResponsePermission struct {
	MaxMsgs int    `json:"max"`
	Expires string `json:"ttl"`
}

// Permission defines allow/deny subjects
type Permission struct {
	Allow []string `json:"allow,omitempty"`
	Deny  []string `json:"deny,omitempty"`
}

type NatsLimits struct {
	Subs    int64 `json:"subs,omitempty"`    // Max number of subscriptions
	Data    int64 `json:"data,omitempty"`    // Max number of bytes
	Payload int64 `json:"payload,omitempty"` // Max message payload
}
