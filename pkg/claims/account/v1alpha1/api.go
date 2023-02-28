/*
Copyright 2023 The EdgeFarm Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1alpha1

import (
	"fmt"

	"github.com/edgefarm/vault-plugin-secrets-nats/pkg/claims/common"
	"github.com/nats-io/jwt/v2"
)

// +kubebuilder:object:generate=true
// Specifies claims of the JWT
type AccountClaims struct {
	// Common data for all JWTs
	common.ClaimsData `json:",inline"`
	// Account specific claims
	// +kubebuilder:validation:Optional
	Account `json:"account,omitempty"`
}

// Specifies account specific claims data
type Account struct {
	// A list of account/subject combinations that this account is allowed to import
	// +kubebuilder:validation:Optional
	Imports []Import `json:"imports,omitempty"`
	// A list of account/subject combinations that this account is allowed to export
	// +kubebuilder:validation:Optional
	Exports []Export `json:"exports,omitempty"`
	// A set of limits for this account
	// +kubebuilder:validation:Optional
	Limits OperatorLimits `json:"limits,omitempty"`
	// A list of signing keys the account can use
	// +kubebuilder:validation:Optional
	SigningKeys []string `json:"signingKeys,omitempty"`
	// Stores user JWTs that have been revoked and the time they were revoked
	// +kubebuilder:validation:Optional
	Revocations map[string]int64 `json:"revocations,omitempty"`
	// Default pub/sub permissions for this account that users inherit
	// +kubebuilder:validation:Optional
	DefaultPermissions common.Permissions `json:"defaultPermissions,omitempty"`
	// Stores subjects that get mapped to other subjects using a weighted mapping.
	// For more information see https://docs.nats.io/nats-concepts/subject_mapping
	// +kubebuilder:validation:Optional
	Mappings             map[string][]WeightedMapping `json:"mappings,omitempty"`
	common.Info          `json:",inline"`
	common.GenericFields `json:",inline"`
}

// WeightedMapping is a mapping from one subject to another with a weight and a destination cluster
type WeightedMapping struct {
	// The subject to map to
	Subject string `json:"subject"`
	// The amount of 100% that this mapping should be used
	// +kubebuilder:validation:Optional
	Weight uint8 `json:"weight,omitempty"`
	// The cluster to map to
	// +kubebuilder:validation:Optional
	Cluster string `json:"cluster,omitempty"`
}

// OperatorLimits represents the limits for that are set on an account
type OperatorLimits struct {
	common.NatsLimits `json:",inline"`
	AccountLimits     `json:",inline"`
	JetStreamLimits   `json:",inline"`
	// JetStreamTieredLimits as far as i can tell it is only used by NATS internally.
	// So not exposed to the user for now.
	// JetStreamTieredLimits `json:"tieredLimits,omitempty"`
}

// JetStreamTieredLimits as far as i can tell it is only used by NATS internally.
// So not exposed to the user for now.
// type JetStreamTieredLimits map[string]JetStreamLimits

// JetStreamLimits represents the Jetstream limits for an account
type JetStreamLimits struct {
	// Max number of bytes stored in memory across all streams. (0 means disabled)
	// +kubebuilder:validation:Optional
	MemoryStorage int64 `json:"memStorage,omitempty"`
	// Max number of bytes stored on disk across all streams. (0 means disabled)
	// +kubebuilder:validation:Optional
	DiskStorage int64 `json:"diskStorage,omitempty"`
	// Max number of streams
	// +kubebuilder:validation:Optional
	Streams int64 `json:"streams,omitempty"`
	// Max number of consumers
	// +kubebuilder:validation:Optional
	Consumer int64 `json:"consumer,omitempty"`
	// Max number of acks pending
	// +kubebuilder:validation:Optional
	MaxAckPending int64 `json:"maxAckPending,omitempty"`
	// Max number of bytes a stream can have in memory. (0 means unlimited)
	// +kubebuilder:validation:Optional
	// +kubebuilder:default=0
	MemoryMaxStreamBytes int64 `json:"memMaxStreamBytes,omitempty"`
	// Max number of bytes a stream can have on disk. (0 means unlimited)
	// +kubebuilder:validation:Optional
	// +kubebuilder:default=0
	DiskMaxStreamBytes int64 `json:"diskMaxStreamBytes,omitempty"`
	// Max bytes required by all Streams
	// +kubebuilder:validation:Optional
	MaxBytesRequired bool `json:"maxBytesRequired,omitempty"`
}

type AccountLimits struct {
	// Max number of imports
	// +kubebuilder:validation:Optional
	Imports int64 `json:"imports,omitempty"`
	// Max number of exports
	// +kubebuilder:validation:Optional
	Exports int64 `json:"exports,omitempty"`
	// Specifies if wildcards are allowed in exports
	// +kubebuilder:validation:Optional
	WildcardExports bool `json:"wildcardExports,omitempty"`
	// Specifies that user JWT can't be bearer token
	// +kubebuilder:validation:Optional
	DisallowBearer bool `json:"disallowBearer,omitempty"`
	// Max number of connections
	// +kubebuilder:validation:Optional
	Conn int64 `json:"conn,omitempty"`
	// Max number of leaf node connections
	// +kubebuilder:validation:Optional
	LeafNodeConn int64 `json:"leafNodeConn,omitempty"`
}

func convertExportType(t string) (jwt.ExportType, error) {
	switch t {
	case "Stream":
		return jwt.Stream, nil
	case "Service":
		return jwt.Service, nil
	case "Unknown":
		return jwt.Unknown, nil
	default:
		return -1, fmt.Errorf("invalid export type")
	}
}

// Import describes a mapping from another account into this one
type Import struct {
	// The name of the import
	// +kubebuilder:validation:Optional
	Name string `json:"name,omitempty"`
	// The subject to import
	// +kubebuilder:validation:Optional
	Subject string `json:"subject,omitempty"`
	// The account to import from
	// +kubebuilder:validation:Optional
	Account string `json:"account,omitempty"`
	// The token to use for the import
	// +kubebuilder:validation:Optional
	Token string `json:"token,omitempty"`
	// The local subject to import to
	// +kubebuilder:validation:Optional
	LocalSubject string `json:"localSubject,omitempty"`
	// The type of the import
	// +kubebuilder:validation:Optional
	Type string `json:"type,omitempty"`
	// Specifies if the import is shared
	// +kubebuilder:validation:Optional
	Share bool `json:"share,omitempty"`
}

// Export describes a mapping from this account to another one
type Export struct {
	// The name of the export
	// +kubebuilder:validation:Optional
	Name string `json:"name,omitempty"`
	// The subject to export
	// +kubebuilder:validation:Optional
	Subject string `json:"subject,omitempty"`
	// The type of the export
	// +kubebuilder:validation:Optional
	Type string `json:"type,omitempty"`
	// Specifies if a token is required for the export
	// +kubebuilder:validation:Optional
	TokenReq bool `json:"tokenReq,omitempty"`
	// The revocations for the export
	// +kubebuilder:validation:Optional
	Revocations map[string]int64 `json:"revocations,omitempty"`
	// The response type for the export
	// +kubebuilder:validation:Optional
	ResponseType string `json:"responseType,omitempty"`
	// The response threshold for the export
	// +kubebuilder:validation:Optional
	ResponseThreshold string `json:"responseThreshold,omitempty"`
	// The latency for the export.
	// +kubebuilder:validation:Optional
	Latency *ServiceLatency `json:"serviceLatency,omitempty"`
	// The account token position for the export
	// +kubebuilder:validation:Optional
	AccountTokenPosition uint `json:"accountTokenPosition,omitempty"`
	// Specifies if the export is advertised
	// +kubebuilder:validation:Optional
	Advertise   bool `json:"advertise,omitempty"`
	common.Info `json:",inline"`
}

type ServiceLatency struct {
	// Specifies the sampling for the latency
	Sampling int `json:"sampling"`
	// Specifies the results for the latency
	Results string `json:"results"`
}
