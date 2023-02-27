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
// AccountClaims is the top level JWT claims for an account
type AccountClaims struct {
	// Common data for all JWTs
	common.ClaimsData `json:",inline"`
	// Account specific claims
	// +kubebuilder:validation:Optional
	Account `json:"account,omitempty"`
}

// Account holds account specific claims data
type Account struct {
	// Imports is a list of account/subject combinations that this account is allowed to import
	// +kubebuilder:validation:Optional
	Imports []Import `json:"imports,omitempty"`
	// Exports is a list of account/subject combinations that this account is allowed to export
	// +kubebuilder:validation:Optional
	Exports []Export `json:"exports,omitempty"`
	// Limits is a set of limits for this account
	// +kubebuilder:validation:Optional
	Limits OperatorLimits `json:"limits,omitempty"`
	// SigningKeys is a list of signing keys the account can use
	// +kubebuilder:validation:Optional
	SigningKeys []string `json:"signingKeys,omitempty"`
	// Revocations stores user JWTs that have been revoked and the time they were revoked
	// +kubebuilder:validation:Optional
	Revocations map[string]int64 `json:"revocations,omitempty"`
	// DefaultPermissions is the default pub/sub permissions for this account that users inherit
	// +kubebuilder:validation:Optional
	DefaultPermissions common.Permissions `json:"defaultPermissions,omitempty"`
	// Mappings stores subjects that get mapped to other subjects using a weighted mapping
	// For more information see https://docs.nats.io/nats-concepts/subject_mapping
	// +kubebuilder:validation:Optional
	Mappings             map[string][]WeightedMapping `json:"mappings,omitempty"`
	common.Info          `json:",inline"`
	common.GenericFields `json:",inline"`
}

// WeightedMapping is a mapping from one subject to another with a weight and a destination cluster
type WeightedMapping struct {
	// Subject is the subject to map to
	Subject string `json:"subject"`
	// Weight is the amount of 100% that this mapping should be used
	// +kubebuilder:validation:Optional
	Weight uint8 `json:"weight,omitempty"`
	// Cluster is the cluster to map to
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
	// MemoryStorage defines them max number of bytes stored in memory across all streams. (0 means disabled)
	// +kubebuilder:validation:Optional
	MemoryStorage int64 `json:"memStorage,omitempty"`
	// DisksStorage defines them max number of bytes stored on disk across all streams. (0 means disabled)
	// +kubebuilder:validation:Optional
	DiskStorage int64 `json:"diskStorage,omitempty"`
	// Streams defines the max number of streams
	// +kubebuilder:validation:Optional
	Streams int64 `json:"streams,omitempty"`
	// Consumer defines the max number of consumers
	// +kubebuilder:validation:Optional
	Consumer int64 `json:"consumer,omitempty"`
	// MaxAckPending defines the max number of acks pending
	// +kubebuilder:validation:Optional
	MaxAckPending int64 `json:"maxAckPending,omitempty"`
	// MemoryMaxStreamBytes defines the max number of bytes a stream can have in memory. (0 means unlimited)
	// +kubebuilder:validation:Optional
	// +kubebuilder:default=0
	MemoryMaxStreamBytes int64 `json:"memMaxStreamBytes,omitempty"`
	// DiskMaxStreamBytes defines the max number of bytes a stream can have on disk. (0 means unlimited)
	// +kubebuilder:validation:Optional
	// +kubebuilder:default=0
	DiskMaxStreamBytes int64 `json:"diskMaxStreamBytes,omitempty"`
	// MaxBytesRequired defines the max bytes required by all Streams
	// +kubebuilder:validation:Optional
	MaxBytesRequired bool `json:"maxBytesRequired,omitempty"`
}

type AccountLimits struct {
	// Imports defines the max number of imports
	// +kubebuilder:validation:Optional
	Imports int64 `json:"imports,omitempty"`
	// Exports defines the max number of exports
	// +kubebuilder:validation:Optional
	Exports int64 `json:"exports,omitempty"`
	// WildcardExports defines if wildcards are allowed in exports
	// +kubebuilder:validation:Optional
	WildcardExports bool `json:"wildcardExports,omitempty"`
	// DisallowBearer defines that user JWT can't be bearer token
	// +kubebuilder:validation:Optional
	DisallowBearer bool `json:"disallowBearer,omitempty"`
	// Conn defines the max number of connections
	// +kubebuilder:validation:Optional
	Conn int64 `json:"conn,omitempty"`
	// LeafNodeConn defines the max number of leaf node connections
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
	// Name is the name of the import
	// +kubebuilder:validation:Optional
	Name string `json:"name,omitempty"`
	// Subject is the subject to import
	// +kubebuilder:validation:Optional
	Subject string `json:"subject,omitempty"`
	// Account is the account to import from
	// +kubebuilder:validation:Optional
	Account string `json:"account,omitempty"`
	// Token is the token to use for the import
	// +kubebuilder:validation:Optional
	Token string `json:"token,omitempty"`
	// LocalSubject is the local subject to import to
	// +kubebuilder:validation:Optional
	LocalSubject string `json:"localSubject,omitempty"`
	// Type is the type of the import
	// +kubebuilder:validation:Optional
	Type string `json:"type,omitempty"`
	// Share defines if the import is shared
	// +kubebuilder:validation:Optional
	Share bool `json:"share,omitempty"`
}

// Export describes a mapping from this account to another one
type Export struct {
	// Name is the name of the export
	// +kubebuilder:validation:Optional
	Name string `json:"name,omitempty"`
	// Subject is the subject to export
	// +kubebuilder:validation:Optional
	Subject string `json:"subject,omitempty"`
	// Type is the type of the export
	// +kubebuilder:validation:Optional
	Type string `json:"type,omitempty"`
	// TokenReq defines if a token is required for the export
	// +kubebuilder:validation:Optional
	TokenReq bool `json:"tokenReq,omitempty"`
	// Revocations defines the revocations for the export
	// +kubebuilder:validation:Optional
	Revocations map[string]int64 `json:"revocations,omitempty"`
	// ResponseType is the response type for the export
	// +kubebuilder:validation:Optional
	ResponseType string `json:"responseType,omitempty"`
	// ResponseThreshold is the response threshold for the export
	// +kubebuilder:validation:Optional
	ResponseThreshold string `json:"responseThreshold,omitempty"`
	// Latency defines the latency for the export.
	// +kubebuilder:validation:Optional
	Latency *ServiceLatency `json:"serviceLatency,omitempty"`
	// AccountTokenPosition defines the account token position for the export
	// +kubebuilder:validation:Optional
	AccountTokenPosition uint `json:"accountTokenPosition,omitempty"`
	// Advertise defines if the export is advertised
	// +kubebuilder:validation:Optional
	Advertise   bool `json:"advertise,omitempty"`
	common.Info `json:",inline"`
}

type ServiceLatency struct {
	// Sampling defines the sampling for the latency
	Sampling int `json:"sampling"`
	// Results defines the results for the latency
	Results string `json:"results"`
}
