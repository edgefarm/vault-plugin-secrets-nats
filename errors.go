package natsbackend

const (

	// Parameters
	InvalidParametersError = "invalid parameters"
	DecodeFailedError      = "could not decode parameters"

	// ISSUE
	AddingIssueFailedError  = "adding issue failed"
	ReadingIssueFailedError = "reading issue failed"
	IssueNotFoundError      = "issue not found"
	DeleteIssueFailedError  = "deleting issue failed"
	ListIssuesFailedError   = "listing issues failed"

	// JWT
	AddingJWTFailedError  = "adding jwt failed"
	ReadingJWTFailedError = "reading jwt failed"
	ListJWTsFailedError   = "listing jwts failed"
	DeleteJWTFailedError  = "deleting jwt failed"
	JwtNotFoundError      = "jwt not found"

	// NKEY
	AddingNkeyFailedError  = "adding nkey failed"
	ReadingNkeyFailedError = "reading nkey failed"
	ListNkeysFailedError   = "listing nkeys failed"
	DeleteNkeyFailedError  = "deleting nkey failed"
	NkeyNotFoundError      = "nkey not found"

	// // Operator Errors
	// OperatorNotConfiguredError      = "operator not configured"
	// OperatorMissingError            = "missing operator"
	// MissingOperatorSigningKeysError = "missing operator signing keys"
	// DeletingOperatorError           = "error deleting operator"
	// NoAdditionalSigningKeysError    = "no additional signing keys defined in operator"
	// NotInOperatorSigningKeysError   = "given signing key id is not defined in operator"

	// // Account errors
	// StrictSigningKeyUsageButNoKeyDefinedError = "operator is enabled with strict signing key usage. Provide at least one account signing key"
	// AccountMissingError                       = "missing account"
	// AccountDeleteError                        = "error deleting account"
	// MissingAccountSigningKeysError            = "missing account signing keys"

	// // NKey errors
	// NKeyStorageAccessError   = "error while accessing nkey storage"
	// NKeyUnknownCategoryError = "unknown nkey category"
	// NKeyMissingPeerError     = "missing peer"
	// NKeyMissingIDError       = "missing id"

	// // JWT errors
	// JwtMissingUserNameError        = "missing user name"
	// JwtMissingAccountNameError     = "missing account name"
	// JwtTokenHasWrongClaimTypeError = "token has wrong claim type"
	// JwtExistenceCheckError         = "existence check failed"
)
