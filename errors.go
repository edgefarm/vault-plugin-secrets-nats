package natsbackend

const (
	// Operator Errors
	OperatorNotConfiguredError      = "operator not configured"
	OperatorMissingError            = "missing operator"
	MissingOperatorSigningKeysError = "missing operator signing keys"
	DeletingOperatorError           = "error deleting operator"
	NoAdditionalSigningKeysError    = "no additional signing keys defined in operator"
	NotInOperatorSigningKeysError   = "given signing key id is not defined in operator"

	// Account errors
	StrictSigningKeyUsageButNoKeyDefinedError = "operator is enabled with strict signing key usage. Provide at least one account signing key"
	AccountMissingError                       = "missing account"
	AccountNotFoundError                      = "account not found"
	AccountDeleteError                        = "error deleting account"
	MissingAccountSigningKeysError            = "missing account signing keys"

	// NKey errors
	NKeyStorageAccessError   = "error while accessing nkey storage"
	NKeyUnknownCategoryError = "unknown nkey category"
	NKeyMissingPeerError     = "missing peer"
	NKeyMissingNameError     = "missing name"

	// JWT errors
	JwtMissingUserNameError        = "missing user name"
	JwtUserNotFound                = "user not found"
	JwtMissingAccountNameError     = "missing account name"
	JwtTokenHasWrongClaimTypeError = "token has wrong claim type"
	JwtExistenceCheckError         = "existence check failed"
)
