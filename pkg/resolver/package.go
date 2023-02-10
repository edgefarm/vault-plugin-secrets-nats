package resolver

// Push accounts mechanism explained
// =================================
// General prerequsites
// ---------------------
// -> There must be a sys account and a sys account user with permissions:
// AllowPub: $SYS.REQ.CLAIMS.LIST, $SYS.REQ.CLAIMS.UPDATE, $SYS.REQ.CLAIMS.DELETE
// AllowSub: _INBOX.>
// -> open a nats connection with the JWT and SEED of this sys account user
//    with options for (optional TLS certs), timeouts, reconnect handlers, etc.

// Adding accounts:
// ----------------
// Iterate over all accounts to add and get their JWTs
// On each iteration create a PUB on subject $SYS.REQ.CLAIMS.UPDATE with the JWT as []byte
// After sending each PUB with the JWT wait for responses using SubscribeSync() within a defined time frame (e.g. 1 second). This information can be used to inform how many servers got the publish.

// Deleting accounts:
// ------------------
// Get JWT of account to be deleted
// create a PUB on subject $SYS.REQ.CLAIMS.DELETE with the JWT as []byte
// After sending the PUB with the JWT wait for responses using SubscribeSync() within a defined time frame (e.g. 1 second). This information can be used to inform how many servers got the publish.
