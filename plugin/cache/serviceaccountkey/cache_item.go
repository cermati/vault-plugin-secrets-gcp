package serviceaccountkey

import "time"

// CacheItem is the service account key that is stored in or obtained from cache
type CacheItem struct {
	Name               string
	RolesetName        string
	RolesetBindingHash string
	PrivateKeyData     string
	KeyAlgorithm       string
	KeyType            string
	IssueTime          time.Time
	TTL                time.Duration
	Counter            int

	// Different than TTL, which is the entry's TTL, LeaseFurthestExpiry is the
	// estimation of the furthest expiration date of all leases that uses
	// this SAK.
	//
	// Adding a positive offset is recommended since this not be earlier that any
	// of the leases' expiration.
	LeaseFurthestExpiry time.Time

	// List of internal key IDs (which are a substitute for lease IDs) that once
	// used this key but has been revoked. Used to prevent the same lease to
	// decrement the reference counter more than once.
	RevokedInternalKeyIDs []string
}

// SecretResponse returns Vault secret data. To be used with
// backend.Secret(SecretTypeKey).Response(...)
func (i *CacheItem) SecretResponse(keyID string) (
	data map[string]interface{},
	internal map[string]interface{},
) {
	data = map[string]interface{}{
		"private_key_data": i.PrivateKeyData,
		"key_algorithm":    i.KeyAlgorithm,
		"key_type":         i.KeyType,
	}

	internal = map[string]interface{}{
		"key_name":          i.Name,
		"role_set":          i.RolesetName,
		"role_set_bindings": i.RolesetBindingHash,
		"key_internal_id":   keyID,
	}

	return
}
