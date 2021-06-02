package serviceaccountkey

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/vault/sdk/logical"
	"google.golang.org/api/iam/v1"
)

const (
	// How long an SAK will stay in the cache, at the minimum. Please note that
	// an SAK can stay in the cache for longer if it is still used by a lease
	// which TTL is after the cache's TTL.
	defaultCacheTTL = time.Duration(3) * time.Hour

	// Storage path prefix for storing SAK cache
	cacheSAKPathPrefix = "cache/sak"
)

var (
	// All exported functions must use this mutex
	saCacheLock sync.Mutex
)

// RevokeKey should be called by the plugin's revocation handler when revoking
// an SAK. Returns true if the SAK is no longer referenced by any leases and
// can be deleted from GCP.
//
// keyInternalID is required to prevent the same lease from decrementing the
// counter multiple times. A "*" keyInternalID will decrement the counter
// without checking.
func RevokeKey(
	ctx context.Context,
	s logical.Storage,
	rolesetName string,
	keyName string,
	keyInternalID string,
) (shouldDelete bool, cacheItem *CacheItem, err error) {
	saCacheLock.Lock()
	defer saCacheLock.Unlock()

	cacheCollection, err := getCacheCollection(ctx, s, rolesetName)
	if err != nil {
		return false, nil, fmt.Errorf("unable to get service account key cache collection of role %s: %v", rolesetName, err)
	}

	// Cache collection is missing, ...
	if cacheCollection == nil {
		return true, nil, nil
	}

	// ... or the key does not exist in it. The key should be deleted from GCP.
	item, ok := cacheCollection.Items[keyName]
	if !ok {
		return true, nil, nil
	}

	// Make sure that the lease ID has not yet decremented the counter
	if keyInternalID != "*" {
		for _, revokedInternalKeyID := range item.RevokedInternalKeyIDs {
			if revokedInternalKeyID == keyInternalID {
				return item.Counter == 0, item, nil
			}
		}
	}

	// Decrement reference counter and persist the change
	item.Counter--

	// Append the key internal ID
	if keyInternalID != "*" {
		if item.RevokedInternalKeyIDs == nil {
			item.RevokedInternalKeyIDs = []string{}
		}

		item.RevokedInternalKeyIDs = append(item.RevokedInternalKeyIDs, keyInternalID)
	}

	if item.Counter == 0 {
		cacheCollection.DeleteItem(keyName)
	}

	cacheCollectionPath := fmt.Sprintf("%s/%s", cacheSAKPathPrefix, rolesetName)

	if err := cacheCollection.PutToStorage(ctx, s, cacheCollectionPath); err != nil {
		return false, nil, fmt.Errorf("unable to update the cache collection storage: %s", err.Error())
	}

	// The key should be deleted if the counter is zero
	return item.Counter == 0, item, nil
}

// DeleteKey should only be called to forcefully delete a key from cache.
func DeleteKey(
	ctx context.Context,
	s logical.Storage,
	rolesetName string,
	keyName string,
) error {
	saCacheLock.Lock()
	defer saCacheLock.Unlock()

	cacheCollection, err := getCacheCollection(ctx, s, rolesetName)
	if err != nil {
		return fmt.Errorf("unable to get service account key cache collection of role %s: %v", rolesetName, err)
	}

	// Cache collection is missing, ...
	if cacheCollection == nil {
		return nil
	}

	// ... or the key does not exist in it. The key should be deleted from GCP.
	_, ok := cacheCollection.Items[keyName]
	if !ok {
		return nil
	}

	cacheCollection.DeleteItem(keyName)

	cacheCollectionPath := fmt.Sprintf("%s/%s", cacheSAKPathPrefix, rolesetName)

	if err := cacheCollection.PutToStorage(ctx, s, cacheCollectionPath); err != nil {
		return fmt.Errorf("unable to update the cache collection storage: %s", err.Error())
	}

	// The key should be deleted if the counter is zero
	return nil
}

// GetKeyByBindingHash fetches the latest SAK for a roleset from cache.
//
// Please note that if the value returned by this function is returned to Vault,
// the UseKey() function must also be called.
func GetKeyByBindingHash(
	ctx context.Context,
	s logical.Storage,
	rolesetName string,
	rolesetBindingHash string,
) (key *CacheItem, err error) {
	saCacheLock.Lock()
	defer saCacheLock.Unlock()

	cacheCollection, err := getCacheCollection(ctx, s, rolesetName)
	if err != nil {
		return nil, errwrap.Wrapf("could not get service account key cache collection: {{err}}", err)
	}

	if cacheCollection == nil {
		return nil, nil
	}

	_, validCacheItem := cacheCollection.GetLatestItemByBindingHash(rolesetBindingHash)
	if validCacheItem == nil {
		return nil, nil
	}

	return validCacheItem, nil
}

// UseKey increments a cached SAK's reference counter. To be called when the key
// is returned to Vault to be used in a lease.
func UseKey(
	ctx context.Context,
	s logical.Storage,
	rolesetName string,
	keyName string,
	leaseTTL time.Duration,
) error {
	saCacheLock.Lock()
	defer saCacheLock.Unlock()

	cacheCollection, err := getCacheCollection(ctx, s, rolesetName)
	if err != nil {
		return errwrap.Wrapf("could not get service account key cache collection: {{err}}", err)
	}

	if cacheCollection == nil {
		return errors.New("cannot increment counter of a null cache collection")
	}

	cacheItem, ok := cacheCollection.Items[keyName]
	if !ok {
		return fmt.Errorf("cached SAK '%s' not found", keyName)
	}

	// Increment counter
	cacheItem.Counter++

	// Estimation of when the lease that uses this cached SAK will expire. The
	// additional one minute is added to account for delay between when function
	// was executed and when the lease will be assigned expiry by Vault.
	leaseFurthestExpiry := time.Now().Add(leaseTTL).Add(time.Minute)
	if cacheItem.LeaseFurthestExpiry.Before(leaseFurthestExpiry) {
		cacheItem.LeaseFurthestExpiry = leaseFurthestExpiry
	}

	cacheCollectionPath := fmt.Sprintf("%s/%s", cacheSAKPathPrefix, rolesetName)

	if err := cacheCollection.PutToStorage(ctx, s, cacheCollectionPath); err != nil {
		return errwrap.Wrapf("failed to update cache key collection: {{err}}", err)
	}

	return nil
}

// UpsertToCacheCollection adds a new SAK to the cache collection of a roleset
// and persists it to Vault storage.
//
// It is assumed that the new SAK will be used by a lease, and thus its
// reference counter will be set to 1.
func UpsertToCacheCollection(
	ctx context.Context,
	s logical.Storage,
	rolesetName string,
	rolesetBindingHash string,
	key *iam.ServiceAccountKey,
	cacheTTL time.Duration,
	leaseTTL time.Duration,
) error {
	saCacheLock.Lock()
	defer saCacheLock.Unlock()

	now := time.Now()

	if cacheTTL == 0 {
		cacheTTL = defaultCacheTTL
	}

	// Estimation of when the lease that uses this cached SAK will expire. The
	// additional one minute is added to account for delay between when function
	// was executed and when the lease will be assigned expiry by Vault.
	leaseFurthestExpiry := time.Now().Add(leaseTTL).Add(time.Minute)

	newCacheItem := &CacheItem{
		Name:                key.Name,
		RolesetName:         rolesetName,
		RolesetBindingHash:  rolesetBindingHash,
		KeyAlgorithm:        key.KeyAlgorithm,
		PrivateKeyData:      key.PrivateKeyData,
		KeyType:             key.PrivateKeyType,
		IssueTime:           now,
		TTL:                 cacheTTL,
		Counter:             1,
		LeaseFurthestExpiry: leaseFurthestExpiry,
	}

	cacheCollection, err := getCacheCollection(ctx, s, rolesetName)
	if err != nil {
		return errwrap.Wrapf("failed to retrieve cache collection: {{err}}", err)
	}

	if cacheCollection == nil {
		cacheCollection = NewCacheCollection()
	}

	if err := cacheCollection.PutItem(key.Name, newCacheItem); err != nil {
		return errwrap.Wrapf("failed to put new item into cache collection: {{err}}", err)
	}

	cacheCollectionPath := fmt.Sprintf("%s/%s", cacheSAKPathPrefix, rolesetName)

	if err := cacheCollection.PutToStorage(ctx, s, cacheCollectionPath); err != nil {
		return errwrap.Wrapf("failed to insert new cache collection into storage: {{err}}", err)
	}

	return nil
}

// GetStaleEntries returns stale (i.e. expired) cache entries. Returns a map
// of roleset names and lists of stale keys
func GetStaleEntries(
	ctx context.Context,
	s logical.Storage,
) (map[string][]*CacheItem, error) {
	staleKeys := make(map[string][]*CacheItem)

	rolesetNames, err := s.List(ctx, cacheSAKPathPrefix+"/")
	if err != nil {
		return nil, err
	}

	for _, rolesetName := range rolesetNames {
		staleKeys[rolesetName] = []*CacheItem{}

		cacheCollection, err := getCacheCollection(ctx, s, rolesetName)
		if err != nil {
			return nil, errwrap.Wrapf(
				fmt.Sprintf("failed fetching cache collection for %s", rolesetName),
				err,
			)
		}

		for _, cachedKey := range cacheCollection.Items {
			// The key is still used longer be used by any lease
			if time.Now().Before(cachedKey.LeaseFurthestExpiry) {
				continue
			}

			// The key has not expire yet
			if time.Now().Before(cachedKey.IssueTime.Add(cachedKey.TTL)) {
				continue
			}

			// The cached key is not used anymore and it has expired
			staleKeys[rolesetName] = append(staleKeys[rolesetName], cachedKey)
		}
	}

	return staleKeys, nil
}

// getCacheCollection retrieves cache collection for a specific roleset
func getCacheCollection(
	ctx context.Context,
	s logical.Storage,
	rolesetName string,
) (*CacheCollection, error) {
	cachedKeyCollection, err := s.Get(ctx, fmt.Sprintf("%s/%s", cacheSAKPathPrefix, rolesetName))
	if err != nil {
		return nil, err
	}

	// Old path convention, for backward compatibility
	if cachedKeyCollection == nil {
		cachedKeyCollection, err = s.Get(ctx, rolesetName)
		if err != nil {
			return nil, err
		}
	}

	if cachedKeyCollection == nil {
		return nil, nil
	}

	decodedCollection := new(CacheCollection)
	if err := cachedKeyCollection.DecodeJSON(decodedCollection); err != nil {
		return nil, err
	}

	return decodedCollection, nil
}
