package serviceaccountkey

import (
	"context"
	"errors"
	"sort"
	"strings"
	"time"

	"github.com/hashicorp/vault/sdk/logical"
)

// CacheCollection is a collection of cached service account keys that belong to
// the same roleset
type CacheCollection struct {
	// Mapping between SAK name and the cached SAK item
	Items map[string]*CacheItem
}

// NewCacheCollection creates a new empty CacheCollection
func NewCacheCollection() *CacheCollection {
	cacheCollection := new(CacheCollection)
	cacheCollection.Items = make(map[string]*CacheItem)

	return cacheCollection
}

// PutItem adds a new fine addition to the SAK collection.
//
// Item key should be the SAK's name, in the format of:
//   projects/<project_id>/serviceAccounts/vault<shorten_roleset_name>-<timestamp>@<project_id>.iam.gserviceaccount.com/keys/<key_id>
// ... for example:
// 	projects/infrastructure-260106/serviceAccounts/vaulttestproduct-te-1589452997@infrastructure-260106.iam.gserviceaccount.com/keys/471b62bd4b2ea968384f66c4d0fa8f91fbf4c61b
func (c *CacheCollection) PutItem(itemKey string, item *CacheItem) error {
	if len(strings.Split(itemKey, "/")) != 6 {
		return errors.New("item key must be in the format of projects/<project_id>/serviceAccounts/<serviceaccount-email>/keys/<key_id>")
	}

	if itemKey == "" {
		return errors.New("item key can't be empty")
	}

	if item == nil {
		return errors.New("item can't be nil")
	}

	c.Items[itemKey] = item

	return nil
}

// GetLatestItemByBindingHash returns the latest cached SAK that matches the binding hash,
// according to:
//   1. SA name, which should include timestamp (e.g. vaulttestproduct-te-1589452997)
//   2. SAK issued timestamp
func (c *CacheCollection) GetLatestItemByBindingHash(rsBindingHash string) (string, *CacheItem) {
	keys := make([]string, 0, len(c.Items))
	for k := range c.Items {
		keys = append(keys, k)
	}

	sort.Sort(sort.Reverse(sort.StringSlice(keys)))

	for _, key := range keys {
		item := c.Items[key]

		expiration := float64((*item).IssueTime.Unix()) + (*item).TTL.Seconds()
		now := float64(time.Now().Unix())

		if expiration > now && rsBindingHash == item.RolesetBindingHash {
			return key, item
		}
	}

	return "", nil
}

// GetLatestItemByServiceAccountEmail returns the latest cached SAK name with
// matching service account email
func (c *CacheCollection) GetLatestItemByServiceAccountEmail(
	serviceAccountEmail string,
) (string, *CacheItem) {
	var latestCachedKey *CacheItem = nil
	var latestIssueTime time.Time = time.Time{}

	for _, cachedKey := range c.Items {
		// Key name is expected to be in the format of
		// projects/<project_id>/serviceAccounts/<serviceaccount-email>/keys/<key_id>
		keyNameSplit := strings.Split(cachedKey.Name, "/")
		if len(keyNameSplit) != 6 {
			// Silently ignore unexpected key names
			continue
		}

		// Not match
		cachedSAEmail := keyNameSplit[3]
		if cachedSAEmail != serviceAccountEmail {
			continue
		}

		laterThanTheLatest := cachedKey.IssueTime.After(latestIssueTime)
		notYetExpired := cachedKey.IssueTime.Add(cachedKey.TTL).After(time.Now())

		if laterThanTheLatest && notYetExpired {
			latestCachedKey = cachedKey
			latestIssueTime = cachedKey.IssueTime
		}
	}

	if latestCachedKey == nil {
		return "", nil
	}

	return latestCachedKey.Name, latestCachedKey
}

// PutToStorage persists the cache collection to Vault's storage
func (c *CacheCollection) PutToStorage(ctx context.Context, s logical.Storage, collectionName string) error {
	entry, err := logical.StorageEntryJSON(collectionName, c)
	if err != nil {
		return err
	}

	if err := s.Put(ctx, entry); err != nil {
		return err
	}

	return nil
}

// DeleteItem deletes an entry from the collection
func (c *CacheCollection) DeleteItem(keyName string) {
	delete(c.Items, keyName)
}
