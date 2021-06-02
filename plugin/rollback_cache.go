package gcpsecrets

import (
	"context"
	"fmt"

	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/go-multierror"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/mitchellh/mapstructure"
	"google.golang.org/api/iam/v1"

	sakcache "github.com/hashicorp/vault-plugin-secrets-gcp/plugin/cache/serviceaccountkey"
)

// WAL entry for rolling back changes made into the SAK cache
type walAccountKeyCache struct {
	RoleSet string
	KeyName string
}

// serviceAccountKeyCacheRollback rolls back changes made into the SAK cache.
// Only to be used by backend.walRollback().
func (b *backend) serviceAccountKeyCacheRollback(ctx context.Context, req *logical.Request, data interface{}) error {
	b.rolesetLock.Lock()
	defer b.rolesetLock.Unlock()

	var entry walAccountKeyCache
	if err := mapstructure.Decode(data, &entry); err != nil {
		return err
	}

	err := sakcache.DeleteKey(ctx, req.Storage, entry.RoleSet, entry.KeyName)
	if err != nil {
		return errwrap.Wrapf(
			fmt.Sprintf(
				"unable to delete service account key '%s' from cache for roleset '%s': {{err}}",
				entry.KeyName,
				entry.RoleSet,
			),
			err,
		)
	}

	b.Logger().Info(
		"Service account key cache rolled back (WAL)",
		"roleset", entry.RoleSet,
		"key_name", entry.KeyName,
	)

	return nil
}

// rollbackAllCachedServiceAccountKeys deletes all service account keys created
// for a roleset
func rollbackAllCachedServiceAccountKeys(
	ctx context.Context,
	s logical.Storage,
	iamC *iam.Service,
	rolesetName string,
) *multierror.Error {
	var merr *multierror.Error

	cachedKeys, err := sakcache.GetAllKeys(ctx, s, rolesetName)
	if err != nil {
		merr = multierror.Append(
			merr,
			errwrap.Wrapf("unable to fetch service account keys used by the roleset, rollback aborted: {{err}}", err),
		)

		return merr
	}

	for _, cachedKey := range cachedKeys {
		err := rollbackCachedServiceAccountKey(ctx, s, iamC, rolesetName, cachedKey.Name)
		if err != nil {
			merr = multierror.Append(
				merr,
				errwrap.Wrapf(
					fmt.Sprintf("unable to successfully rollback key '%s': {{err}}", cachedKey.Name),
					err,
				),
			)
		}
	}

	return merr
}

// rollbackCachedServiceAccountKey should be called on creation of a new SAK
// when there are failures during cache-related operations.
func rollbackCachedServiceAccountKey(
	ctx context.Context,
	s logical.Storage,
	iamC *iam.Service,
	rolesetName string,
	keyName string,
) error {
	// WAL entries to retry this rollback in the background.
	// Deletion of the cache entry for the SAK, due to errors in manual rollback
	sakCacheRollbackWAL, errWAL := framework.PutWAL(ctx, s, walTypeAccountKeyCache, &walAccountKeyCache{
		RoleSet: rolesetName,
		KeyName: keyName,
	})
	if errWAL != nil {
		tryDeleteWALs(ctx, s, sakCacheRollbackWAL)

		return errwrap.Wrapf(
			fmt.Sprintf(
				"unable to create WAL entries for rolling back service account key %s (manual cleanup required)", keyName,
			),
			errWAL,
		)
	}

	// Deletion of the newly-created SAK, due to errors in manual rollback
	sakRollbackWAL, errWAL := framework.PutWAL(ctx, s, walTypeAccountKey, &walAccountKey{
		RoleSet:            rolesetName,
		ServiceAccountName: "", // not needed if we have KeyName set
		KeyName:            keyName,
	})
	if errWAL != nil {
		tryDeleteWALs(ctx, s, sakRollbackWAL)

		return errwrap.Wrapf(
			fmt.Sprintf(
				"unable to create WAL entries for rolling back service account key %s (manual cleanup required)", keyName,
			),
			errWAL,
		)
	}

	// We can't assume that the SAK has not been successfully persisted into
	// storage. Thus, delete the SAK from storage.
	err := sakcache.DeleteKey(ctx, s, rolesetName, keyName)
	if err != nil {
		return errwrap.Wrapf(
			fmt.Sprintf(
				"unable to rollback cache entry for service account key %s (will be retried w/ WAL)", keyName,
			),
			errWAL,
		)
	}

	tryDeleteWALs(ctx, s, sakCacheRollbackWAL)

	// Delete the SAK from GCP
	_, err = iamC.Projects.ServiceAccounts.Keys.Delete(keyName).Do()
	if err != nil && !isGoogleAccountKeyNotFoundErr(err) {
		return errwrap.Wrapf(
			fmt.Sprintf(
				"unable to rollback service account key %s (will be retried w/ WAL)", keyName,
			),
			errWAL,
		)
	}

	tryDeleteWALs(ctx, s, sakRollbackWAL)

	return nil
}
