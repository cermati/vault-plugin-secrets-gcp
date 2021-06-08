package gcpsecrets

import (
	"context"
	"fmt"

	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/go-multierror"
	"github.com/hashicorp/vault/sdk/logical"

	sakcache "github.com/hashicorp/vault-plugin-secrets-gcp/plugin/cache/serviceaccountkey"
)

// WorkerCleanUpStaleCacheEntries clean stale cache entries
func WorkerCleanUpStaleCacheEntries(
	b *backend,
	ctx context.Context,
	req *logical.Request,
) error {
	b.Logger().Debug("Cleaning up stale cache entries...")

	allStaleKeys, err := sakcache.GetStaleEntries(ctx, req.Storage)
	if err != nil {
		return errwrap.Wrapf("failed getting stale SAK cache entries: {{err}}", err)
	}

	iamC, err := b.IAMAdminClient(req.Storage)
	if err != nil {
		return errwrap.Wrapf("failed to create IAM client: {{err}}", err)
	}

	var merr *multierror.Error
	removed := 0
	for rolesetName, staleKeys := range allStaleKeys {
		if len(staleKeys) == 0 {
			continue
		}

		for _, staleKey := range staleKeys {
			err := rollbackCachedServiceAccountKey(ctx, req.Storage, iamC, rolesetName, staleKey.Name)
			if err != nil {
				// Ignore error for now
				merr = multierror.Append(merr, err)
			} else {
				removed++
				b.Logger().Debug(fmt.Sprintf("Cleaned up stale SAK %s from roleset %s", staleKey.Name, rolesetName))
			}
		}
	}

	if removed != 0 {
		b.Logger().Info(fmt.Sprintf("Cleaned up %d stale entries from SAK cache", removed))
	}

	b.Logger().Debug("Finished cleaning up stale SAK cache entries")

	return merr.ErrorOrNil()
}
