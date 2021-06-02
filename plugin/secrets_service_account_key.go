package gcpsecrets

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"google.golang.org/api/iam/v1"

	sakcache "github.com/hashicorp/vault-plugin-secrets-gcp/plugin/cache/serviceaccountkey"
	"github.com/hashicorp/vault-plugin-secrets-gcp/plugin/util"
)

const (
	SecretTypeKey      = "service_account_key"
	keyAlgorithmRSA2k  = "KEY_ALG_RSA_2048"
	privateKeyTypeJson = "TYPE_GOOGLE_CREDENTIALS_FILE"
)

func secretServiceAccountKey(b *backend) *framework.Secret {
	return &framework.Secret{
		Type: SecretTypeKey,
		Fields: map[string]*framework.FieldSchema{
			"private_key_data": {
				Type:        framework.TypeString,
				Description: "Base-64 encoded string. Private key data for a service account key",
			},
			"key_algorithm": {
				Type:        framework.TypeString,
				Description: "Which type of key and algorithm to use for the key (defaults to 2K RSA). Valid values are GCP enum(ServiceAccountKeyAlgorithm)",
			},
			"key_type": {
				Type:        framework.TypeString,
				Description: "Type of the private key (i.e. whether it is JSON or P12). Valid values are GCP enum(ServiceAccountPrivateKeyType)",
			},
		},

		Renew:  b.secretKeyRenew,
		Revoke: b.secretKeyRevoke,
	}
}

func pathSecretServiceAccountKey(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: fmt.Sprintf("key/%s", framework.GenericNameRegex("roleset")),
		Fields: map[string]*framework.FieldSchema{
			"roleset": {
				Type:        framework.TypeString,
				Description: "Required. Name of the role set.",
			},
			"key_algorithm": {
				Type:        framework.TypeString,
				Description: fmt.Sprintf(`Private key algorithm for service account key - defaults to %s"`, keyAlgorithmRSA2k),
				Default:     keyAlgorithmRSA2k,
			},
			"key_type": {
				Type:        framework.TypeString,
				Description: fmt.Sprintf(`Private key type for service account key - defaults to %s"`, privateKeyTypeJson),
				Default:     privateKeyTypeJson,
			},
			"ttl": {
				Type:        framework.TypeDurationSecond,
				Description: "Lifetime of the service account key",
			},
		},
		ExistenceCheck: b.pathRoleSetExistenceCheck("roleset"),
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation:   &framework.PathOperation{Callback: b.pathServiceAccountKey},
			logical.UpdateOperation: &framework.PathOperation{Callback: b.pathServiceAccountKey},
		},
		HelpSynopsis:    pathServiceAccountKeySyn,
		HelpDescription: pathServiceAccountKeyDesc,
	}
}

func (b *backend) pathServiceAccountKey(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	rsName := d.Get("roleset").(string)
	keyType := d.Get("key_type").(string)
	keyAlg := d.Get("key_algorithm").(string)
	ttl := d.Get("ttl").(int)

	rs, err := getRoleSet(rsName, ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if rs == nil {
		return logical.ErrorResponse(fmt.Sprintf("role set '%s' does not exist", rsName)), nil
	}

	if rs.SecretType != SecretTypeKey {
		return logical.ErrorResponse(fmt.Sprintf("role set '%s' cannot generate service account keys (has secret type %s)", rsName, rs.SecretType)), nil
	}

	return b.getSecretKey(ctx, req.Storage, rs, keyType, keyAlg, ttl)
}

func (b *backend) secretKeyRenew(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	resp, err := b.verifySecretServiceKeyExists(ctx, req)
	if err != nil {
		return resp, err
	}
	if resp == nil {
		resp = &logical.Response{}
	}
	cfg, err := getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if cfg == nil {
		cfg = &config{}
	}

	resp.Secret = req.Secret
	resp.Secret.TTL = cfg.TTL
	resp.Secret.MaxTTL = cfg.MaxTTL
	return resp, nil
}

func (b *backend) verifySecretServiceKeyExists(ctx context.Context, req *logical.Request) (*logical.Response, error) {
	keyName, ok := req.Secret.InternalData["key_name"]
	if !ok {
		return nil, fmt.Errorf("invalid secret, internal data is missing key name")
	}

	rsName, ok := req.Secret.InternalData["role_set"]
	if !ok {
		return nil, fmt.Errorf("invalid secret, internal data is missing role set name")
	}

	bindingSum, ok := req.Secret.InternalData["role_set_bindings"]
	if !ok {
		return nil, fmt.Errorf("invalid secret, internal data is missing role set checksum")
	}

	// Verify role set was not deleted.
	rs, err := getRoleSet(rsName.(string), ctx, req.Storage)
	if err != nil {
		return logical.ErrorResponse(fmt.Sprintf("could not find role set '%v' for secret", rsName)), nil
	}

	// Verify role set bindings have not changed since secret was generated.
	if rs.bindingHash() != bindingSum.(string) {
		return logical.ErrorResponse(fmt.Sprintf("role set '%v' bindings were updated since secret was generated, cannot renew", rsName)), nil
	}

	// Verify service account key still exists.
	iamAdmin, err := b.IAMAdminClient(req.Storage)
	if err != nil {
		return logical.ErrorResponse("could not confirm key still exists in GCP"), nil
	}
	if k, err := iamAdmin.Projects.ServiceAccounts.Keys.Get(keyName.(string)).Do(); err != nil || k == nil {
		return logical.ErrorResponse(fmt.Sprintf("could not confirm key still exists in GCP: %v", err)), nil
	}
	return nil, nil
}

func (b *backend) secretKeyRevoke(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	keyNameRaw, ok := req.Secret.InternalData["key_name"]
	if !ok {
		return nil, fmt.Errorf("secret is missing key_name internal data")
	}
	keyName := keyNameRaw.(string)

	rolesetNameRaw, ok := req.Secret.InternalData["role_set"]
	if !ok {
		return nil, fmt.Errorf("secret is missing role_set internal data")
	}
	rolesetName := rolesetNameRaw.(string)

	// Internal key ID we use as a replacement of lease ID that the plugin doesn't
	// have access to.
	var keyInternalID string = ""
	keyInternalIDRaw, ok := req.Secret.InternalData["key_internal_id"]
	if !ok || keyInternalIDRaw == nil {
		keyInternalIDRaw = "*"
	}

	keyInternalID, ok = keyInternalIDRaw.(string)
	if !ok {
		keyInternalID = "*"
	}

	if keyInternalID == "*" {
		b.Logger().Warn(
			"Revoking key that does not have an internal ID, reference counter might "+
				"be decremented more than once",
			"roleset", rolesetName,
			"keyName", keyName,
		)
	}

	// Revoke the key from cache (i.e. decrement its reference counter). Should be
	// okay to return error (as long as we propagate it) since chances are, the
	// revocation will be retried (either by Vault or by the user).
	shouldDelete, cachedSAK, err := sakcache.RevokeKey(ctx, req.Storage, rolesetName, keyName, keyInternalID)
	if err != nil {
		return logical.ErrorResponse(fmt.Sprintf("unable to revoke key from cache: %s", err.Error())), nil
	}

	debugMsg := "reducing service account key counter"
	debugArgs := []interface{}{
		"roleset", rolesetName,
		"key_internal_id", keyInternalID,
	}

	if shouldDelete {
		debugMsg = "deleting service account key as it has no more referee..."
	}

	if cachedSAK != nil {
		debugArgs = append(debugArgs, "updated_num_user", cachedSAK.Counter)
		debugArgs = append(debugArgs, "cache_key", cachedSAK.Name)
		debugArgs = append(debugArgs, "cache_issue_time", cachedSAK.IssueTime.Format(time.RFC3339))
		debugArgs = append(debugArgs, "cache_ttl", cachedSAK.TTL.Seconds())
	}

	b.Logger().Debug(debugMsg, debugArgs)

	if !shouldDelete {
		return nil, nil
	}

	iamAdmin, err := b.IAMAdminClient(req.Storage)
	if err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}

	_, err = iamAdmin.Projects.ServiceAccounts.Keys.Delete(keyNameRaw.(string)).Do()
	if err != nil && !isGoogleAccountKeyNotFoundErr(err) {
		return logical.ErrorResponse(fmt.Sprintf("unable to delete service account key: %v", err)), nil
	}

	return nil, nil
}

func (b *backend) getSecretKey(ctx context.Context, s logical.Storage, rs *RoleSet, keyType, keyAlgorithm string, ttl int) (*logical.Response, error) {
	cfg, err := getConfig(ctx, s)
	if err != nil {
		return nil, errwrap.Wrapf("could not read backend config: {{err}}", err)
	}
	if cfg == nil {
		cfg = &config{}
	}

	ttlToUse := cfg.TTL
	if ttl > 0 {
		ttlToUse = time.Duration(ttl) * time.Second
	}

	var cachedSAK *sakcache.CacheItem = nil

	if !rs.UseStaticServiceAccount {
		cachedSAK, err = sakcache.GetKeyByBindingHash(ctx, s, rs.Name, rs.bindingHash())
	} else {
		// Static service account rolesets have empty binding, use service account
		// email instead
		cachedSAK, err = sakcache.GetKeyByServiceAccountEmail(ctx, s, rs.Name, rs.AccountId.EmailOrId)
	}
	if err != nil {
		b.Logger().Error("failed to get service account key from cache", "roleset_name", rs.Name, "err", err.Error())
	}

	// Valid entry in cache, do not create a new SAK
	if cachedSAK != nil {
		if err := sakcache.UseKey(ctx, s, rs.Name, cachedSAK.Name, ttlToUse); err != nil {
			return nil, errwrap.Wrapf("failed using cached service account key: {{err}}", err)
		}

		secretD, internalD := cachedSAK.SecretResponse(util.GenerateKeyID())

		resp := b.Secret(SecretTypeKey).Response(secretD, internalD)
		resp.Secret.Renewable = false
		resp.Secret.MaxTTL = cfg.MaxTTL
		resp.Secret.TTL = ttlToUse

		return resp, nil
	}

	// No valid entry in cache, create a new SAK
	b.Logger().Debug("a new service account will be created", "roleset_name", rs.Name)

	iamC, err := b.IAMAdminClient(s)
	if err != nil {
		return nil, errwrap.Wrapf("could not create IAM Admin client: {{err}}", err)
	}

	account, err := rs.getServiceAccount(iamC)
	if err != nil {
		if rs.UseStaticServiceAccount {
			return logical.ErrorResponse(
				fmt.Sprintf("roleset '%s' is using a static service account '%s' that has been deleted", rs.Name, rs.AccountId.EmailOrId),
			), nil
		}

		return logical.ErrorResponse(fmt.Sprintf("roleset service account was removed - role set must be updated (write to roleset/%s/rotate) before generating new secrets", rs.Name)), nil
	}

	key, err := iamC.Projects.ServiceAccounts.Keys.Create(
		account.Name, &iam.CreateServiceAccountKeyRequest{
			KeyAlgorithm:   keyAlgorithm,
			PrivateKeyType: keyType,
		}).Do()
	if err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}

	if cacheCreationErr := sakcache.UpsertToCacheCollection(ctx, s, rs.Name, rs.bindingHash(), key, ttlToUse, ttlToUse); cacheCreationErr != nil {
		baseErrResp := fmt.Sprintf("failed to save the new service account key cache collection for role %s: %s;", rs.Name, cacheCreationErr.Error())

		rollbackErr := rollbackCachedServiceAccountKey(ctx, s, iamC, rs.Name, key.Name)
		if rollbackErr != nil {
			return logical.ErrorResponse(fmt.Sprintf("%s service account key cannot be rolled back: %s", baseErrResp, rollbackErr.Error())), nil
		}

		return logical.ErrorResponse(fmt.Sprintf("%s service account key has been rolled back.", baseErrResp)), nil
	}

	secretD := map[string]interface{}{
		"private_key_data": key.PrivateKeyData,
		"key_algorithm":    key.KeyAlgorithm,
		"key_type":         key.PrivateKeyType,
	}
	internalD := map[string]interface{}{
		"key_name":          key.Name,
		"role_set":          rs.Name,
		"role_set_bindings": rs.bindingHash(),
		"key_internal_id":   util.GenerateKeyID(),
	}

	resp := b.Secret(SecretTypeKey).Response(secretD, internalD)
	resp.Secret.Renewable = false
	resp.Secret.MaxTTL = cfg.MaxTTL
	resp.Secret.TTL = ttlToUse

	return resp, nil
}

const pathServiceAccountKeySyn = `Generate an service account private key under a specific role set.`
const pathServiceAccountKeyDesc = `
This path will generate a new service account private key for accessing GCP APIs.
A role set, binding IAM roles to specific GCP resources, will be specified
by name - for example, if this backend is mounted at "gcp", then "gcp/key/deploy"
would generate service account keys for the "deploy" role set.

On the backend, each roleset is associated with a service account under
which secrets/keys are created.
`
