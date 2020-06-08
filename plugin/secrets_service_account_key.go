package gcpsecrets

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"google.golang.org/api/iam/v1"
)

const (
	SecretTypeKey      = "service_account_key"
	keyAlgorithmRSA2k  = "KEY_ALG_RSA_2048"
	privateKeyTypeJson = "TYPE_GOOGLE_CREDENTIALS_FILE"

	defaultCacheTTL = time.Duration(3) * time.Hour
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

	b.saCacheLock.Lock()
	defer b.saCacheLock.Unlock()

	cacheCollection, err := getCacheCollection(ctx, req.Storage, rolesetName)
	if err != nil {
		return logical.ErrorResponse(fmt.Sprintf("unable to get service account key cache collection of role %s: %v", rolesetName, err)), nil
	}

	item, ok := cacheCollection.Items[keyName]
	if !ok {
		return logical.ErrorResponse(fmt.Sprintf("unable to get service account key cache item of key %s: %v", keyName, err)), nil
	}

	item.Counter--

	if item.Counter == 0 {
		cacheCollection.deleteItem(keyName)
	}

	if err := cacheCollection.putToStorage(ctx, req.Storage, rolesetName); err != nil {
		return logical.ErrorResponse(fmt.Sprintf("unable to update the cache collection storage: %s", err.Error())), nil
	}

	if item.Counter > 0 {
		b.Logger().Debug(
			"reducing service account key counter",
			"roleset", rolesetName,
			"updated_num_user", item.Counter,
			"cache_key", item.Name,
			"cache_issue_time", item.IssueTime.Format(time.RFC3339),
			"cache_ttl", item.TTL.Seconds(),
		)
		return nil, nil
	}

	b.Logger().Debug(
		"deleting service account key as it has no more referee...",
		"roleset", rolesetName,
		"updated_num_user", item.Counter,
		"cache_key", item.Name,
		"cache_issue_time", item.IssueTime.Format(time.RFC3339),
		"cache_ttl", item.TTL.Seconds(),
	)

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

	b.saCacheLock.Lock()
	defer b.saCacheLock.Unlock()

	b.Logger().Debug("trying to get cache collection", "roleset", rs.Name)
	validCacheItem, err := getSecretKeyFromCache(ctx, s, rs)
	if err != nil {
		b.Logger().Error("failed to get service account key from cache", "roleset_name", rs.Name, "err", err.Error())
	}

	if validCacheItem != nil && err == nil {
		b.Logger().Debug(
			"service account key cache item found",
			"roleset", rs.Name,
			"updated_num_user", validCacheItem.Counter,
			"cache_key", validCacheItem.Name,
			"cache_issue_time", validCacheItem.IssueTime.Format(time.RFC3339),
			"cache_ttl", validCacheItem.TTL.Seconds(),
		)

		resp := b.constructRespFromCache(validCacheItem, ttlToUse, cfg.MaxTTL)
		return resp, nil
	}

	b.Logger().Debug("a new service account will be created", "roleset_name", rs.Name)

	iamC, err := b.IAMAdminClient(s)
	if err != nil {
		return nil, errwrap.Wrapf("could not create IAM Admin client: {{err}}", err)
	}

	account, err := rs.getServiceAccount(iamC)
	if err != nil {
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

	if cacheCreationErr := upsertCacheCollection(ctx, s, rs, key, ttlToUse); cacheCreationErr != nil {
		baseErrResp := fmt.Sprintf("failed to save the new service account key cache collection for role %s: %s;", rs.Name, cacheCreationErr.Error())

		_, err = iamC.Projects.ServiceAccounts.Keys.Delete(key.Name).Do()
		if err != nil && !isGoogleAccountKeyNotFoundErr(err) {
			return logical.ErrorResponse(fmt.Sprintf("%s unable to rollback service account key %s: %s", baseErrResp, key.Name, err.Error())), nil
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
	}

	resp := b.Secret(SecretTypeKey).Response(secretD, internalD)
	resp.Secret.Renewable = false
	resp.Secret.MaxTTL = cfg.MaxTTL
	resp.Secret.TTL = ttlToUse

	return resp, nil
}

func (b *backend) constructRespFromCache(item *serviceAccountKeyCacheItem, ttl, maxTTL time.Duration) *logical.Response {
	secretD, internalD := item.secretResponse()
	resp := b.Secret(SecretTypeKey).Response(secretD, internalD)
	resp.Secret.TTL = ttl
	resp.Secret.MaxTTL = maxTTL
	resp.Secret.Renewable = false

	return resp
}

func getSecretKeyFromCache(ctx context.Context, s logical.Storage, rs *RoleSet) (*serviceAccountKeyCacheItem, error) {
	cacheCollection, err := getCacheCollection(ctx, s, rs.Name)
	if err != nil {
		return nil, errwrap.Wrapf("could not get service account key cache collection: {{err}}", err)
	}

	if cacheCollection == nil {
		return nil, nil
	}

	_, validCacheItem := cacheCollection.getLatestItem(rs.bindingHash())
	if validCacheItem == nil {
		return nil, nil
	}

	validCacheItem.Counter++

	if err := cacheCollection.putToStorage(ctx, s, rs.Name); err != nil {
		return nil, errwrap.Wrapf("failed to update cache key collection: {{err}}", err)
	}

	return validCacheItem, nil

}

func upsertCacheCollection(ctx context.Context, s logical.Storage, rs *RoleSet, key *iam.ServiceAccountKey, ttl time.Duration) error {
	now := time.Now()

	cacheTTL := ttl
	if cacheTTL == 0 {
		cacheTTL = defaultCacheTTL
	}

	newCacheItem := &serviceAccountKeyCacheItem{
		Name:               key.Name,
		RolesetName:        rs.Name,
		RolesetBindingHash: rs.bindingHash(),
		KeyAlgorithm:       key.KeyAlgorithm,
		PrivateKeyData:     key.PrivateKeyData,
		KeyType:            key.PrivateKeyType,
		IssueTime:          now,
		TTL:                cacheTTL,
		Counter:            1,
	}

	cacheCollection, err := getCacheCollection(ctx, s, rs.Name)
	if err != nil {
		return errwrap.Wrapf("failed to retrieve cache collection: {{err}}", err)
	}

	if cacheCollection == nil {
		cacheCollection = newServiceAccountKeyCacheCollection()
	}

	if err := cacheCollection.putItem(key.Name, newCacheItem); err != nil {
		return errwrap.Wrapf("failed to put new item into cache collection: {{err}}", err)
	}

	if err := cacheCollection.putToStorage(ctx, s, rs.Name); err != nil {
		return errwrap.Wrapf("failed to insert new cache collection into storage: {{err}}", err)
	}

	return nil
}

func getCacheCollection(ctx context.Context, s logical.Storage, rolesetName string) (*serviceAccountKeyCacheCollection, error) {
	cachedKeyCollection, err := s.Get(ctx, rolesetName)
	if err != nil {
		return nil, err
	}

	if cachedKeyCollection == nil {
		return nil, nil
	}

	decodedCollection := new(serviceAccountKeyCacheCollection)
	if err := cachedKeyCollection.DecodeJSON(decodedCollection); err != nil {
		return nil, err
	}

	return decodedCollection, nil
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

type serviceAccountKeyCacheCollection struct {
	Items map[string]*serviceAccountKeyCacheItem
}

func newServiceAccountKeyCacheCollection() *serviceAccountKeyCacheCollection {
	cacheCollection := new(serviceAccountKeyCacheCollection)
	cacheCollection.Items = make(map[string]*serviceAccountKeyCacheItem)

	return cacheCollection
}

func (c *serviceAccountKeyCacheCollection) putItem(itemKey string, item *serviceAccountKeyCacheItem) error {
	if itemKey == "" {
		return errors.New("Item key can't be empty")
	}

	if item == nil {
		return errors.New("Item can't be nil")
	}

	c.Items[itemKey] = item

	return nil
}

func (c *serviceAccountKeyCacheCollection) getLatestItem(rsBindingHash string) (string, *serviceAccountKeyCacheItem) {
	// Keys element format:
	// projects/<project_id>/serviceAccounts/vault<shorten_roleset_name>-<timestamp>@<project_id>.iam.gserviceaccount.com/keys/<key_id>
	// Example:
	// projects/infrastructure-260106/serviceAccounts/vaulttestproduct-te-1589452997@infrastructure-260106.iam.gserviceaccount.com/keys/471b62bd4b2ea968384f66c4d0fa8f91fbf4c61b

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

func (c *serviceAccountKeyCacheCollection) putToStorage(ctx context.Context, s logical.Storage, collectionName string) error {
	entry, err := logical.StorageEntryJSON(collectionName, c)
	if err != nil {
		return err
	}

	if err := s.Put(ctx, entry); err != nil {
		return err
	}

	return nil
}

func (c *serviceAccountKeyCacheCollection) deleteItem(keyName string) {
	delete(c.Items, keyName)
}

type serviceAccountKeyCacheItem struct {
	Name               string
	RolesetName        string
	RolesetBindingHash string
	PrivateKeyData     string
	KeyAlgorithm       string
	KeyType            string
	IssueTime          time.Time
	TTL                time.Duration
	Counter            int
}

func (i *serviceAccountKeyCacheItem) secretResponse() (data map[string]interface{}, internal map[string]interface{}) {
	data = map[string]interface{}{
		"private_key_data": i.PrivateKeyData,
		"key_algorithm":    i.KeyAlgorithm,
		"key_type":         i.KeyType,
	}

	internal = map[string]interface{}{
		"key_name":          i.Name,
		"role_set":          i.RolesetName,
		"role_set_bindings": i.RolesetBindingHash,
	}

	return
}
