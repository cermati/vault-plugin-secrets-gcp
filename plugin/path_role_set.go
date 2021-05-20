package gcpsecrets

import (
	"context"
	"errors"
	"fmt"

	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/go-gcp-common/gcputil"
	"github.com/hashicorp/vault-plugin-secrets-gcp/plugin/iamutil"
	"github.com/hashicorp/vault-plugin-secrets-gcp/plugin/util"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/useragent"
	"github.com/hashicorp/vault/sdk/logical"
	"google.golang.org/api/iam/v1"
	"google.golang.org/api/option"
)

const (
	rolesetStoragePrefix = "roleset"
)

func pathRoleSet(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: fmt.Sprintf("roleset/%s", framework.GenericNameRegex("name")),
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeString,
				Description: "Required. Name of the role.",
			},
			"secret_type": {
				Type:        framework.TypeString,
				Description: fmt.Sprintf("Type of secret generated for this role set. Defaults to '%s'", SecretTypeAccessToken),
				Default:     SecretTypeAccessToken,
			},
			"project": {
				Type:        framework.TypeString,
				Description: "Name of the GCP project that this roleset's service account will belong to.",
			},
			"bindings": {
				Type:        framework.TypeString,
				Description: "Bindings configuration string.",
			},
			"token_scopes": {
				Type:        framework.TypeCommaStringSlice,
				Description: `List of OAuth scopes to assign to credentials generated under this role set`,
			},
			"existing_service_account_email": {
				Type:        framework.TypeString,
				Description: "Email address of an existing service account to use, instead of generating a new one",
				Default:     "",
			},
		},
		ExistenceCheck: b.pathRoleSetExistenceCheck("name"),
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.DeleteOperation: &framework.PathOperation{
				Callback: b.pathRoleSetDelete,
			},
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathRoleSetRead,
			},
			logical.CreateOperation: &framework.PathOperation{
				Callback: b.pathRoleSetCreateUpdate,
			},
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathRoleSetCreateUpdate,
			},
		},
		HelpSynopsis:    pathRoleSetHelpSyn,
		HelpDescription: pathRoleSetHelpDesc,
	}
}

func pathRoleSetList(b *backend) *framework.Path {
	// Paths for listing role sets
	return &framework.Path{
		Pattern: "rolesets?/?",
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ListOperation: &framework.PathOperation{
				Callback: b.pathRoleSetList,
			},
		},
		HelpSynopsis:    pathListRoleSetHelpSyn,
		HelpDescription: pathListRoleSetHelpDesc,
	}
}

func pathRoleSetRotateAccount(b *backend) *framework.Path {
	return &framework.Path{
		// Path to rotate role set service accounts
		Pattern: fmt.Sprintf("roleset/%s/rotate", framework.GenericNameRegex("name")),
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeString,
				Description: "Name of the role.",
			},
		},
		ExistenceCheck: b.pathRoleSetExistenceCheck("name"),
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathRoleSetRotateAccount,
			},
		},
		HelpSynopsis:    pathRoleSetRotateAccountHelpSyn,
		HelpDescription: pathRoleSetRotateAccountHelpDesc,
	}
}

func pathRoleSetRotateKey(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: fmt.Sprintf("roleset/%s/rotate-key", framework.GenericNameRegex("name")),
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeString,
				Description: "Name of the role.",
			},
		},
		ExistenceCheck: b.pathRoleSetExistenceCheck("name"),
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathRoleSetRotateKey,
			},
		},
		HelpSynopsis:    pathRoleSetRotateKeyHelpSyn,
		HelpDescription: pathRoleSetRotateKeyHelpDesc,
	}
}

func (b *backend) pathRoleSetExistenceCheck(rolesetFieldName string) framework.ExistenceFunc {
	return func(ctx context.Context, req *logical.Request, d *framework.FieldData) (bool, error) {
		// check for either name or roleset
		nameRaw, ok := d.GetOk(rolesetFieldName)
		if !ok {
			return false, errors.New("roleset name is required")
		}

		rs, err := getRoleSet(nameRaw.(string), ctx, req.Storage)
		if err != nil {
			return false, err
		}

		return rs != nil, nil
	}
}

func (b *backend) pathRoleSetRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	nameRaw, ok := d.GetOk("name")
	if !ok {
		return logical.ErrorResponse("name is required"), nil
	}

	rs, err := getRoleSet(nameRaw.(string), ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if rs == nil {
		return nil, nil
	}

	data := map[string]interface{}{
		"secret_type":                  rs.SecretType,
		"use_existing_service_account": rs.UseExistingServiceAccount,
		"bindings":                     rs.Bindings.asOutput(),
	}

	if rs.AccountId != nil {
		data["service_account_email"] = rs.AccountId.EmailOrId
		data["project"] = rs.AccountId.Project
	}

	if rs.TokenGen != nil && rs.SecretType == SecretTypeAccessToken {
		data["token_scopes"] = rs.TokenGen.Scopes
	}

	return &logical.Response{
		Data: data,
	}, nil
}

func (b *backend) pathRoleSetDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	nameRaw, ok := d.GetOk("name")
	if !ok {
		return logical.ErrorResponse("name is required"), nil
	}
	rsName := nameRaw.(string)

	rs, err := getRoleSet(rsName, ctx, req.Storage)
	if err != nil {
		return nil, errwrap.Wrapf(fmt.Sprintf("unable to get role set %s: {{err}}", rsName), err)
	}
	if rs == nil {
		return nil, nil
	}

	b.rolesetLock.Lock()
	defer b.rolesetLock.Unlock()

	if rs.AccountId != nil && !rs.UseExistingServiceAccount {
		_, err := framework.PutWAL(ctx, req.Storage, walTypeAccount, &walAccount{
			RoleSet: rsName,
			Id:      *rs.AccountId,
		})
		if err != nil {
			return nil, errwrap.Wrapf("unable to create WAL entry to clean up service account: {{err}}", err)
		}

		for resName, roleSet := range rs.Bindings {
			_, err := framework.PutWAL(ctx, req.Storage, walTypeIamPolicy, &walIamPolicy{
				RoleSet:   rsName,
				AccountId: *rs.AccountId,
				Resource:  resName,
				Roles:     roleSet.ToSlice(),
			})
			if err != nil {
				return nil, errwrap.Wrapf("unable to create WAL entry to clean up service account bindings: {{err}}", err)
			}
		}

		if rs.TokenGen != nil {
			_, err := framework.PutWAL(ctx, req.Storage, walTypeAccount, &walAccountKey{
				RoleSet:            rsName,
				ServiceAccountName: rs.AccountId.ResourceName(),
				KeyName:            rs.TokenGen.KeyName,
			})
			if err != nil {
				return nil, errwrap.Wrapf("unable to create WAL entry to clean up service account key: {{err}}", err)
			}
		}
	}

	if err := req.Storage.Delete(ctx, fmt.Sprintf("roleset/%s", nameRaw)); err != nil {
		return nil, err
	}

	// Clean up resources:
	httpC, err := b.HTTPClient(req.Storage)
	if err != nil {
		return nil, err
	}

	iamAdmin, err := iam.NewService(ctx, option.WithHTTPClient(httpC))
	if err != nil {
		return nil, err
	}

	apiHandle := iamutil.GetApiHandle(httpC, useragent.String())

	warnings := make([]string, 0)
	if rs.AccountId != nil && !rs.UseExistingServiceAccount {
		if err := b.deleteTokenGenKey(ctx, iamAdmin, rs.TokenGen); err != nil {
			w := fmt.Sprintf("unable to delete key under service account %q (WAL entry to clean-up later has been added): %v", rs.AccountId.ResourceName(), err)
			warnings = append(warnings, w)
		}

		if err := b.deleteServiceAccount(ctx, iamAdmin, rs.AccountId); err != nil {
			w := fmt.Sprintf("unable to delete service account %q (WAL entry to clean-up later has been added): %v", rs.AccountId.ResourceName(), err)
			warnings = append(warnings, w)
		}

		if merr := b.removeBindings(ctx, apiHandle, rs.AccountId.EmailOrId, rs.Bindings); merr != nil {
			for _, err := range merr.Errors {
				w := fmt.Sprintf("unable to delete IAM policy bindings for service account %q (WAL entry to clean-up later has been added): %v", rs.AccountId.EmailOrId, err)
				warnings = append(warnings, w)
			}
		}
	}

	if len(warnings) > 0 {
		return &logical.Response{Warnings: warnings}, nil
	}

	return nil, nil
}

func (b *backend) pathRoleSetCreateUpdate(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	var warnings []string
	nameRaw, ok := d.GetOk("name")
	if !ok {
		return logical.ErrorResponse("name is required"), nil
	}
	name := nameRaw.(string)

	rs, err := getRoleSet(name, ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	if rs == nil {
		rs = &RoleSet{
			Name: name,
		}
	}

	isCreate := req.Operation == logical.CreateOperation

	// Secret type
	if isCreate {
		secretType := d.Get("secret_type").(string)
		switch secretType {
		case SecretTypeKey, SecretTypeAccessToken:
			rs.SecretType = secretType
		default:
			return logical.ErrorResponse(fmt.Sprintf(`invalid "secret_type" value: "%s"`, secretType)), nil
		}
	} else {
		secretTypeRaw, ok := d.GetOk("secret_type")
		if ok && rs.SecretType != secretTypeRaw.(string) {
			return logical.ErrorResponse("cannot change secret_type after roleset creation"), nil
		}
	}

	// Project
	var project string
	projectRaw, ok := d.GetOk("project")
	if ok {
		project = projectRaw.(string)
		if !isCreate && rs.AccountId.Project != project {
			return logical.ErrorResponse(fmt.Sprintf("cannot change project for existing role set (old: %s, new: %s)", rs.AccountId.Project, project)), nil
		}
		if len(project) == 0 {
			return logical.ErrorResponse("given empty project"), nil
		}
	} else {
		if isCreate {
			return logical.ErrorResponse("project argument is required for new role set"), nil
		}
		project = rs.AccountId.Project
	}

	// Default scopes
	var scopes []string
	scopesRaw, ok := d.GetOk("token_scopes")
	if ok {
		if rs.SecretType != SecretTypeAccessToken {
			warnings = []string{
				fmt.Sprintf("ignoring token_scopes, only valid for '%s' secret type role set", SecretTypeAccessToken),
			}
		}
		scopes = scopesRaw.([]string)
		if len(scopes) == 0 {
			return logical.ErrorResponse("cannot provide empty token_scopes"), nil
		}
	} else if rs.SecretType == SecretTypeAccessToken {
		if isCreate {
			return logical.ErrorResponse("token_scopes must be provided for creating access token role set"), nil
		}
		if rs.TokenGen != nil {
			scopes = rs.TokenGen.Scopes
		}
	}

	// Existing service account
	var existingServiceAccountEmail string
	existingServiceAccountEmailRaw, useExistingServiceAccount := d.GetOk("existing_service_account_email")

	// Conversion between automatically-generated SA roleset and exsting SA
	// roleset is not allowed
	if !isCreate && rs.UseExistingServiceAccount != useExistingServiceAccount {
		return logical.ErrorResponse("cannot change existing service account config for existing roleset"), nil
	}

	if useExistingServiceAccount {
		existingServiceAccountEmail = existingServiceAccountEmailRaw.(string)

		rs.UseExistingServiceAccount = true
		rs.AccountId = &gcputil.ServiceAccountId{
			Project:   project,
			EmailOrId: existingServiceAccountEmail,
		}

		// TODO: check SA exsistence
		// TODO: check whether updating SA is a good idea
	}

	// Bindings
	bRaw, newBindings := d.GetOk("bindings")
	if useExistingServiceAccount {
		if newBindings {
			return logical.ErrorResponse("bindings are not supported for static service account"), nil
		}
	} else {
		if newBindings {
			bindings, ok := bRaw.(string)
			if !ok {
				return logical.ErrorResponse("bindings are not a string"), nil
			}
			if bindings == "" {
				return logical.ErrorResponse("bindings are empty"), nil
			}
		}

		if isCreate && !newBindings {
			return logical.ErrorResponse("bindings are required for new role set"), nil
		}
	}

	// If no new bindings, new bindings are exactly same as old bindings, or
	// using an exsting service account, just update the role set without rotating
	// service account.
	if !newBindings || rs.bindingHash() == getStringHash(bRaw.(string)) || useExistingServiceAccount {
		if rs.TokenGen != nil {
			rs.TokenGen.Scopes = scopes
		}
		// Just save role with updated metadata:
		if err := rs.save(ctx, req.Storage); err != nil {
			return logical.ErrorResponse(err.Error()), nil
		}
		return nil, nil
	}

	// If new bindings, update service account.
	var bindings ResourceBindings
	bindings, err = util.ParseBindings(bRaw.(string))
	if err != nil {
		return logical.ErrorResponse(fmt.Sprintf("unable to parse bindings: %v", err)), nil
	}
	if len(bindings) == 0 {
		return logical.ErrorResponse("unable to parse any bindings from given bindings HCL"), nil
	}
	rs.RawBindings = bRaw.(string)

	updateWarns, err := b.saveRoleSetWithNewAccount(ctx, req.Storage, rs, project, bindings, scopes)
	if updateWarns != nil {
		warnings = append(warnings, updateWarns...)
	}
	if err != nil {
		return logical.ErrorResponse(err.Error()), nil
	} else if warnings != nil && len(warnings) > 0 {
		return &logical.Response{Warnings: warnings}, nil
	}
	return nil, nil
}

func (b *backend) pathRoleSetList(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	rolesets, err := req.Storage.List(ctx, "roleset/")
	if err != nil {
		return nil, err
	}
	return logical.ListResponse(rolesets), nil
}

func (b *backend) pathRoleSetRotateAccount(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	nameRaw, ok := d.GetOk("name")
	if !ok {
		return logical.ErrorResponse("name is required"), nil
	}
	name := nameRaw.(string)

	rs, err := getRoleSet(name, ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if rs == nil {
		return logical.ErrorResponse(fmt.Sprintf("roleset '%s' not found", name)), nil
	}

	if rs.UseExistingServiceAccount {
		return logical.ErrorResponse(
			fmt.Sprintf(
				"roleset '%s' is using an existing service account '%s', and thus cannot be rotated",
				name,
				rs.AccountId.EmailOrId,
			),
		), nil
	}

	var scopes []string
	if rs.TokenGen != nil {
		scopes = rs.TokenGen.Scopes
	}

	warnings, err := b.saveRoleSetWithNewAccount(ctx, req.Storage, rs, rs.AccountId.Project, nil, scopes)
	if err != nil {
		return logical.ErrorResponse(err.Error()), nil
	} else if warnings != nil && len(warnings) > 0 {
		return &logical.Response{Warnings: warnings}, nil
	}
	return nil, nil
}

func (b *backend) pathRoleSetRotateKey(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	nameRaw, ok := d.GetOk("name")
	if !ok {
		return logical.ErrorResponse("name is required"), nil
	}
	name := nameRaw.(string)

	rs, err := getRoleSet(name, ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if rs == nil {
		return logical.ErrorResponse(fmt.Sprintf("roleset '%s' not found", name)), nil
	}

	if rs.SecretType != SecretTypeAccessToken {
		return logical.ErrorResponse("cannot rotate key for non-access-token role set"), nil
	}
	var scopes []string
	if rs.TokenGen != nil {
		scopes = rs.TokenGen.Scopes
	}
	warn, err := b.saveRoleSetWithNewTokenKey(ctx, req.Storage, rs, scopes)
	if err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}
	if warn != "" {
		return &logical.Response{Warnings: []string{warn}}, nil
	}
	return nil, nil
}

func getRoleSet(name string, ctx context.Context, s logical.Storage) (*RoleSet, error) {
	entry, err := s.Get(ctx, fmt.Sprintf("%s/%s", rolesetStoragePrefix, name))
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}

	rs := &RoleSet{}
	if err := entry.DecodeJSON(rs); err != nil {
		return nil, err
	}
	return rs, nil
}

const pathRoleSetHelpSyn = `Read/write sets of IAM roles to be given to generated credentials for specified GCP resources.`
const pathRoleSetHelpDesc = `
This path allows you create role sets, which bind sets of IAM roles
to specific GCP resources. Secrets (either service account keys or
access tokens) are generated under a role set and will have the
given set of roles on resources.

The specified binding file accepts an HCL (or JSON) string
with the following format:

resource "some/gcp/resource/uri" {
	roles = [
		"roles/role1",
		"roles/role2",
		"roles/role3",
		...
	]
}

The given resource can have the following

* Project-level self link
	Self-link for a resource under a given project
	(i.e. resource name starts with 'projects/...')
	Use if you need to provide a versioned object or
	are directly using resource.self_link.

	Example (Compute instance):
		http://www.googleapis.com/compute/v1/projects/$PROJECT/zones/$ZONE/instances/$INSTANCE_NAME

* Full Resource Name
	A scheme-less URI consisting of a DNS-compatible
	API service name and a resource path (i.e. the
	relative resource name). Useful if you need to
	specify what service this resource is under
	but just want the preferred supported API version.
	Note that if the resource you are using is for
	a non-preferred API with multiple service versions,
	you MUST specify the version.

	Example (IAM service account):
		//$SERVICE.googleapis.com/projects/my-project/serviceAccounts/myserviceaccount@...

* Relative Resource Name:
	A URI path (path-noscheme) without the leading "/".
	It identifies a resource within the API service.
	Use if there is only one service that your
	resource could belong to. If there are multiple
	API versions that support the resource, we will
	attempt to use the preferred version and ask
	for more specific format otherwise.

	Example (Pubsub subscription):
		projects/myproject/subscriptions/mysub
`

const pathListRoleSetHelpSyn = `List existing rolesets.`
const pathListRoleSetHelpDesc = `List created role sets.`

const pathRoleSetRotateAccountHelpSyn = `Rotates or recreates the service account bound to a roleset.`
const pathRoleSetRotateAccountHelpDesc = `
This path allows you to rotate (i.e. recreate) the service account used to
generate secrets for a given role set. This will delete and recreate
the service account, invalidating any old keys/credentials
generated previously.
`

const pathRoleSetRotateKeyHelpSyn = `Rotate the service account key used to generate access tokens for a roleset.`
const pathRoleSetRotateKeyHelpDesc = `
This path allows you to rotate (i.e. recreate) the service account key 
used to generate access tokens under a given role set. This path only
applies to role sets that generate access tokens and will not delete
the associated service account.`
