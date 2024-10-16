package onepasswordsdk

import (
	"context"
	"errors"
	"fmt"

	"github.com/1password/onepassword-sdk-go"
	esv1beta1 "github.com/external-secrets/external-secrets/apis/externalsecrets/v1beta1"
	"github.com/external-secrets/external-secrets/pkg/utils"
	"github.com/external-secrets/external-secrets/pkg/utils/resolvers"
	v1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

const (
	errOnePasswordSdkStore                              = "received invalid 1PasswordSdk SecretStore resource: %w"
	errOnePasswordSdkStoreNilSpec                       = "nil spec"
	errOnePasswordSdkStoreNilSpecProvider               = "nil spec.provider"
	errOnePasswordSdkStoreNilSpecProviderOnePasswordSdk = "nil spec.provider.onepasswordsdk"
	errOnePasswordSdkStoreMissingRefName                = "missing: spec.provider.onepasswordsdk.auth.secretRef.serviceAccountTokenSecretRef.name"
	errOnePasswordSdkStoreMissingRefKey                 = "missing: spec.provider.onepasswordsdk.auth.secretRef.serviceAccountTokenSecretRef.key"

	errVersionNotImplemented = "'remoteRef.version' is not implemented in the 1Password SDK provider"
	errDeleteNotImplemented  = "DeleteSecret is not supported"

	errNotImplemented = "not implemented"
)

type ProviderOnePasswordSdk struct {
	client onepassword.Client
}

// Capabilities implements v1beta1.Provider.
func (provider *ProviderOnePasswordSdk) Capabilities() esv1beta1.SecretStoreCapabilities {
	return esv1beta1.SecretStoreReadOnly
}

// NewClient implements v1beta1.Provider.
func (provider *ProviderOnePasswordSdk) NewClient(ctx context.Context, store esv1beta1.GenericStore, kube client.Client, namespace string) (esv1beta1.SecretsClient, error) {
	config := store.GetSpec().Provider.OnePasswordSdk
	serviceAccountToken, err := resolvers.SecretKeyRef(
		ctx,
		kube,
		store.GetKind(),
		namespace,
		&config.Auth.ServiceAccountSecretRef,
	)
	if err != nil {
		return nil, err
	}
	client, err := onepassword.NewClient(
		ctx,
		onepassword.WithServiceAccountToken(serviceAccountToken),
		// TODO: Set the following to your own integration name and version.
		onepassword.WithIntegrationInfo("My 1Password Integration", "v1.0.0"),
	)
	if err != nil {
		return nil, err
	}
	provider.client = *client

	return provider, nil
}

// ValidateStore checks if the provided store is valid.
func (provider *ProviderOnePasswordSdk) ValidateStore(store esv1beta1.GenericStore) (admission.Warnings, error) {
	return nil, validateStore(store)
}

func validateStore(store esv1beta1.GenericStore) error {
	storeSpec := store.GetSpec()
	if storeSpec == nil {
		return fmt.Errorf(errOnePasswordSdkStore, errors.New(errOnePasswordSdkStoreNilSpec))
	}
	if storeSpec.Provider == nil {
		return fmt.Errorf(errOnePasswordSdkStore, errors.New(errOnePasswordSdkStoreNilSpecProvider))
	}
	if storeSpec.Provider.OnePasswordSdk == nil {
		return fmt.Errorf(errOnePasswordSdkStore, errors.New(errOnePasswordSdkStoreNilSpecProviderOnePasswordSdk))
	}

	config := storeSpec.Provider.OnePasswordSdk
	if config.Auth.ServiceAccountSecretRef.Name == "" {
		return fmt.Errorf(errOnePasswordSdkStore, errors.New(errOnePasswordSdkStoreMissingRefName))
	}
	if config.Auth.ServiceAccountSecretRef.Key == "" {
		return fmt.Errorf(errOnePasswordSdkStore, errors.New(errOnePasswordSdkStoreMissingRefKey))
	}

	// check namespace compared to kind
	if err := utils.ValidateSecretSelector(store, config.Auth.ServiceAccountSecretRef); err != nil {
		return fmt.Errorf(errOnePasswordSdkStore, err)
	}

	return nil

}

// GetSecret returns a single secret from the provider.
func (provider *ProviderOnePasswordSdk) GetSecret(ctx context.Context, ref esv1beta1.ExternalSecretDataRemoteRef) ([]byte, error) {
	if ref.Version != "" {
		return nil, errors.New(errVersionNotImplemented)
	}
	// TODO: maybe return an error if the ref.Key is not a valid op url ("op://vault/item/field")
	secret, err := provider.client.Secrets.Resolve(ctx, ref.Key)
	if err != nil {
		return nil, err
	}
	return []byte(secret), nil
}

// Close closes the client connection.
func (provider *ProviderOnePasswordSdk) Close(_ context.Context) error {
	return nil
}

// DeleteSecret Not Implemented
func (provider *ProviderOnePasswordSdk) DeleteSecret(ctx context.Context, remoteRef esv1beta1.PushSecretRemoteRef) error {
	return fmt.Errorf(errOnePasswordSdkStore, errors.New(errNotImplemented))
}

// GetAllSecrets implements v1beta1.SecretsClient.
func (provider *ProviderOnePasswordSdk) GetAllSecrets(ctx context.Context, ref esv1beta1.ExternalSecretFind) (map[string][]byte, error) {
	panic("unimplemented")
}

// GetSecretMap implements v1beta1.SecretsClient.
func (provider *ProviderOnePasswordSdk) GetSecretMap(ctx context.Context, ref esv1beta1.ExternalSecretDataRemoteRef) (map[string][]byte, error) {
	panic("unimplemented")
}

// PushSecret Not Implemented
func (provider *ProviderOnePasswordSdk) PushSecret(ctx context.Context, secret *v1.Secret, data esv1beta1.PushSecretData) error {
	return fmt.Errorf(errOnePasswordSdkStore, errors.New(errNotImplemented))
}

// SecretExists Not Implemented.
func (provider *ProviderOnePasswordSdk) SecretExists(ctx context.Context, remoteRef esv1beta1.PushSecretRemoteRef) (bool, error) {
	return false, fmt.Errorf(errOnePasswordSdkStore, errors.New(errNotImplemented))
}

// Validate checks if the client is configured correctly
// currently only checks if it is possible to list vaults
func (provider *ProviderOnePasswordSdk) Validate() (esv1beta1.ValidationResult, error) {
	// TODO: maybe try to list a secret
	// although this may not be ideal, since by getting a secret the an entry is added to the audit log
	// this may confuse users, as they don't know why this entry is getting revealed
	vaults, err := provider.client.Vaults.ListAll(context.TODO())
	if err != nil {
		return esv1beta1.ValidationResultError, err
	}
	_, err = vaults.Next()
	if err != nil {
		return esv1beta1.ValidationResultError, err
	}
	return esv1beta1.ValidationResultReady, nil
}

func init() {
	esv1beta1.Register(&ProviderOnePasswordSdk{}, &esv1beta1.SecretStoreProvider{
		OnePasswordSdk: &esv1beta1.OnePasswordSdkProvider{},
	})
}
