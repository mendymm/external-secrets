package v1beta1

import (
	esmeta "github.com/external-secrets/external-secrets/apis/meta/v1"
)

// OnePasswordSdkAuth contains a secretRef for the service account token.
type OnePasswordSdkAuth struct {
	ServiceAccountSecretRef esmeta.SecretKeySelector `json:"serviceAccountSecretRef"`
}

// OnePasswordSdkProvider configures a store to sync secrets using the 1Password sdk.
type OnePasswordSdkProvider struct {
	// Auth defines the information necessary to authenticate against OnePassword API
	Auth *OnePasswordSdkAuth `json:"auth"`
}
