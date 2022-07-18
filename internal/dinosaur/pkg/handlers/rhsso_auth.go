package handlers

import (
	"github.com/golang/glog"
	"github.com/stackrox/acs-fleet-manager/pkg/errors"
	"github.com/stackrox/acs-fleet-manager/pkg/handlers"
	"net/http"
	"net/url"
)

type authHandler struct {
}

func NewAuthHandler() *authHandler {
	return &authHandler{}
}

func (h authHandler) Config(w http.ResponseWriter, r *http.Request) {
	cfg := &handlers.HandlerConfig{
		Action: func() (i interface{}, serviceError *errors.ServiceError) {
			return openidConfig(), nil
		},
	}
	handlers.HandleGet(w, r, cfg)
}

func (h authHandler) LoginURL(w http.ResponseWriter, r *http.Request) {
	for k, v := range r.URL.Query() {
		glog.Warningf("%s=%v", k, v)
	}
	redirectURL := &url.URL{
		Scheme:   "https",
		Host:     "sso.stage.redhat.com",
		Path:     "/auth/realms/redhat-external/protocol/openid-connect/auth",
		RawQuery: r.URL.Query().Encode(),
	}
	glog.Warning(redirectURL.String())
	w.Header().Set("Location", redirectURL.String())
	w.WriteHeader(http.StatusSeeOther)
}

func (h authHandler) Token(w http.ResponseWriter, r *http.Request) {

}

func openidConfig() map[string]interface{} {
	return map[string]interface{}{
		"issuer":                 "https://7e0f-2a00-cc47-4165-c100-a80b-2adc-24c8-b495.ngrok.io/api/rhacs/auth",
		"authorization_endpoint": "https://7e0f-2a00-cc47-4165-c100-a80b-2adc-24c8-b495.ngrok.io/api/rhacs/auth/protocol/openid-connect/auth",
		"token_endpoint":         "https://7e0f-2a00-cc47-4165-c100-a80b-2adc-24c8-b495.ngrok.io/api/rhacs/auth/protocol/openid-connect/token",
		"introspection_endpoint": "https://7e0f-2a00-cc47-4165-c100-a80b-2adc-24c8-b495.ngrok.io/api/rhacs/auth/protocol/openid-connect/token/introspect",
		"userinfo_endpoint":      "https://7e0f-2a00-cc47-4165-c100-a80b-2adc-24c8-b495.ngrok.io/api/rhacs/auth/protocol/openid-connect/userinfo",
		"end_session_endpoint":   "https://7e0f-2a00-cc47-4165-c100-a80b-2adc-24c8-b495.ngrok.io/api/rhacs/auth/protocol/openid-connect/logout",
		"jwks_uri":               "https://7e0f-2a00-cc47-4165-c100-a80b-2adc-24c8-b495.ngrok.io/api/rhacs/auth/protocol/openid-connect/certs",
		"check_session_iframe":   "https://7e0f-2a00-cc47-4165-c100-a80b-2adc-24c8-b495.ngrok.io/api/rhacs/auth/protocol/openid-connect/login-status-iframe.html",
		"grant_types_supported": []string{
			"authorization_code",
			"implicit",
			"refresh_token",
			"password",
			"client_credentials",
			"urn:ietf:params:oauth:grant-type:device_code",
			"urn:openid:params:grant-type:ciba",
		},
		"response_types_supported": []string{
			"code",
			"none",
			"id_token",
			"token",
			"id_token token",
			"code id_token",
			"code token",
			"code id_token token",
		},
		"subject_types_supported": []string{
			"public",
			"pairwise",
		},
		"id_token_signing_alg_values_supported": []string{
			"PS384",
			"ES384",
			"RS384",
			"HS256",
			"HS512",
			"ES256",
			"RS256",
			"HS384",
			"ES512",
			"PS256",
			"PS512",
			"RS512",
		},
		"id_token_encryption_alg_values_supported": []string{
			"RSA-OAEP",
			"RSA-OAEP-256",
			"RSA1_5",
		},
		"id_token_encryption_enc_values_supported": []string{
			"A256GCM",
			"A192GCM",
			"A128GCM",
			"A128CBC-HS256",
			"A192CBC-HS384",
			"A256CBC-HS512",
		},
		"userinfo_signing_alg_values_supported": []string{
			"PS384",
			"ES384",
			"RS384",
			"HS256",
			"HS512",
			"ES256",
			"RS256",
			"HS384",
			"ES512",
			"PS256",
			"PS512",
			"RS512",
			"none",
		},
		"request_object_signing_alg_values_supported": []string{
			"PS384",
			"ES384",
			"RS384",
			"HS256",
			"HS512",
			"ES256",
			"RS256",
			"HS384",
			"ES512",
			"PS256",
			"PS512",
			"RS512",
			"none",
		},
		"request_object_encryption_alg_values_supported": []string{
			"RSA-OAEP",
			"RSA-OAEP-256",
			"RSA1_5",
		},
		"request_object_encryption_enc_values_supported": []string{
			"A256GCM",
			"A192GCM",
			"A128GCM",
			"A128CBC-HS256",
			"A192CBC-HS384",
			"A256CBC-HS512",
		},
		"response_modes_supported": []string{
			"query",
			"fragment",
			"form_post",
			"query.jwt",
			"fragment.jwt",
			"form_post.jwt",
			"jwt",
		},
		"registration_endpoint": "https://7e0f-2a00-cc47-4165-c100-a80b-2adc-24c8-b495.ngrok.io/api/rhacs/auth/clients-registrations/openid-connect",
		"token_endpoint_auth_methods_supported": []string{
			"private_key_jwt",
			"client_secret_basic",
			"client_secret_post",
			"tls_client_auth",
			"client_secret_jwt",
		},
		"token_endpoint_auth_signing_alg_values_supported": []string{
			"PS384",
			"ES384",
			"RS384",
			"HS256",
			"HS512",
			"ES256",
			"RS256",
			"HS384",
			"ES512",
			"PS256",
			"PS512",
			"RS512",
		},
		"introspection_endpoint_auth_methods_supported": []string{
			"private_key_jwt",
			"client_secret_basic",
			"client_secret_post",
			"tls_client_auth",
			"client_secret_jwt",
		},
		"introspection_endpoint_auth_signing_alg_values_supported": []string{
			"PS384",
			"ES384",
			"RS384",
			"HS256",
			"HS512",
			"ES256",
			"RS256",
			"HS384",
			"ES512",
			"PS256",
			"PS512",
			"RS512",
		},
		"authorization_signing_alg_values_supported": []string{
			"PS384",
			"ES384",
			"RS384",
			"HS256",
			"HS512",
			"ES256",
			"RS256",
			"HS384",
			"ES512",
			"PS256",
			"PS512",
			"RS512",
		},
		"authorization_encryption_alg_values_supported": []string{
			"RSA-OAEP",
			"RSA-OAEP-256",
			"RSA1_5",
		},
		"authorization_encryption_enc_values_supported": []string{
			"A256GCM",
			"A192GCM",
			"A128GCM",
			"A128CBC-HS256",
			"A192CBC-HS384",
			"A256CBC-HS512",
		},
		"claims_supported": []string{
			"aud",
			"sub",
			"iss",
			"auth_time",
			"name",
			"given_name",
			"family_name",
			"preferred_username",
			"email",
			"acr",
		},
		"claim_types_supported": []string{
			"normal",
		},
		"claims_parameter_supported": true,
		"scopes_supported": []string{
			"openid",
			"profile",
			"client_type.org_service_account",
			"openshiftonlinefree",
			"fuseignitepro",
			"quayio",
			"phone",
			"minuser",
			"web-origins",
			"offline_access",
			"rhdsolp",
			"user.account_info",
			"address",
			"rhdfull",
			"rhbase",
			"rhdsupportable",
			"email",
			"rhdmin",
			"fuseignite",
			"openshiftio",
			"api.iam.service_accounts",
			"openshiftonlinepro",
			"rhfull",
			"groups",
			"supportable",
			"nameandterms",
			"rhdbulkinvite",
			"Legacy_IDP_OpenID",
			"openshiftuhc",
			"codereadytoolchain",
			"microprofile-jwt",
			"amqonline",
			"jbossorg",
			"openshiftonlinededicated",
			"rhproducteval",
			"roles",
			"rhopenbanking",
		},
		"request_parameter_supported":      true,
		"request_uri_parameter_supported":  true,
		"require_request_uri_registration": true,
		"code_challenge_methods_supported": []string{
			"plain",
			"S256",
		},
		"tls_client_certificate_bound_access_tokens": true,
		"revocation_endpoint":                        "https://7e0f-2a00-cc47-4165-c100-a80b-2adc-24c8-b495.ngrok.io/api/rhacs/auth/protocol/openid-connect/revoke",
		"require_pushed_authorization_requests":      false,
		"pushed_authorization_request_endpoint":      "https://7e0f-2a00-cc47-4165-c100-a80b-2adc-24c8-b495.ngrok.io/api/rhacs/auth/protocol/openid-connect/ext/par/request",
		"mtls_endpoint_aliases": map[string]string{
			"token_endpoint":                        "https://7e0f-2a00-cc47-4165-c100-a80b-2adc-24c8-b495.ngrok.io/api/rhacs/auth/protocol/openid-connect/token",
			"revocation_endpoint":                   "https://7e0f-2a00-cc47-4165-c100-a80b-2adc-24c8-b495.ngrok.io/api/rhacs/auth/protocol/openid-connect/revoke",
			"introspection_endpoint":                "https://7e0f-2a00-cc47-4165-c100-a80b-2adc-24c8-b495.ngrok.io/api/rhacs/auth/protocol/openid-connect/token/introspect",
			"device_authorization_endpoint":         "https://7e0f-2a00-cc47-4165-c100-a80b-2adc-24c8-b495.ngrok.io/api/rhacs/auth/protocol/openid-connect/auth/device",
			"registration_endpoint":                 "https://7e0f-2a00-cc47-4165-c100-a80b-2adc-24c8-b495.ngrok.io/api/rhacs/auth/clients-registrations/openid-connect",
			"userinfo_endpoint":                     "https://7e0f-2a00-cc47-4165-c100-a80b-2adc-24c8-b495.ngrok.io/api/rhacs/auth/protocol/openid-connect/userinfo",
			"pushed_authorization_request_endpoint": "https://7e0f-2a00-cc47-4165-c100-a80b-2adc-24c8-b495.ngrok.io/api/rhacs/auth/protocol/openid-connect/ext/par/request",
			"backchannel_authentication_endpoint":   "https://7e0f-2a00-cc47-4165-c100-a80b-2adc-24c8-b495.ngrok.io/api/rhacs/auth/protocol/openid-connect/ext/ciba/auth",
		},
	}
}
