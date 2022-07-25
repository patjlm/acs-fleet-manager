package handlers

import (
	"bytes"
	"fmt"
	"github.com/golang/glog"
	"github.com/google/uuid"
	"github.com/stackrox/acs-fleet-manager/pkg/errors"
	"github.com/stackrox/acs-fleet-manager/pkg/handlers"
	"github.com/stackrox/rox/pkg/stringutils"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
)

var oldRedirectURIs map[string]string

func init() {
	oldRedirectURIs = make(map[string]string, 0)
}

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

	oldRedirectURI := r.URL.Query().Get("redirect_uri")
	state := r.URL.Query().Get("state")
	requestID := uuid.New().String()
	glog.Warningf("Generated requestID: %s", requestID)
	oldRedirectURIs[requestID] = oldRedirectURI
	state = state + ":" + requestID

	query := r.URL.Query()
	query.Set("redirect_uri", "<fleet-manager-dns-name>/api/rhacs/auth/redirect")
	query.Set("state", state)

	redirectURL := &url.URL{
		Scheme:   "https",
		Host:     "sso.stage.redhat.com",
		Path:     "/auth/realms/redhat-external/protocol/openid-connect/auth",
		RawQuery: query.Encode(),
	}
	glog.Warning(redirectURL.String())
	w.Header().Set("Location", redirectURL.String())
	w.WriteHeader(http.StatusSeeOther)
}

func (h authHandler) Redirect(w http.ResponseWriter, r *http.Request) {
	state := r.URL.Query().Get("state")
	state, requestID := stringutils.Split2Last(state, ":")
	resultingQuery := r.URL.Query()
	resultingQuery.Set("state", state)
	if redPath, ok := oldRedirectURIs[requestID]; ok {
		for head, values := range r.Header {
			for _, val := range values {
				w.Header().Add(head, val)
			}
		}
		w.Header().Set("Location", redPath+"?"+resultingQuery.Encode())
		w.WriteHeader(http.StatusSeeOther)
	} else {
		panic(fmt.Sprintf("no redirectURI with id: %s", requestID))
	}
}

func (h authHandler) Token(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		panic(err)
	}
	r.Form.Set("redirect_uri", "<fleet-manager-dns-name>/api/rhacs/auth/redirect")
	newUrl := &url.URL{
		Scheme:   "https",
		Host:     "sso.stage.redhat.com",
		Path:     "/auth/realms/redhat-external/protocol/openid-connect/token",
		RawQuery: r.URL.Query().Encode(),
	}
	reader := ioutil.NopCloser(bytes.NewBuffer([]byte(r.Form.Encode())))
	newReq, err := http.NewRequest(http.MethodPost, newUrl.String(), reader)
	if err != nil {
		panic(err)
	}
	newReq.Header = make(http.Header)
	for head, val := range r.Header {
		if head == "Authorization" || head == "Content-Type" {
			newReq.Header[head] = val
		}
	}

	resp, err := http.DefaultClient.Do(newReq)
	if err != nil {
		panic(err)
	}

	if resp.StatusCode != http.StatusOK {
		defer resp.Body.Close()

		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			glog.Fatal(err)
		}
		bodyString := string(bodyBytes)
		glog.Info(bodyString)
		glog.Info(resp.StatusCode)
	} else {
		for head, val := range resp.Header {
			for _, v := range val {
				w.Header().Set(head, v)
			}
		}
		if _, err := io.Copy(w, resp.Body); err != nil {
			panic(err)
		}
	}
}

func (h authHandler) Certs(w http.ResponseWriter, r *http.Request) {
	resp, err := http.Get("https://sso.stage.redhat.com/auth/realms/redhat-external/protocol/openid-connect/certs")
	if err != nil {
		panic(err)
	}
	for head, val := range resp.Header {
		for _, v := range val {
			w.Header().Set(head, v)
		}
	}
	if _, err := io.Copy(w, resp.Body); err != nil {
		panic(err)
	}
}

func openidConfig() map[string]interface{} {
	return map[string]interface{}{
		"issuer":                 "<fleet-manager-dns-name>/api/rhacs/auth",
		"authorization_endpoint": "<fleet-manager-dns-name>/api/rhacs/auth/protocol/openid-connect/auth",
		"token_endpoint":         "<fleet-manager-dns-name>/api/rhacs/auth/protocol/openid-connect/token",
		"introspection_endpoint": "<fleet-manager-dns-name>/api/rhacs/auth/protocol/openid-connect/token/introspect",
		"userinfo_endpoint":      "<fleet-manager-dns-name>/api/rhacs/auth/protocol/openid-connect/userinfo",
		"end_session_endpoint":   "<fleet-manager-dns-name>/api/rhacs/auth/protocol/openid-connect/logout",
		"jwks_uri":               "<fleet-manager-dns-name>/api/rhacs/auth/protocol/openid-connect/certs",
		"check_session_iframe":   "<fleet-manager-dns-name>/api/rhacs/auth/protocol/openid-connect/login-status-iframe.html",
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
			//"fragment",
			//"form_post",
			//"query.jwt",
			//"fragment.jwt",
			//"form_post.jwt",
			//"jwt",
		},
		"registration_endpoint": "<fleet-manager-dns-name>/api/rhacs/auth/clients-registrations/openid-connect",
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
		"revocation_endpoint":                        "<fleet-manager-dns-name>/api/rhacs/auth/protocol/openid-connect/revoke",
		"require_pushed_authorization_requests":      false,
		"pushed_authorization_request_endpoint":      "<fleet-manager-dns-name>/api/rhacs/auth/protocol/openid-connect/ext/par/request",
		"mtls_endpoint_aliases": map[string]string{
			"token_endpoint":                        "<fleet-manager-dns-name>/api/rhacs/auth/protocol/openid-connect/token",
			"revocation_endpoint":                   "<fleet-manager-dns-name>/api/rhacs/auth/protocol/openid-connect/revoke",
			"introspection_endpoint":                "<fleet-manager-dns-name>/api/rhacs/auth/protocol/openid-connect/token/introspect",
			"device_authorization_endpoint":         "<fleet-manager-dns-name>/api/rhacs/auth/protocol/openid-connect/auth/device",
			"registration_endpoint":                 "<fleet-manager-dns-name>/api/rhacs/auth/clients-registrations/openid-connect",
			"userinfo_endpoint":                     "<fleet-manager-dns-name>/api/rhacs/auth/protocol/openid-connect/userinfo",
			"pushed_authorization_request_endpoint": "<fleet-manager-dns-name>/api/rhacs/auth/protocol/openid-connect/ext/par/request",
			"backchannel_authentication_endpoint":   "<fleet-manager-dns-name>/api/rhacs/auth/protocol/openid-connect/ext/ciba/auth",
		},
	}
}
