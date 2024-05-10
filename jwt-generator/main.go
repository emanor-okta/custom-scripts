package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/okta/okta-sdk-golang/v2/okta"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
)

const SSWS = "00QMAh2TiEwwEqj5K2FjSzKgv30z3xvJnxalmSA0Na"

func main() {

	const src = `
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAyF1M5A3ev9KXr6GCsodM+YXBNZ5kC8N7gIO2F3IkbUikhFyd
...
kWHvKiRcEwWQf+QNJAyuA/8dBYos/b/S7E5JDmAMNVm9HV23S/cukw==
-----END RSA PRIVATE KEY-----`

	privkey, err := jwk.ParseKey([]byte(src), jwk.WithPEM(true))
	if err != nil {
		fmt.Printf("failed to parse JWK: %s\n", err)
	}
	//fmt.Printf("%+v\n", privkey)
	json.NewEncoder(os.Stdout).Encode(privkey)

	pubkey, err := jwk.PublicKeyOf(privkey)
	if err != nil {
		fmt.Printf("failed to get public key: %s\n", err)
	}

	fmt.Printf("%+v\n", pubkey)
	json.NewEncoder(os.Stdout).Encode(pubkey)
	pubKeyJson, _ := json.Marshal(pubkey)
	fmt.Printf("\nKEY\n%v\n\n", pubKeyJson)

	hdrs := jws.NewHeaders()
	hdrs.Set(`kid`, "terraform_kid")
	buf, err := jws.Sign([]byte("Lorem ipsum"), jws.WithKey(jwa.RS256, privkey, jws.WithProtectedHeaders(hdrs)))
	if err != nil {
		fmt.Printf("failed to sign payload: %s\n", err)
		return
	}
	fmt.Printf("%s\n", buf)

	client := getOktaClient()
	//testClient(client)
	createServiceApp(client, pubKeyJson, privkey)
}

func createServiceApp(client *okta.Client, pubKeyJson []byte, privkey jwk.Key) {
	/*
		// app := okta.OpenIdConnectApplication{}
		app := okta.NewOpenIdConnectApplication()
		app.Label = "test_1"
		settings := okta.OpenIdConnectApplicationSettings{}
		a := okta.ApplicationSettingsApplication{}
		a["client_name"] = "test"
		settings.App = &a
		oauthClient := okta.OpenIdConnectApplicationSettingsClient{}
		oauthClient.ApplicationType = "service"
		responseTypes := make([]*okta.OAuthResponseType, 1)
		responseType := okta.OAuthResponseType("token")
		responseTypes[0] = &responseType
		grantTypes := make([]*okta.OAuthGrantType, 1)
		grantType := okta.OAuthGrantType("client_credentials")
		grantTypes[0] = &grantType
		keys := make([]*okta.JsonWebKey, 1)
		json.Unmarshal(pubKeyJson, keys[0])
		jwks := okta.OpenIdConnectApplicationSettingsClientKeys{Keys: keys}
		oauthClient.ResponseTypes = responseTypes
		oauthClient.GrantTypes = grantTypes
		oauthClient.Jwks = &jwks
		settings.OauthClient = &oauthClient
		app.Settings = &settings
	*/

	type service struct {
		ClientName              string                 `json:"client_name,omitempty"`
		ResponseTypes           []string               `json:"response_types,omitempty"`
		GrantTypes              []string               `json:"grant_types,omitempty"`
		TokenEndpointAuthMethod string                 `json:"token_endpoint_auth_method,omitempty"`
		ApplicationType         string                 `json:"application_type,omitempty"`
		Jwks                    map[string]interface{} `json:"jwks,omitempty"`
	}

	s := service{}
	s.ApplicationType = "service"
	s.ClientName = "Test_1"
	s.GrantTypes = []string{"client_credentials"}
	s.TokenEndpointAuthMethod = "private_key_jwt"
	s.ResponseTypes = []string{"token"}
	s.Jwks = make(map[string]interface{}, 1)
	//s.Jwks["keys"][0] = make(map[string]string)

	k := `{"kid":"terraform_kid","e":"AQAB","kty":"RSA","n":"yF1M5A3ev9KXr6GCsodM-YXBNZ5kC8N7gIO2F3IkbUikhFydQmCUYDs9OmbEkfTL3xltg2CQ43HzaJm9D6CCTogxF2GLkSsnnY3mcNNA6EnITdv11AV0GYtR5KI3F7EcVhbWdYh3Q7jywGdSTESwoULTXsuPtY3oLtKDm2ewKqARzFUfPWDky0a_xJ4KPRcOwtG_F7h4L4L1pVWo5QsJ60YYBNaZ82ug04-UttMLt0GSxkzQmjvC_cXJzCSQ3dFoyaTYWxzE7Mv5WJDM6eOSkOBNskUYs5FWj3Pg6KRP0rlAYEtGeUVH6L-ccvJhWeSFVHKp0DhkxykvP8I8xmoPfw"}`
	m := make(map[string]string)
	json.Unmarshal([]byte(k), &m)

	keys2 := make([]map[string]string, 1)
	keys2[0] = m

	s.Jwks["keys"] = keys2

	fmt.Printf("\n\n%+v\n\n", s)

	// req, err := client.CloneRequestExecutor().NewRequest("POST", "/oauth2/v1/clients", s)
	// if err != nil {
	// 	fmt.Printf("Error creating new request: %v\n", err)
	// }

	// var openId *okta.OpenIdConnectApplication
	// //var s2 *service
	// resp, err := client.CloneRequestExecutor().Do(context.TODO(), req, openId)
	// if err != nil {
	// 	fmt.Printf("Error executing request: %v\n", err)
	// }

	// fmt.Printf("\n Response: %+v\n\n%+v\n\n", resp.Response, openId)
	// body := map[string]interface{}{}
	// json.NewDecoder(resp.Response.Body).Decode(&body)
	// fmt.Printf("\n%+v\n\n", body["client_id"])
	// clientId := body["client_id"]

	// url := fmt.Sprintf("https://oie.erikdevelopernot.com/api/v1/apps/%s/grants", clientId)
	// method := "POST"
	// payload := strings.NewReader(`{"scopeId": "okta.apps.read","issuer": "https://oie.erikdevelopernot.com"}`)
	// grantResp, err := httpRequest(method, url, "application/json", fmt.Sprintf("SSWS %s", SSWS), payload)
	// if err != nil {
	// 	os.Exit(1)
	// }
	// fmt.Printf("grantResp: %s\n", grantResp)

	clientId := "0oa7hcsubqTK2OijK1d7"

	jwtPayload := fmt.Sprintf(`{"aud": "https://emanor-oie.oktapreview.com/oauth2/v1/token","iss": "%s","sub": "%s","exp": "%v"}`, clientId, clientId, time.Now().Unix())

	hdrs := jws.NewHeaders()
	hdrs.Set(`kid`, "key1")
	buf, err := jws.Sign([]byte(jwtPayload), jws.WithKey(jwa.RS256, privkey, jws.WithProtectedHeaders(hdrs)))
	if err != nil {
		fmt.Printf("failed to sign payload: %s\n", err)
		return
	}
	fmt.Printf("%s\n", buf)

	url := "https://emanor-oie.oktapreview.com/oauth2/v1/token"
	payload := strings.NewReader(fmt.Sprintf(`grant_type=client_credentials&redirect_uri=http://localhost:8080/redirect&scope=okta.users.read&client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer&client_assertion=%s`, buf))
	tokenResp, err := httpRequest("POST", url, "application/x-www-form-urlencoded", "", payload)
	if err != nil {
		os.Exit(1)
	}
	fmt.Printf("tokenResp: %s\n", tokenResp)

	// httpClient := &http.Client{}
	// req, err = http.NewRequest(method, url, payload)
	// if err != nil {
	// 	fmt.Println(err)
	// 	return
	// }
	// req.Header.Add("Accept", "application/json")
	// req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	// res, err := httpClient.Do(req)
	// if err != nil {
	// 	fmt.Println(err)
	// 	return
	// }
	// defer res.Body.Close()

	// body2, err := ioutil.ReadAll(res.Body)
	// if err != nil {
	// 	fmt.Println(err)
	// 	return
	// }
	// fmt.Println(string(body2))

}

func httpRequest(method, url, contentType, authorization string, payload *strings.Reader) (string, error) {
	httpClient := &http.Client{}
	req, err := http.NewRequest(method, url, payload)
	if err != nil {
		fmt.Println(err)
		return "", err
	}
	req.Header.Add("Accept", "application/json")
	req.Header.Add("Content-Type", contentType)
	//req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	if authorization != "" {
		req.Header.Add("Authorization", authorization)
	}

	res, err := httpClient.Do(req)
	if err != nil {
		fmt.Println(err)
		return "", err
	}
	defer res.Body.Close()

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		fmt.Println(err)
		return "", err
	}
	fmt.Println(string(body))

	return string(body), nil
}

func getOktaClient() *okta.Client {
	_, client, err := okta.NewClient(context.TODO(), okta.WithOrgUrl("https://oie.erikdevelopernot.com"), okta.WithToken("00QMAh2TiEwwEqj5K2FjSzKgv30z3xvJnxalmSA0Na"))

	if err != nil {
		fmt.Errorf("Error: %v\n", err)
	}

	return client
}

func testClient(client *okta.Client) {
	user, resp, err := client.User.GetUser(context.TODO(), "emanor.okta3@gmail.com")
	if err != nil {
		fmt.Printf("Error Getting User: %v\n", err)
	}
	fmt.Printf("User: %+v\n Response: %+v\n\n", user, resp)
}
