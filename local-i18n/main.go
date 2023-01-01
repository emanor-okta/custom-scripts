package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
	"time"
)

func main() {
	http.HandleFunc("/assets/dist/labels/json/", handleI18nPropertyReq)
	http.HandleFunc("/parent.html", handleParentReq)
	http.HandleFunc("/oauth2/v1/authorize", handleAuthorizeReq)

	http.HandleFunc("/oauth2/default/.well-known/openid-configuration", handleConfig)
	http.HandleFunc("/oauth2/default/v1/keys", handleKeys)

	testKeys()
	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatalf("Server startup failed: %s\n", err)
	}
}

func handleI18nPropertyReq(res http.ResponseWriter, req *http.Request) {
	fmt.Printf("Received Request:\n%v\n", req.RequestURI)
	res.Header().Add("access-control-allow-origin", "*")
	b, err := ioutil.ReadFile(fmt.Sprintf("./properties/%v", strings.Split(req.RequestURI, "/")[5]))
	if err != nil {
		fmt.Printf("handleLogin - Error reading json: %v\n", err)
		res.WriteHeader(http.StatusInternalServerError)
		res.Write(nil)
		return
	}

	// fmt.Println(string(b))
	var m map[string]interface{}
	if err = json.Unmarshal(b, &m); err != nil {
		fmt.Printf("Unmarshal Error: %v\n", err)
		res.WriteHeader(http.StatusInternalServerError)
		res.Write(nil)
		return
	}

	b, _ = json.Marshal(m)
	if _, err := res.Write(b); err != nil {
		fmt.Println(err)
	}
}

func handleConfig(res http.ResponseWriter, req *http.Request) {
	// for _, i := range []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10} {
	// 	fmt.Printf("handleConfig sleepng: %v\n", i)
	// 	time.Sleep(time.Minute * 1)
	// 	fmt.Println("handleConfig Done sleeping")
	// }

	// t := http.DefaultTransport
	// t.IdleConnTimeout = time.Second * 5
	//t := http.Transport{IdleConnTimeout: time.Second * 5}
	//t.IdleConnTimeout = time.Second * 5
	config := `{"issuer":"https://okta.oktamanor.com/oauth2/default","authorization_endpoint":"https://okta.oktamanor.com/oauth2/default/v1/authorize","token_endpoint":"https://okta.oktamanor.com/oauth2/default/v1/token","userinfo_endpoint":"https://okta.oktamanor.com/oauth2/default/v1/userinfo","registration_endpoint":"https://okta.oktamanor.com/oauth2/v1/clients","jwks_uri":"http://localhost:8082/oauth2/default/v1/keys","response_types_supported":["code","id_token","code id_token","code token","id_token token","code id_token token"],"response_modes_supported":["query","fragment","form_post","okta_post_message"],"grant_types_supported":["authorization_code","implicit","refresh_token","password","urn:ietf:params:oauth:grant-type:device_code"],"subject_types_supported":["public"],"id_token_signing_alg_values_supported":["RS256"],"scopes_supported":["openid","profile","email","address","phone","offline_access","device_sso"],"token_endpoint_auth_methods_supported":["client_secret_basic","client_secret_post","client_secret_jwt","private_key_jwt","none"],"claims_supported":["iss","ver","sub","aud","iat","exp","jti","auth_time","amr","idp","nonce","name","nickname","preferred_username","given_name","middle_name","family_name","email","email_verified","profile","zoneinfo","locale","address","phone_number","picture","website","gender","birthdate","updated_at","at_hash","c_hash"],"code_challenge_methods_supported":["S256"],"introspection_endpoint":"https://okta.oktamanor.com/oauth2/default/v1/introspect","introspection_endpoint_auth_methods_supported":["client_secret_basic","client_secret_post","client_secret_jwt","private_key_jwt","none"],"revocation_endpoint":"https://okta.oktamanor.com/oauth2/default/v1/revoke","revocation_endpoint_auth_methods_supported":["client_secret_basic","client_secret_post","client_secret_jwt","private_key_jwt","none"],"end_session_endpoint":"https://okta.oktamanor.com/oauth2/default/v1/logout","request_parameter_supported":true,"request_object_signing_alg_values_supported":["HS256","HS384","HS512","RS256","RS384","RS512","ES256","ES384","ES512"],"device_authorization_endpoint":"https://okta.oktamanor.com/oauth2/default/v1/device/authorize"}`
	res.Write([]byte(config))
}

func handleKeys(res http.ResponseWriter, req *http.Request) {
	for _, i := range []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10} {
		fmt.Printf("handleKeys sleepng: %v\n", i)
		time.Sleep(time.Minute * 1)
		fmt.Println("handleKeys Done sleeping")
	}

	keys := `{"keys":[{"kty":"RSA","alg":"RS256","kid":"razBEsBCiFqyT0lXOiApfhbh2BoNZGyUpEAulxldM0Y","use":"sig","e":"AQAB","n":"utGPRZ6TWiI534q_m9Bio1CI4Rh8ZS7LkwE-O_KRb86bveWg7_bm5p7VZ1szLsZqsKzOHC-EhyMeXZ09bJPoqjHaEk3epDnl3EzN1uh_va9VSCCYo4Fp6K7ykkxpvJTEud0V9lxBG-7JnSpy0GdYWqdZx2X0LqfUP5XWdPftYeLlQ_JRl58syLkvbN1q2Rta07Gu26Eo0W1uz4S6y1MeWyZ-bZAZJWLhEqND3ACl519oqJSIMxFZtgkKwo5LrdIK1AzFsI9VENiCVe9AvAJqU88zWDWXxKkfURfNq48O6B1jQ5FUBtiis-ufVGLR8xbnhMo-t456pwIrFGOV2qWihw"},{"kty":"RSA","alg":"RS256","kid":"bewJ96TXmzSBeu-hznd-s506EpcvgtigmkaMTB3Iztk","use":"sig","e":"AQAB","n":"5Qkrj_urDTOeDBil-NwfRg5l-r0sS7fapLYoJTWqwNMbiYu4nyWh20MU9Fs9cf-fKORWG9U-nIWvQzXE6aHE73k_7l9dmxl1bPQQYXVScoYhwWJUdqwjrdtQWFoJUa9LCqjHUipuzUHnGIm-b3CC7S7G1PziOfmm_Dh4Nn6N6ZrR58DKMTnjqhaW6V7jf4vlT0BLqjIyIfz27H0IQPU7eFk1uYr-LQAsD71SyGYpUB3yjXInoSj5O6Zf1PQfTzGM3TMBuxy9_3uqyTqRzC7I2ALOHoax0v0Ay4tPoMVrqnzrjK7RucSLmtdcIV2_5bBP_TsY7U8nOZCdDLsk7jn3OQ"}]}`
	res.Write([]byte(keys))
}

func handleParentReq(res http.ResponseWriter, req *http.Request) {
	fmt.Printf("Received Request:\n%v\n", req.RequestURI)
	res.Header().Add("Cross-Origin-Embedder-Policy", "require-corp")
	res.Header().Add("Cross-Origin-Opener-Policy", "same-origin")
	b, err := ioutil.ReadFile("./html/parent.html")
	if err != nil {
		fmt.Printf("handleParentReq - Error reading html: %v\n", err)
		res.WriteHeader(http.StatusInternalServerError)
		res.Write(nil)
		return
	}

	if _, err := res.Write(b); err != nil {
		fmt.Println(err)
	}
}

func handleAuthorizeReq(res http.ResponseWriter, req *http.Request) {
	fmt.Printf("Received Request:\n%v\n", req.RequestURI)
	res.Header().Add("Cross-Origin-Embedder-Policy", "require-corp")
	res.Header().Add("Cross-Origin-Resource-Policy", "cross-origin")
	// b, err := ioutil.ReadFile("./html/parent.html")
	// if err != nil {
	// 	fmt.Printf("handleParentReq - Error reading html: %v\n", err)
	// 	res.WriteHeader(http.StatusInternalServerError)
	// 	res.Write(nil)
	// 	return
	// }
	html := "<html><body>hello</body></html>"
	if _, err := res.Write([]byte(html)); err != nil {
		fmt.Println(err)
	}
}

func testKeys() {
	done := make(chan bool, 100)
	t1 := time.Now()
	for i := 1; i <= 100; i++ {
		go getKeys(i, 60, done)
	}
	<-done
	t2 := time.Now()
	fmt.Printf("Started at: %v, finished at: %v\n", t1, t2)
}

func getKeys(n, c int, done chan bool) {
	for i := 1; i <= c; i++ {
		res, err := http.Get("https://essentialenergy.okta.com/oauth2/ausybuegau5JryVLT2p6/v1/keys")
		if err != nil {
			log.Fatal(err)
		}
		body, err := ioutil.ReadAll(res.Body)
		res.Body.Close()
		if res.StatusCode > 299 {
			log.Fatalf("Response failed with status code: %d and\nbody: %s\n", res.StatusCode, body)
		}
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("%v:%v - %s\n", n, i, body)
	}
	done <- true
}
