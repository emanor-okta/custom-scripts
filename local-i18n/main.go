package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func main() {
	verifySig()
	http.HandleFunc("/assets/dist/labels/json/", handleI18nPropertyReq)
	http.HandleFunc("/parent.html", handleParentReq)
	http.HandleFunc("/oauth2/v1/authorize", handleAuthorizeReq)
	http.HandleFunc("/oauth2/v1/token", handleTokenReq)
	http.HandleFunc("/fb", handleFB)

	http.HandleFunc("/oauth2/default/.well-known/openid-configuration", handleConfig)
	http.HandleFunc("/oauth2/default/v1/keys", handleKeys)
	http.HandleFunc("/keys", handleServiceKeys)

	// testKeys()
	fmt.Println("setup proxy")
	handleProxySetup()
	fmt.Println("Done setup")

	if err := http.ListenAndServe(":8082", nil); err != nil {
		log.Fatalf("Server startup failed: %s\n", err)
	}
}

func handleI18nPropertyReq(res http.ResponseWriter, req *http.Request) {
	fmt.Printf("Received Request:\n%v\n", req.RequestURI)
	res.Header().Add("access-control-allow-origin", "*")
	b, err := os.ReadFile(fmt.Sprintf("./properties/%v", strings.Split(req.RequestURI, "/")[5]))
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

func handleFB(res http.ResponseWriter, req *http.Request) {
	fmt.Printf("Received Request:\n%v\n", req.RequestURI)
	res.Header().Add("access-control-allow-origin", "*")
	b, err := ioutil.ReadFile("./properties/fb.png")
	if err != nil {
		fmt.Printf("handleFB - Error reading png: %v\n", err)
		res.WriteHeader(http.StatusInternalServerError)
		res.Write(nil)
		return
	}
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

func handleProxySetup() {
	httpbin, _ := url.Parse("https://httpbin.org")
	proxy := httputil.NewSingleHostReverseProxy(httpbin)
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Printf("proxy: RequestURI=%s\n", r.RequestURI)
		proxy.ServeHTTP(w, r)
		// m := w.Header()
		// fmt.Printf("%+v\n", m[""])
		for k, v := range w.Header() {
			fmt.Printf("%v : %v\n", k, v)
		}
	})
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

func handleServiceKeys(res http.ResponseWriter, req *http.Request) {
	// keys := `{"keys":[{"kty":"RSA","e":"AQAB","kid":"4vMiWTLn9nvEKliV67HyXnVRpWE0harVegnEh8v-nnc","n":"sva1f8Vj1G025BxzdIC1hpYy7hAyegbMTY6txgCbp_LTsIpDX0pwJg5oBImvAxHZrQxKSJjoS4wyRdsE1XjhG0ydkC_H7r6DfY_YNdRHy5anBAYxwl8vVDrBUTEyPZSVijeB1QbYN9TkAma-R-AX1jkoKOagodrqVhphxKKXgNmeYpoObp5v0f8mbdZxuE4uGvcRh0evRj7JV2j-5QbMp-FJPzhMrolN9HAV22Dj9TEfOgKdlLXTtrbA3Q20jmxAazTDiFJC8RWwgBnHHssTU-64ZwUwdN2hoFyeWGui8cOOygtQvfTyxGH3AFZxmXbLKT1js9k747v3RJivDd-_7w"},{"kty":"RSA","e":"AQAB","kid":"xMqrNgSqQdIJEKTkLKTrCT8zKEKNy3p8DeE9Q0lZ-Lg","n":"wu0X5OYS8pLpKFQ9gA41P-ej_jVSoxl9HWNwjvVXyQ_Yb5263leE5rADxQ1pKnOCcvU--ZtLHCakQsBxuaqq46cYCoSDetto8hO9uPRVQJxDWjqyf7-ZaiLD3eBNfS79RNJUGfmD8qcQesLz6WpyMjnngw03oS69DC572KEcoRb80v8WFc-_IH4tu1VpVWirVh-uQVp12G87Z9AdveNtbb-7NKq_QBb_F5VtSWYb7VVHY5DNuYz14G5XVuxNNPua_ms49dOsCwFIGx7VW3i9cV6Zv8OdH2GPxfsneQd2iiNrtRBQR2qs_94mwtOeyViuuUmzoU9Q53ZOuouhokHG3Q"}]}`
	keys := `{"keys":[  {"kty":"RSA","e":"AQAB","kid":"fXAoZYMCzKIO2rhoUD1tKF_SA3S6fBeoBG6qZcOXg4M","n": "0h2M59SAWZvR0wAotzOvu9VgiNQWL4XnjWxH1yp7k85kgN8HY1e-qc8og4Tk3NZPevOXH67e89jHVoEKHkA9IsNve5Vp6ELS2yo5hVty144LhXbnc3BEcZDuUuuCAK_s__cgHbWy8yDKnCLcHV7ZLshm7zX9KOnw7IOGdH-3BIGhyZzMbsQGc7XSo6e9xNmjhU-RrNqH98VIMt2ye7JxaMKlGC9OI2cX0J6_2T2RP20WMMPKWDgcWwA5WxIQDs2Wa-zx25iuHI23xpczp--KRfquBZ_BQHG9zpFZWwHtNOLDFfmgxpib_CMenJ30oUjsCEXuHaDPeCZ7QIL8RUUufw"}]}`
	keys = `{"keys":[{  
		"kid": "key2",
		"kty": "RSA",
		"e": "AQAB",
		"use": "sig",
		"n": "yF1M5A3ev9KXr6GCsodM-YXBNZ5kC8N7gIO2F3IkbUikhFydQmCUYDs9OmbEkfTL3xltg2CQ43HzaJm9D6CCTogxF2GLkSsnnY3mcNNA6EnITdv11AV0GYtR5KI3F7EcVhbWdYh3Q7jywGdSTESwoULTXsuPtY3oLtKDm2ewKqARzFUfPWDky0a_xJ4KPRcOwtG_F7h4L4L1pVWo5QsJ60YYBNaZ82ug04-UttMLt0GSxkzQmjvC_cXJzCSQ3dFoyaTYWxzE7Mv5WJDM6eOSkOBNskUYs5FWj3Pg6KRP0rlAYEtGeUVH6L-ccvJhWeSFVHKp0DhkxykvP8I8xmoPfw"
		}]
	}`
	fmt.Printf("%+v\n", req)
	res.Header().Add("Content-Type", "application/json")
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

	// res.Header().Add("Cross-Origin-Embedder-Policy", "require-corp")
	// res.Header().Add("Cross-Origin-Resource-Policy", "cross-origin")
	// b, err := ioutil.ReadFile("./html/parent.html")
	// if err != nil {
	// 	fmt.Printf("handleParentReq - Error reading html: %v\n", err)
	// 	res.WriteHeader(http.StatusInternalServerError)
	// 	res.Write(nil)
	// 	return
	// }

	// html := "<html><body>hello</body></html>"
	// if _, err := res.Write([]byte(html)); err != nil {
	// 	fmt.Println(err)
	// }

	s := req.URL.Query().Get("state")
	redir := fmt.Sprintf("https://system-admin.oktapreview.com/admin/app/cpc/emanor_iceresearch_1/oauth/callback?code=123456&state=%s", s)
	http.Redirect(res, req, redir, http.StatusTemporaryRedirect)
}

func handleTokenReq(res http.ResponseWriter, req *http.Request) {
	tRes := struct {
		Access_token string `json:"access_token"`
		Token_type   string `json:"token_type"`
		Expires_in   int    `json:"expires_in"`
		Scope        string `json:"scope"`
	}{
		"enlsndlfnsldnsldnfsldsndngf",
		"Bearer",
		3600,
		"scim",
	}
	res.Header().Add("Content-Type", "application/json")
	b, _ := json.Marshal(tRes)
	res.Write(b)
}

func verifySig() {
	p := jwt.NewParser()
	fmt.Printf("%+v\n", p)

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
		res, err := http.Get("https://erikmanor.okta.com/oauth2/ausybuegau5JryVLT2p6/v1/keys")
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
