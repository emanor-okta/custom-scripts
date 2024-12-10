package main

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
)

type JwtPayload struct {
	Htm   string `json:"htm,omitempty"`
	Htu   string `json:"htu,omitempty"`
	Iat   int64  `json:"iat,omitempty"`
	Nonce string `json:"nonce,omitempty"`
	Jti   string `json:"jti,omitempty"`
	Ath   string `json:"ath,omitempty"`
}

type TokenResponse struct {
	TokenType        string `json:"token_type,omitempty"`
	Scope            string `json:"scope,omitempty"`
	ExpiresIn        int64  `json:"expires_in,omitempty"`
	AccessToken      string `json:"access_token,omitempty"`
	IdToken          string `json:"id_token,omitempty"`
	Error            string `json:"error,omitempty"`
	ErrorDescription string `json:"error_description,omitempty"`
}

type AssertionPayload struct {
	Aud string `json:"aud,omitempty"`
	Iss string `json:"iss,omitempty"`
	Sub string `json:"sub,omitempty"`
	Exp int64  `json:"exp,omitempty"`
	Jti string `json:"jti,omitempty"`
}

type FlowParams struct {
	Type,
	Issuer,
	Code,
	CodeVerifier,
	RedirectURI,
	ClientId,
	ClientSecret,
	AssertPem,
	AssertKid,
	DpopPem,
	Port,
	ApiEndpoint,
	ApiMethod,
	Scopes string
	DebugNet bool
}

type loggingTransport struct{}

const (
	auth_code_payload          = "grant_type=%s&redirect_uri=%s&client_id=%s&code=%s"
	client_credentials_payload = "grant_type=%s&scope=%s&client_assertion_type=%s&client_assertion=%s"
)

func (s *loggingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	bytes, _ := httputil.DumpRequestOut(r, true)

	resp, err := http.DefaultTransport.RoundTrip(r)
	// err is returned after dumping the response
	respBytes, _ := httputil.DumpResponse(resp, true)
	bytes = append(bytes, respBytes...)

	fmt.Printf("\n%s\n", bytes)

	return resp, err
}

var flowParams FlowParams
var privkey, pubkey jwk.Key
var jwtPayload JwtPayload

func main() {
	flowParams = parseCommandLineArgs()
	if flowParams.Type == "jwt" {
		fmt.Printf("JWT Credential:\n%s\n", generateAssertion(flowParams))
	} else if flowParams.Port == "" {
		// client credentials or auth code was provided
		if flowParams.ApiEndpoint == "" {
			// no DPoP m2m, get access_token
			tokenCall("POST", getHtu(flowParams.Issuer), "", []byte(""), generateTokenPayload(flowParams))
		} else {
			// DPoP m2m or web (with auth code provided), start token calls
			getTokens()
			reader := bufio.NewReader(os.Stdin)
			for {
				fmt.Print("Press Enter to generate new DPoP or 'q' to quit: ")
				input, _ := reader.ReadString('\n')
				fmt.Println(input)
				if strings.TrimSpace(input) == "q" {
					return
				}
				fmt.Printf("\n\nDPoP: %s\n\n", generateDpop())
			}
		}
	} else {
		// auth code flow - start callback server
		http.HandleFunc("/callback", handleCallbackReq)
		http.HandleFunc("/generate_dpop", handleGenerateDpop)
		if err := http.ListenAndServe(fmt.Sprintf(":%s", flowParams.Port), nil); err != nil {
			log.Fatalf("\nError, Server startup failed: %s\n", err)
		}
	}
}

func generateDpop() string {
	// generates another DPoP since each API call with the access_token requires a unique DPoP sent with the request
	jwtPayload.Jti = uuid.NewString()
	return string(signJwt(jwtPayload, jws.WithKey(jwa.RS256, privkey, jws.WithProtectedHeaders(generateJwtHeader(pubkey)))))
}

func getTokens() string {
	privkey, pubkey = getOrGenerateDpopKey(flowParams.DpopPem)

	fmt.Println("\nDPoP Private Key:")
	json.NewEncoder(os.Stdout).Encode(privkey)
	fmt.Println("\nDPoP Public Key:")
	json.NewEncoder(os.Stdout).Encode(pubkey)

	// token call 1
	jwtPayload = JwtPayload{
		Htm: "POST",
		Htu: getHtu(flowParams.Issuer),
		Iat: time.Now().Unix(),
	}
	dPop := signJwt(jwtPayload, jws.WithKey(jwa.RS256, privkey, jws.WithProtectedHeaders(generateJwtHeader(pubkey))))
	fmt.Printf("\nDPoP JWT:\n%s\n", dPop)
	resp1, nonce := tokenCall(jwtPayload.Htm, jwtPayload.Htu, flowParams.Code, dPop, generateTokenPayload(flowParams))
	fmt.Printf("\nToken Call Response 1: \n%+v\n", resp1)
	fmt.Printf("\nnonce: %v\n", nonce)
	if nonce == "" {
		log.Fatalf("\nExpected \"dpop-nonce\" http header but was not present")
	}

	// token call 2
	jwtPayload = JwtPayload{
		Htm:   "POST",
		Htu:   getHtu(flowParams.Issuer),
		Iat:   time.Now().Unix(),
		Nonce: nonce,
		Jti:   uuid.NewString(),
	}
	dPop = signJwt(jwtPayload, jws.WithKey(jwa.RS256, privkey, jws.WithProtectedHeaders(generateJwtHeader(pubkey))))
	resp2, _ := tokenCall(jwtPayload.Htm, jwtPayload.Htu, flowParams.Code, dPop, generateTokenPayload(flowParams))
	fmt.Printf("\nToken Call Response 2: \n%+v\n", resp2)

	jwtPayload = JwtPayload{
		Htm: flowParams.ApiMethod,
		Htu: flowParams.ApiEndpoint,
	}
	if !strings.Contains(flowParams.Issuer, "/oauth2/") {
		// Add ath value for o4o
		jwtPayload.Ath = generateAth(resp2.AccessToken)
		jwtPayload.Iat = time.Now().Unix()
		jwtPayload.Jti = uuid.NewString()
	}
	dPop = signJwt(jwtPayload, jws.WithKey(jwa.RS256, privkey, jws.WithProtectedHeaders(generateJwtHeader(pubkey))))

	values := getApiRequestValues(resp2.AccessToken, string(dPop))
	fmt.Println(values)
	return values
}

func getApiRequestValues(authorization, dPop string) string {
	return fmt.Sprintf("\n\n-------- DPoP Bound Request Values --------\nAuthorization: DPoP %s\n\nDPoP: %s\n\n", authorization, dPop)
}

func generateAth(accessToken string) string {
	sum := sha256.Sum256([]byte(accessToken))
	ath := base64.RawURLEncoding.EncodeToString(sum[:])
	fmt.Printf("\nATH Token:\n%s\n\nATH value:\n%s\n", accessToken, ath)
	return ath
}

func generateKey() (jwk.Key, jwk.Key) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("\nError, Generating RSA Private Key: %v\n", err)
	}

	jwkKey, err := jwk.FromRaw(privateKey)
	if err != nil {
		log.Fatalf("\nError, Generating JWK Key from RSA Private Key: %v\n", err)
	}

	pubKey, err := jwkKey.PublicKey()
	if err != nil {
		log.Fatalf("\nError, Getting Public Key Part from JWK: %v\n", err)
	}

	return jwkKey, pubKey
}

func getKeys(keyAsPem []byte) (jwk.Key, jwk.Key) {
	privkey, err := jwk.ParseKey(keyAsPem, jwk.WithPEM(true))
	if err != nil {
		log.Fatalf("\nfailed to parse JWK: %s\n", err)
	}

	pubkey, err := jwk.PublicKeyOf(privkey)
	if err != nil {
		log.Fatalf("\nfailed to get public key: %s\n", err)
	}

	return privkey, pubkey
}

func signJwt(jwtPayload JwtPayload, options ...jws.SignOption) []byte {
	jwtPayloadBytes, _ := json.Marshal(jwtPayload)
	buf, err := jws.Sign(jwtPayloadBytes, options...)
	if err != nil {
		log.Fatalf("\nFailed to signJWT: %+v, with options: %+v\n", jwtPayload, options)
	}

	return buf
}

func generateJwtHeader(k jwk.Key) jws.Headers {
	hdrs := jws.NewHeaders()
	hdrs.Set("typ", "dpop+jwt")
	hdrs.Set("alg", "RS256")
	hdrs.Set("jwk", k)
	return hdrs
}

func generateTokenPayload(fp FlowParams) *strings.Reader {
	var payload string
	if fp.Type == "web" {
		var redirectUri string
		grantType := "authorization_code"
		if fp.RedirectURI == "" {
			redirectUri = fmt.Sprintf("http://localhost:%s/callback", fp.Port)
		} else {
			redirectUri = fp.RedirectURI
		}
		payload = fmt.Sprintf(auth_code_payload, grantType, redirectUri, fp.ClientId, fp.Code)
		if fp.ClientSecret != "" {
			payload = fmt.Sprintf("%s&client_secret=%s", payload, fp.ClientSecret)
		}
		if fp.CodeVerifier != "" {
			payload = fmt.Sprintf("%s&code_verifier=%s", payload, fp.CodeVerifier)
		}
	} else {
		grantType := "client_credentials"
		assertionType := "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
		payload = fmt.Sprintf(client_credentials_payload, grantType, strings.ReplaceAll(fp.Scopes, ",", " "), assertionType, generateAssertion(fp))
	}

	return strings.NewReader(payload)
}

func tokenCall(method, url, _ string, dpop []byte, payload *strings.Reader) (TokenResponse, string) {
	dpopNonceHeader, tokenResp, err := httpRequest(method, url, "application/x-www-form-urlencoded", "", string(dpop), payload)
	if err != nil {
		log.Fatalf("Error making /token call: %+v\n", err)
	}
	tokenResponse := TokenResponse{}
	if err := json.Unmarshal([]byte(tokenResp), &tokenResponse); err != nil {
		log.Fatalf("\nError UnMarshalling /token Response: %+v\n", err)
	}
	return tokenResponse, dpopNonceHeader
}

func httpRequest(method, url, contentType, authorization, dpop string, payload *strings.Reader) (string, string, error) {
	var httpClient *http.Client
	if flowParams.DebugNet {
		httpClient = &http.Client{Transport: &loggingTransport{}}
	} else {
		httpClient = &http.Client{}
	}
	req, err := http.NewRequest(method, url, payload)
	if err != nil {
		fmt.Println(err)
		return "", "", err
	}
	req.Header.Add("Accept", "application/json")
	req.Header.Add("Content-Type", contentType)
	if dpop != "" {
		req.Header.Add("DPoP", dpop)
	}
	// fmt.Println(dpop)
	if authorization != "" {
		req.Header.Add("Authorization", authorization)
	}

	res, err := httpClient.Do(req)
	if err != nil {
		log.Fatal(err)
		return "", "", err
	}

	defer res.Body.Close()
	dpopNonce := ""
	if dpopNonceHeaders := res.Header.Values("dpop-nonce"); len(dpopNonceHeaders) > 0 {
		dpopNonce = dpopNonceHeaders[0]
	}

	body, err := io.ReadAll(res.Body)
	if err != nil {
		fmt.Println(err)
		return "", "", err
	}

	// fmt.Println(string(body))
	return dpopNonce, string(body), nil
}

func getOrGenerateDpopKey(keyAsPemFile string) (jwk.Key, jwk.Key) {
	if keyAsPemFile == "" {
		return generateKey()
	} else {
		pem, err := os.ReadFile(keyAsPemFile)
		if err != nil {
			fmt.Printf("\nError, Reading Key file for DPoP, generating a key instead, %+v\n", err)
			return generateKey()
		}
		return getKeys(pem)
	}
}

func generateAssertion(fp FlowParams) string {
	if fp.AssertPem == "" {
		log.Fatalf("\nError, 'assertion_pem_file=<file>' option not present and needed for this flow\n")
	}

	pem, err := os.ReadFile(fp.AssertPem)
	if err != nil {
		log.Fatalf("\nError, Reading Key file for JWT Assertion, %+v\n", err)
	}
	fmt.Println(pem)
	privkey, _ := getKeys(pem)
	assertion := AssertionPayload{
		Aud: fmt.Sprintf("%s/oauth2/v1/token", fp.Issuer),
		Iss: fp.ClientId,
		Sub: fp.ClientId,
		Exp: time.Now().Unix(),
		// Jti: "AlwaysTheSame2",
	}
	payload, _ := json.Marshal(assertion)
	hdrs := jws.NewHeaders()
	if kid := fp.AssertKid; kid != "" {
		hdrs.Set(`kid`, kid)
	}

	jwt, err := jws.Sign([]byte(payload), jws.WithKey(jwa.RS256, privkey, jws.WithProtectedHeaders(hdrs)))
	if err != nil {
		log.Fatalf("\nError, failed to sign assertion: %s\n", err)
	}

	return string(jwt)
}

func getHtu(htu string) string {
	if strings.Contains(htu, "/oauth2/") {
		return fmt.Sprintf("%s/v1/token", flowParams.Issuer)
	} else {
		return fmt.Sprintf("%s/oauth2/v1/token", flowParams.Issuer)
	}
}

func handleCallbackReq(res http.ResponseWriter, req *http.Request) {
	code := req.URL.Query().Get("code")
	flowParams.Code = code
	values := getTokens()
	res.Write([]byte(values))
}

func handleGenerateDpop(res http.ResponseWriter, req *http.Request) {
	dpop := generateDpop()
	res.Write([]byte(dpop))
}

func parseCommandLineArgs() FlowParams {

	flowParams := FlowParams{}
	if len(os.Args) < 2 {
		showHelp()
	}

	switch os.Args[1] {
	case "m2m":
		flowParams.Type = "service"
	case "web":
		flowParams.Type = "web"
	case "jwt":
		flowParams.Type = "jwt"
	default:
		showHelp()
	}

	for i := 2; i < len(os.Args); i++ {
		option := os.Args[i]
		if option == "-d" || option == "--debug" {
			flowParams.DebugNet = true
			continue
		}
		i = i + 1
		val := os.Args[i]
		fmt.Printf("option=%s, val=%s\n", option, val)

		switch option {
		case "-i", "--issuer":
			flowParams.Issuer = val
		case "-c", "--client-id":
			flowParams.ClientId = val
		case "-x", "--client-secret":
			flowParams.ClientSecret = val
		case "-v", "--code-verifier":
			flowParams.CodeVerifier = val
		case "-s", "--scopes":
			flowParams.Scopes = val
		case "-o", "--dpop-pem-file":
			flowParams.DpopPem = val
		case "-a", "--auth-code":
			flowParams.Code = val
		case "-r", "--redirect-uri":
			flowParams.RedirectURI = val
		case "-p", "--port":
			flowParams.Port = val
		case "-m", "--api-method":
			flowParams.ApiMethod = val
		case "-e", "--api-endpoint":
			flowParams.ApiEndpoint = val
		case "-j", "--jwt-pem-file":
			flowParams.AssertPem = val
		case "-k", "--jwt-kid":
			flowParams.AssertKid = val
		default:
			fmt.Printf("\nError, Invalid command line param supplied: %s\n", val)
		}
	}

	return flowParams
}

func showHelp() {
	fmt.Println("\nUsage:")
	fmt.Printf("%-2sgo run main.go [command]\n", "")

	fmt.Println("\nAvailable Commands:")
	fmt.Printf("  %-10sAuthorization Code\n", "web")
	fmt.Printf("  %-10sClient Credentials\n", "m2m")
	fmt.Printf("  %-10sGenerate JWT Credential for Oauth for Okta without DPoP\n", "jwt")

	fmt.Println("\nFlags:")
	fmt.Printf("  %-3s %-20s Okta Authorization Server\n", "-i,", "--issuer")
	fmt.Printf("  %-3s %-20s OIDC Client id of Okta App\n", "-c,", "--client-id")
	fmt.Printf("  %-3s %-20s OIDC Client Client Secret of Okta App (for web apps)\n", "-x,", "--client-secret")
	fmt.Printf("  %-3s %-20s OAuth Scopes Requested, comma seperated (ie okta.apps.read,okta.groups.manage)\n", "-s,", "--scopes")
	fmt.Printf("  %-3s %-20s OAuth Redirect URI\n", "-r,", "--redirect-uri")
	fmt.Printf("  %-3s %-20s PKCE code Verifier (for flows that use PKVE)\n", "-v,", "--code-verifier")
	fmt.Printf("  %-3s %-20s Authorization Code Value (needed for web flow if not redirecting to 'http://localhost:<port>/callback')\n", "-a,", "--auth-code")
	fmt.Printf("  %-3s %-20s For web flows if redirecting to this process port to run http server on (will start server on 'http://localhost:<port>/callback')\n", "-p,", "--port")
	fmt.Printf("  %-3s %-20s API endpoint the DPoP Access Token will be used for\n", "-e,", "--api-endpoint")
	fmt.Printf("  %-3s %-20s HTTP Method used with the DPoP Access Token (GET/POST/etc)\n", "-m,", "--api-method")
	fmt.Printf("  %-3s %-20s File location with PEM encoded private key to sign JWT (needed for o4o when using m2m)\n", "-j,", "--jwt-pem-file")
	fmt.Printf("  %-3s %-20s Key id of JWK registered in Okta\n", "-k,", "--jwt-key")
	fmt.Printf("  %-3s %-20s File location with PEM encoded private key to sign DPoP (if not specified a JWKS will dynamically be generated)\n", "-o,", "--dpop-pem-file")
	fmt.Printf("  %-3s %-20s Debug Network Requests and Responses\n", "-d,", "--debug")
	fmt.Printf("\n\n")
	os.Exit(0)
}
