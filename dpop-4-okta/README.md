## README.md

### Usage:
For General Help either run straight from source,  
`go mod tidy`  
`go run main.go`  
or [download](https://github.com/emanor-okta/custom-scripts/releases) appropriate binary from release page,  
MacOS - `./dpop-4-okta_darwin-amd64`  
Windows - `dpop-4-okta_win-amd64.exe`   
   
### Generate a JWT signed with Private Key to use for OAuth for Okta (without DPoP):  
```
./dpop-4-okta_darwin-amd64 jwt -i <OKTA_ISSUER> -c <CLIENT_ID> -k <PRIVATE_KEY_KID> -j <PRIVATE_KEY_FILE_PEM_FORMAT>
```  
example,  
```
./dpop-4-okta_darwin-amd64 jwt -i https://okta.oktapreview.com -c 0oa6xed6trtDfn654321 -k key1 -j jwtKeyFile.pem
```  

### Generate DPoP and Access Token for use with a Service Application for OAuth for Okta:  
```
./dpop-4-okta_darwin-amd64 m2m -i <OKTA_ISSUER> -c <CLIENT_ID> -k <PRIVATE_KEY_KID> -s <OKTA_SCOPES> -e <OKTA_API_ENDPOINT> -m <API_HTTP_METHOD> -j <PRIVATE_KEY_FILE_PEM_FORMAT>
```  
example,
```
./dpop-4-okta_darwin-amd64 m2m -i https://okta.oktapreview.com -c 0oa6xed6trtDfn654321 -k key1 -s okta.apps.read,okta.users.read -e https://okta.oktapreview.com/api/v1/apps -m GET -j jwtKeyFile.pem
```  

(for non Okta APIs set issuer `-i` to be a Okta custom authorization server and scopes `-s`, endpoint `-e`, and method `-m` to the resource being called.)  

### Generate DPoP and Access Token for Authorization Code (web/spa) Application for OAuth for Okta:  
```
./dpop-4-okta_darwin-amd64 web -i <OKTA_ISSUER> -c <CLIENT_ID> -s <OKTA_SCOPES> -e <OKTA_API_ENDPOINT> -m <API_HTTP_METHOD> [-v <PKCE_CODE_VERIFIER>] [-a <AUTHORIZATION_CODE_VALUE> | -p <PORT>] -r <REDIRECT_URI>
```  
example,  
```
./dpop-4-okta_darwin-amd64 web --issuer https://okta.oktapreview.com --client-id 0oa6xed6trtDfn654321 --code-verifier 9d140e712652b1ecbc5e27944819189c6d4c641661b --scopes okta.apps.read --redirect-uri https://httpbin.org/get --auth-code o_ZBdpCYoqO8PpXXyYbzvKR2FnqleSbdhInyAMsTw8g --api-endpoint https://emanor-oie.oktapreview.com/api/v1/apps --api-method GET
```  

Use one of:
* [-a | --auth-code] - to suppy an authorization code value
* [-p | --port] - to start an http server on `http://localhost:<port>/callback` which will handle the redirect during authorization code flow and exchange the code for DPoP and Access Token. Need to register `http://localhost:<port>/callback` as an allowed redirect_uri in the Okta OIDC app and supply this as the redirect_uri during authorize call.  


#### Debug Network calls  
[-d | --debug]  

#### Full list of Options:  
```
Available Commands:
  web       Authorization Code
  m2m       Client Credentials
  jwt       Generate JWT Credential for Oauth for Okta without DPoP

Flags:
  -i, --issuer             Okta Authorization Server
  -c, --client-id          OIDC Client id of Okta App
  -x, --client-secret      OIDC Client Client Secret of Okta App (for web apps)
  -s, --scopes             OAuth Scopes Requested, comma seperated (ie okta.apps.read,okta.groups.manage)
  -r, --redirect-uri       OAuth Redirect URI
  -v, --code-verifier      PKCE code Verifier (for flows that use PKVE)
  -a, --auth-code          Authorization Code Value (needed for web flow if not redirecting to 'http://localhost:<port>/callback')
  -p, --port               For web flows if redirecting to this process port to run http server on (will start server on 'http://localhost:<port>/callback')
  -e, --api-endpoint       API endpoint the DPoP Access Token will be used for
  -m, --api-method         HTTP Method used with the DPoP Access Token (GET/POST/etc)
  -j, --jwt-pem-file       File location with PEM encoded private key to sign JWT (needed for o4o when using m2m)
  -k, --jwt-key            Key id of JWK registered in Okta
  -o, --dpop-pem-file      File location with PEM encoded private key to sign DPoP (if not specified a JWKS will dynamically be generated)
  -d, --debug              Debug Network Requests and Responses
```
