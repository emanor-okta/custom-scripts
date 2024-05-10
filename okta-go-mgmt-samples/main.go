package main

import (
	"context"
	"fmt"

	// "syscall"
	"golang.org/x/sys/unix"

	"github.com/okta/okta-sdk-golang/v2/okta"
	"github.com/okta/okta-sdk-golang/v2/okta/query"
)

func main() {
	fmt.Println("Go!!")
	// getOS()

	ctx, client, err := okta.NewClient(
		context.TODO(),
		// okta.WithOrgUrl("https://emanor.oktapreview.com"),
		okta.WithOrgUrl("https://emanor-oie.oktapreview.com"),
		okta.WithAuthorizationMode("PrivateKey"),
		// okta.WithClientId("0oa8q0q34xUAiRF9P1d6"),
		// okta.WithClientId("0oadsr9fp1e6kUx2Z1d7"),
		okta.WithClientId("0oa7hcsubqTK2OijK1d7"),
		// okta.WithScopes(([]string{"okta.users.read", "okta.apps.manage", "okta.factors.manage", "okta.users.manage", "okta.idps.read"})),
		okta.WithScopes(([]string{"ssf.read", "ssf.manage"})),
		// okta.WithPrivateKeyId("PemToJWK"),
		// okta.WithPrivateKey(`
		// -----BEGIN RSA PRIVATE KEY-----
		// MIIEogIBAAKCAQEAhHwsAxcKGFL1jiiu/4b0Byu7VDxNXR23QjU1nQBC+2/sS9vb
		// ...
		// Jjv0hT/xPMc0EhArBqc81rYf/w6QbKAMT12CpU8o3MXZD7aLHZg=
		// -----END RSA PRIVATE KEY-----`), //when pasting blocks, use backticks and remove all space at beginning of each line.
		okta.WithPrivateKey(`
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAyF1M5A3ev9KXr6GCsodM+YXBNZ5kC8N7gIO2F3IkbUikhFyd
...
kWHvKiRcEwWQf+QNJAyuA/8dBYos/b/S7E5JDmAMNVm9HV23S/cukw==
-----END RSA PRIVATE KEY-----
		`),
	)

	// ctx, client, err := okta.NewClient(
	// 	context.TODO(),
	// 	// okta.WithOrgUrl("https://emanor-oie.oktapreview.com"),
	// 	// okta.WithToken("00IWyBcycCpHEdCPP9j3dMEP3vqORAZrVCEG38F9Ve"),
	// 	okta.WithOrgUrl("https://okta.oktamanor.com"),
	// 	okta.WithToken("00xYCqCQOT_uHJwwMHH5CG3iCEZ9VNLw9UTO-BoejU"),
	// )

	if err != nil {
		fmt.Printf("Error: %v\n", err)
	}

	fmt.Printf("Context: %+v\n Client: %+v\n", ctx, client)

	user, resp, err := client.User.GetUser(ctx, "emanor.okta@gmail.com")
	if err != nil {
		fmt.Printf("Error Getting User: %v\n", err)
	}
	fmt.Printf("User: %+v\n Response: %+v\n\n", user.Id, resp)

	// factors, _, err := client.UserFactor.ListFactors(ctx, user.Id)
	// if err != nil {
	// 	fmt.Printf("Error Getting ListFactors: %v\n", err)
	// }
	// fmt.Printf("Factors: %+v\n\n", factors[0])
	// f := factors[0].(*okta.EmailUserFactor)
	// fmt.Printf("Factor 2: %+v\n\n", f)

	type MyCredentials struct {
		ID           string `json:"id,omitempty"`
		ClientSecret string `json:"client_secret,omitempty"`
		SecretHash   string `json:"secret_hash,omitempty"`
	}

	type Keys struct {
		Keys []okta.JsonWebKey `json:"keys,omitempty"`
	}

	q := query.NewQueryParams(query.WithLimit(100))
	applicationList, resp, err := client.Application.ListApplications(ctx, q)
	if err != nil {
		fmt.Printf("Error listing applications: %v\n", err)
	}

	for _, app := range applicationList {
		if app.(*okta.Application).Name == "oidc_client" {

			if "0oa8q0q34xUAiRF9P1d6" == app.(*okta.Application).Id {
				// fmt.Printf("%+v\n", app.(*okta.Application))

				var webKeys Keys
				url := fmt.Sprintf("/api/v1/apps/%s/credentials/jwks", app.(*okta.Application).Id)
				req, err := client.CloneRequestExecutor().NewRequest("GET", url, nil)
				if err != nil {
					fmt.Printf("Error creating new request: %v\n", err)
				}

				_, err = client.CloneRequestExecutor().Do(ctx, req, &webKeys)
				if err != nil {
					fmt.Printf("Error executing request: %v\n", err)
				}

				if len(webKeys.Keys) > 0 {
					fmt.Printf("Client Secret: %+v\n", webKeys.Keys[0])
				}
			}

			var myCreds []MyCredentials
			url := fmt.Sprintf("/api/v1/apps/%s/credentials/secrets", app.(*okta.Application).Id)
			req, err := client.CloneRequestExecutor().NewRequest("GET", url, nil)
			if err != nil {
				fmt.Printf("Error creating new request: %v\n", err)
			}

			_, err = client.CloneRequestExecutor().Do(ctx, req, &myCreds)
			if err != nil {
				fmt.Printf("Error executing request: %v\n", err)
			}

			if len(myCreds) > 0 {
				fmt.Printf("Client Secret: %+v\n", myCreds[0].ClientSecret)
			}
		}
	}

	//oidc_client
	// q := query.NewQueryParams(query.WithQ("Maintenance OKTA API"))
	// q := query.NewQueryParams(query.WithLimit(100))
	// applicationList, resp, err := client.Application.ListApplications(ctx, q)
	// if err != nil {
	// 	fmt.Printf("Error listing applications: %v\n", err)
	// }
	// // fmt.Printf("%+v\n", resp.Response)

	// fmt.Printf("ApplicationList: %+v\n Response: %+v\n\n", applicationList, resp)
	// // var o okta.OpenIdConnectApplication
	// // Listing applications is mapped and returned as a interface. Once you
	// // get the list of applications, find the one you want to work on, and
	// // make a `GET` request with that ID and the concrete application type
	// for _, app := range applicationList {
	// 	fmt.Printf("%+v\n", app.IsApplicationInstance())
	// 	// if app.(*okta.OpenIdConnectApplication).Name == "oidc_client" {
	// 	if app.(*okta.Application).Name == "oidc_client" {
	// 		// fmt.Printf("\n\n%+v\n\n", app.(*okta.OpenIdConnectApplication).Credentials.OauthClient.ClientId)
	// 		fmt.Printf("Client ID: %+v\n", app.(*okta.Application).Id)

	// 		///api/v1/apps/0oa2cpl777xczKzL21d7/credentials/secrets
	// 		type MyCredentials struct {
	// 			ID           string `json:"id,omitempty"`
	// 			ClientSecret string `json:"client_secret,omitempty"`
	// 			SecretHash   string `json:"secret_hash,omitempty"`
	// 		}
	// 		var myCreds []MyCredentials
	// 		url := fmt.Sprintf("/api/v1/apps/%s/credentials/secrets", app.(*okta.Application).Id)
	// 		req, err := client.CloneRequestExecutor().NewRequest("GET", url, nil)
	// 		if err != nil {
	// 			fmt.Printf("Error creating new request: %v\n", err)
	// 		}

	// 		// Make the request
	// 		_, err = client.CloneRequestExecutor().Do(ctx, req, &myCreds)
	// 		if err != nil {
	// 			fmt.Printf("Error executing request: %v\n", err)
	// 		}
	// 		if len(myCreds) > 0 {
	// 			fmt.Printf("Client Secret: %+v\n", myCreds[0].ClientSecret)
	// 		}
	// 		// }

	// 		// if app.(*okta.OpenIdConnectApplication).Name == "oidc_client" {

	// 		// application, resp, err := client.Application.GetApplication(ctx, app.(*okta.OpenIdConnectApplication).Id, okta.NewOpenIdConnectApplication(), nil)
	// 		// if err != nil {
	// 		// 	fmt.Printf("Error getting application: %v\n", err)
	// 		// }

	// 		// fmt.Printf("%+v\n\n Response: %+v\n\n", application.(*okta.OpenIdConnectApplication) /*.Credentials.OauthClient.ClientId*/, resp)
	// 	} else {
	// 		fmt.Printf("\n\nNot OIDC: %+v\n\n", nil)
	// 	}
	// }

	// system := false
	// p := okta.NewPolicy()
	// p.Name = "Golang"
	// // p.Priority = 98
	// p.Status = "ACTIVE"
	// p.System = &system
	// p.Type = "ACCESS_POLICY"

	// policies, resp, err := client.Policy.CreatePolicy(ctx, p, nil)
	// if err != nil {
	// 	fmt.Printf("Error create policy: %+v\n", err)
	// }
	// fmt.Printf("%+v\n", policies)
	// fmt.Printf("%+v\n", resp)
}

// A utility to convert the values to proper strings.
func int8ToStr(arr []int8) string {
	b := make([]byte, 0, len(arr))
	for _, v := range arr {
		if v == 0x00 {
			break
		}
		b = append(b, byte(v))
	}
	return string(b)
}

func getOS() {

	var uname unix.Utsname
	if err := unix.Uname(&uname); err == nil {
		// extract members:
		// type Utsname struct {
		//  Sysname    [65]int8
		//  Nodename   [65]int8
		//  Release    [65]int8
		//  Version    [65]int8
		//  Machine    [65]int8
		//  Domainname [65]int8
		// }

		fmt.Println(string(uname.Sysname[:]),
			string(uname.Release[:]),
			string(uname.Version[:]))

		fmt.Println(string(uname.Release[:]))

	}
}
