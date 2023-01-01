package main

import (
	"context"
	"fmt"

	"github.com/okta/okta-sdk-golang/v2/okta"
)

func main() {
	fmt.Println("Go!!")

	ctx, client, err := okta.NewClient(
		context.TODO(),
		okta.WithOrgUrl("https://emanor.oktapreview.com"),
		okta.WithAuthorizationMode("PrivateKey"),
		okta.WithClientId("0oa8q0q34xUAiRF9P1d6"),
		okta.WithScopes(([]string{"okta.users.read", "okta.apps.read", "okta.factors.manage", "okta.users.manage"})),
		okta.WithPrivateKeyId("MyKeyId"),
		okta.WithPrivateKey(`
-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAhHwsAxcKGFL1jiiu/4b0Byu7VDxNXR23QjU1nQBC+2/sS9vb
EAIvKkJTvq1dgYnshryQUriSRMJNK8GHrTkY51IKwcXC8fSJQgCmsQ8sb7SBzS/7
O5LEZw02ytKduKqIajbQJVz4NDv6vhClD9fIezdSZ4smaVL1AgBZ807eSRHAhwiz
rVkL88HOBUUGZxKI9ogSlUHzoHkT6WCbH7IIOdX2Fod478SJQWJqb/jiaiOKLoiU
LjPqkJm5TUlimyKh08wjLVl6OTUaYSsY1ecNCDbmXr70ZiMshA2b8rSumcs+x18V
D59f+ijndIH1rG+46ujCZ9i51T2uqwTXl+Qp9wIDAQABAoIBAArAILondnQ+1xow
BvNJOigSzmKpegWiUaqXssAIs2a/0EbfkkkcREODmlQQsVO/o2fTiUqNG6Fkuupg
C+hsh67No33R1F3Z4AFxGBWqC4sM9LN3v0U4RaOvGNEgghfoDqW/yOgfQSzL6S7f
HuXINsZ42MD6M6W8S5FcAfCSZ8s5/ZKa2qAd7CSmdIvv0qHU1l/dd9S6eQtC95V+
EEu+s3pnPMthzCBJtps/522qisuTxgBesJ6LuhmwsTEJTEAfsKVcm5EiryvJjft+
yr2ndkvSoT015LXNgmZeZImLAH+M+woL2Te0R3ROiIglD3fOdn/tXELKEcwP+aLR
jnpH7lECgYEAxnpojI7UHOr57YLFfN/4IYReCm4QpJOgUESGPKRrEGIXTHSvQszI
InyCTtzKlM3fPZ4PX85VQrsjbHBTpG8d8IQ2O3NMseNUwli+uwSAlOPNUFEOmtQZ
r4VpGwxY3ykLZJOV6mE+XX1UYoCqT0mg0dccbVE2JSOIfJwVDiRx86MCgYEAquGR
v5MuLQJNKalHq1ZpoUZFAQTnSGt8fYhGmCka6SfQB/Qh+7FKcFmx3LoT/1Tl99V4
e6f24uErc2MMyY95ocJ6zoO826oVZ0pV7DCbtne+WtnWYg60d1H66p1nK0MLBCEp
YfcwPOZA+6EQYCiQZ33m5U3JKNuZYtUc+YA7NZ0CgYAK1gADPIEEGygN+YfCq4+m
dM2VkDDEa3LjLvqNMQTPXiubdvtikD+U8mtC1vcQbLT1bj20o1UwUXs7nl5SqeZe
jTlQwZi8VYb5HVM8bqB+gHljGynK9i140bXNTj1D4b/He+9BXpHDFOaYgiHKNmDb
U/0vUrG8EVaQRw03OnImNQKBgEYznVkC8jlzdJfk/5iYS5UB9V9R0GKkJeS8k6P3
XyLiREjANyXb1CUL9FIl8Ak5q7CBdpn2iyryLpOc4af81Y9rAmDNJk1oNprUozAB
WDdCQmW4kKaAPAu5FkhEmhnf1SrBJOsmTh72yUOXC881Wv3pb25M4pNyhDViMCEg
WTLRAoGAM7x4OQqQMWgknIiQzkSymQy1TcH0LbpuoRJUBKe59XCv8eVxrkJN2II7
GawXlGqJyB4dlyR5PMkGPm+BsEpuUXFD8GDbZuewHlKMwS+nAJ8ULCG3xVfhx3Gi
Jjv0hT/xPMc0EhArBqc81rYf/w6QbKAMT12CpU8o3MXZD7aLHZg=
-----END RSA PRIVATE KEY-----`), //when pasting blocks, use backticks and remove all space at beginning of each line.
	)

	// ctx, client, err := okta.NewClient(
	// 	context.TODO(),
	// 	okta.WithOrgUrl("https://emanor-oie.oktapreview.com"),
	// 	okta.WithToken("00Qagv4UtNHXytJiSFVws2qKvNMrF3pMIcQi64mG06"),
	// )

	if err != nil {
		fmt.Printf("Error: %v\n", err)
	}

	fmt.Printf("Context: %+v\n Client: %+v\n", ctx, client)

	user, resp, err := client.User.GetUser(ctx, "emanor.okta@gmail.com")
	if err != nil {
		fmt.Printf("Error Getting User: %v\n", err)
	}
	fmt.Printf("User: %+v\n Response: %+v\n\n", user, resp)

	// //oidc_client
	// // q := query.NewQueryParams(query.WithQ("Maintenance OKTA API"))
	// q := query.NewQueryParams(query.WithLimit(100))
	// applicationList, resp, err := client.Application.ListApplications(ctx, q)
	// if err != nil {
	// 	fmt.Printf("Error listing applications: %v\n", err)
	// }

	// fmt.Printf("ApplicationList: %+v\n Response: %+v\n\n", applicationList, resp)
	// // var o okta.OpenIdConnectApplication
	// // Listing applications is mapped and returned as a interface. Once you
	// // get the list of applications, find the one you want to work on, and
	// // make a `GET` request with that ID and the concrete application type
	// for _, app := range applicationList {
	// 	if app.(*okta.OpenIdConnectApplication).Name == "oidc_client" {
	// 		fmt.Printf("\n\n%+v\n\n", app.(*okta.OpenIdConnectApplication).Credentials.OauthClient.ClientId)
	// 		// fmt.Printf("Client ID: %v\n", app.Credentials.OauthClient.ClientId)
	// 		// }

	// 		// if app.(*okta.OpenIdConnectApplication).Name == "oidc_client" {

	// 		application, resp, err := client.Application.GetApplication(ctx, app.(*okta.OpenIdConnectApplication).Id, okta.NewOpenIdConnectApplication(), nil)
	// 		if err != nil {
	// 			fmt.Printf("Error getting application: %v\n", err)
	// 		}

	// 		fmt.Printf("%+v\n\n Response: %+v\n\n", application.(*okta.OpenIdConnectApplication) /*.Credentials.OauthClient.ClientId*/, resp)
	// 	} else {
	// 		fmt.Printf("\n\nNot OIDC: %+v\n\n", app)
	// 	}
	// }

	system := false
	p := okta.NewPolicy()
	p.Name = "Golang"
	// p.Priority = 98
	p.Status = "ACTIVE"
	p.System = &system
	p.Type = "ACCESS_POLICY"

	policies, resp, err := client.Policy.CreatePolicy(ctx, p, nil)
	if err != nil {
		fmt.Printf("Error create policy: %+v\n", err)
	}
	fmt.Printf("%+v\n", policies)
	fmt.Printf("%+v\n", resp)
}
