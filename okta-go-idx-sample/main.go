package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"

	idx "github.com/okta/okta-idx-golang"
)

func main() {
	fmt.Println("Go!!")
	// establish context here, or use context from/within a caller
	ctx := context.TODO()

	client, err := idx.NewClient()
	if err != nil {
		log.Fatalf("new client error: %+v\n", err)
	}

	fmt.Printf("cleint: %v\n", client)

	//activationTokenTest(client, "WNH2FLBRMc9BYlzeHEfB", ctx)
	passwordless(client, ctx)

}

func passwordless(client *idx.Client, ctx context.Context) {
	lr, err := client.InitLogin(ctx)
	if err != nil {
		log.Fatalf("client.InitLogin error: %+v\n", err)
	}

	fmt.Printf("%+v\n", lr)

	ir := &idx.IdentifyRequest{
		Identifier: "emanor.okta2@gmail.com",
	}

	if !lr.HasStep(idx.LoginStepIdentify) {
		return lr.missingStepError(idx.LoginStepIdentify)
	}
	resp, err := idx.introspect(ctx, lr.idxContext.InteractionHandle)
	if err != nil {
		return nil, err
	}
	ro, err := resp.remediationOption("identify")
	if err != nil {
		return nil, err
	}
	b, _ := json.Marshal(ir)
	resp, err = ro.proceed(ctx, b)
	if err != nil {
		return nil, err
	}
}

func activationTokenTest(client *idx.Client, token string, ctx context.Context) {
	authOpts := idx.AuthenticationOptions{
		ActivationToken: token,
	}

	lr, err := client.Authenticate(ctx, &authOpts)
	if err != nil {
		log.Fatalf("authentication error: %+v\n", err)
	}

	fmt.Printf("%+v\n", lr)

	fmt.Println("steps:")
	for _, step := range lr.AvailableSteps() {
		fmt.Printf("  %+v\n", step)
	}
	if lr.HasStep(idx.LoginStepAuthenticatorEnroll) {
		fmt.Println("response has authenticator enroll")
		fmt.Println("app should redirect users to the enrollment view now")
	} else {
		fmt.Println("response didn't have select authenticator enroll remediation")
	}

	fmt.Printf("isAuthenticated: %v\n", lr.IsAuthenticated())
	fmt.Printf("tokens: %v\n", lr.Token())
	fmt.Printf("idxContext: %+v\n", lr.Context().InteractionHandle)

	// do something, having a token signals identification success
	resp, err := client.Introspect(ctx, lr.Context().InteractionHandle)
	if err != nil {
		log.Fatalf("introspect error: %+v\n", err)
	}

	fmt.Printf("%+v\n", resp)
	bytes, err := json.MarshalIndent(resp, "", "  ")
	if err != nil {
		log.Fatalf("Marshal error: %v\n", err)
	}
	fmt.Printf("%v\n", string(bytes))

	// er := idx.EnrollmentResponse{
	// 	idxContext:     lr.Context(),
	// 	availableSteps: lr.availableSteps,
	// }
	// er, err = er.SetNewPassword(ctx, "P@ssw0rd")
	// if err != nil {
	// 	log.Fatalf("SetNewPassword error: %v\n", err)
	// }
	// fmt.Printf("%+v\n", er)
}
