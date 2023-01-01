package main

import (
	"fmt"
	"time"

	jwtverifier "github.com/okta/okta-jwt-verifier-golang"
)

func main() {
	toValidate := map[string]string{}
	toValidate["aud"] = "api://default"
	toValidate["cid"] = "0oa8rc1vvUWbpGroC1d6"

	fmt.Println("1")
	jwtVerifierSetup := jwtverifier.JwtVerifier{
		// Issuer: "https://okta.oktamanor.com/oauth2/default",
		Issuer:           "http://localhost:8082/oauth2/default",
		ClaimsToValidate: toValidate,
		DiscoveryTimeout: 5,
	}

	fmt.Println("2")
	verifier := jwtVerifierSetup.New()
	fmt.Println("3")

	// token, err := verifier.VerifyAccessToken("eyJraWQiOiJyYXpCRXNCQ2lGcXlUMGxYT2lBcGZoYmgyQm9OWkd5VXBFQXVseGxkTTBZIiwiYWxnIjoiUlMyNTYifQ.eyJ2ZXIiOjEsImp0aSI6IkFULmtEdVJwajFOeGF2SUhsOGRoSHpENUUxaXN0aW41MDhGLXZzdEpNN3FEZmciLCJpc3MiOiJodHRwczovL29rdGEub2t0YW1hbm9yLmNvbS9vYXV0aDIvZGVmYXVsdCIsImF1ZCI6ImFwaTovL2RlZmF1bHQiLCJpYXQiOjE2NTg2NDA4MDMsImV4cCI6MTY1ODY0NDQwMywiY2lkIjoiMG9hOHJjMXZ2VVdicEdyb0MxZDYiLCJ1aWQiOiIwMHU0c3VuNmlPUlFHdFlobDFkNiIsInNjcCI6WyJvcGVuaWQiLCJlbWFpbCIsInByb2ZpbGUiLCJncm91cHMiXSwiYXV0aF90aW1lIjoxNjU4NjQwNzk5LCJzaHJncnBzMyI6W10sInN1YiI6ImtheS53ZXN0QG9rdGFpY2UuY29tIiwiZnJvbVByb2ZpbGUiOlsiRXZlcnlvbmUiXSwiTXlUZXN0IjpbXX0.TIQONHyVKdaaPS_UowyLMM1peRCjpEkc3iYXHDz8zRutcNqAcmi6SX73RTXngxbgeQlXvJugUYBrjM-zT51lOl4EtA0ObwEIu6GUzoj4Nf7E-0tT2yzYZJAq99RewxE9C7O4vjaBbsjBRmxg-UV4R_pbs9RIhtIHajYw23fEs5fcMSUBgZiNImkWPvHqAL89UwemC-1nuMN93ls3uW4zEF3p0mdZ4RKbMXY760fXYonLvXrfah9lA24cO7U9QbPzyjQH9M4kvqvWxfkazloTRgnA50XivZNoDWZ-7zCJ-ONZNV7omSSUq3lgQAQbw8TQFbC_n81FUkgIoOO2OdAGvQ")
	token, err := verify("eyJraWQiOiJyYXpCRXNCQ2lGcXlUMGxYT2lBcGZoYmgyQm9OWkd5VXBFQXVseGxkTTBZIiwiYWxnIjoiUlMyNTYifQ.eyJ2ZXIiOjEsImp0aSI6IkFULmtEdVJwajFOeGF2SUhsOGRoSHpENUUxaXN0aW41MDhGLXZzdEpNN3FEZmciLCJpc3MiOiJodHRwczovL29rdGEub2t0YW1hbm9yLmNvbS9vYXV0aDIvZGVmYXVsdCIsImF1ZCI6ImFwaTovL2RlZmF1bHQiLCJpYXQiOjE2NTg2NDA4MDMsImV4cCI6MTY1ODY0NDQwMywiY2lkIjoiMG9hOHJjMXZ2VVdicEdyb0MxZDYiLCJ1aWQiOiIwMHU0c3VuNmlPUlFHdFlobDFkNiIsInNjcCI6WyJvcGVuaWQiLCJlbWFpbCIsInByb2ZpbGUiLCJncm91cHMiXSwiYXV0aF90aW1lIjoxNjU4NjQwNzk5LCJzaHJncnBzMyI6W10sInN1YiI6ImtheS53ZXN0QG9rdGFpY2UuY29tIiwiZnJvbVByb2ZpbGUiOlsiRXZlcnlvbmUiXSwiTXlUZXN0IjpbXX0.TIQONHyVKdaaPS_UowyLMM1peRCjpEkc3iYXHDz8zRutcNqAcmi6SX73RTXngxbgeQlXvJugUYBrjM-zT51lOl4EtA0ObwEIu6GUzoj4Nf7E-0tT2yzYZJAq99RewxE9C7O4vjaBbsjBRmxg-UV4R_pbs9RIhtIHajYw23fEs5fcMSUBgZiNImkWPvHqAL89UwemC-1nuMN93ls3uW4zEF3p0mdZ4RKbMXY760fXYonLvXrfah9lA24cO7U9QbPzyjQH9M4kvqvWxfkazloTRgnA50XivZNoDWZ-7zCJ-ONZNV7omSSUq3lgQAQbw8TQFbC_n81FUkgIoOO2OdAGvQ", verifier, 1)
	fmt.Println("4")
	fmt.Printf("Err: %+v\n", err)
	fmt.Printf("Err != nil: %+v\n", err != nil)
	if err != nil {
		fmt.Printf("Error validating token: %v\n", err)
	}
	fmt.Printf("Token: %+v\n", token)
	time.Sleep(time.Minute * 5)
}

func verify(token string, verifier *jwtverifier.JwtVerifier, att int) (*jwtverifier.Jwt, error) {
	t, err := verifier.VerifyAccessToken(token)
	if err != nil {
		fmt.Printf("Error validating token: %v\n", err)
		if att >= 3 {
			return nil, err
		}
		return verify(token, verifier, att+1)
	}
	return t, nil
}
