package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"strconv"
	"time"

	"github.com/okta/okta-sdk-golang/v2/okta"
	"github.com/okta/okta-sdk-golang/v2/okta/query"
)

/*
 * LogsRL - range [1-100], indicates % of rate limit for /api/v1/logs has been used when a back off will take place
 * UsersRL - range [1-100], indicates % of rate limit for /api/v1/users has been used when a back off will take place
 * ex. a value of 65 will back off once 65% of API calls have been used for a 60 second window for a apecific rate limit
 */
const (
	OrgURL   string = "https://{DOMAIN}.okta.com"
	APIToken string = "{API_TOKEN}"
	LogsRL   int    = 60
	UsersRL  int    = 60
)

var client *okta.Client
var users map[string]int
var nonExistent []string
var nowActive []string
var staged []string

func main() {
	var err error
	_, client, err = okta.NewClient(context.TODO(), okta.WithOrgUrl(OrgURL), okta.WithToken(APIToken))
	if err != nil {
		log.Fatalf("Error Initializing Okta Mgmt Client: %s\n", err)
	}

	getEvents()
	getStaged()
	//checkNonStagedUsers()				// uncomment to check for users that have become active or don't exist. Adds run time with user lookups
	writeToFile("staged.txt", staged)
	//writeToFile("non-existent.txt", nonExistent)	// uncomment if checkNonStagedUsers() is uncommented
	//writeToFile("now-active.txt", nowActive)	// uncomment if checkNonStagedUsers() is uncommented
}

func getEvents() {
	users = make(map[string]int)
	events, resp, err := client.LogEvent.GetLogs(context.TODO(), query.NewQueryParams(query.WithFilter("outcome.reason eq \"VERIFICATION_ERROR\""), query.WithSince("2017-10-01T00:00:00.000Z"), query.WithLimit(1000)))
	if err != nil {
		log.Fatalf("Error calling GetLogs: %s\n", err)
	}
	next := ""
	for _, val := range events {
		users[val.Actor.AlternateId] = users[val.Actor.AlternateId] + 1
	}

	for next != resp.NextPage && resp.NextPage != "" {
		checkRateLimit(resp.Header, LogsRL)
		fmt.Printf("Getting next block of events\n")
		var events2 []*okta.LogEvent
		next = resp.NextPage
		resp, err = resp.Next(context.TODO(), &events2)

		if err != nil {
			log.Fatalf("Error calling inner GetLogs: %s\n", err)
		}

		for _, val := range events2 {
			users[val.Actor.AlternateId] = users[val.Actor.AlternateId] + 1
		}
	}
}

func getStaged() {
	stagedUsers, resp, err := client.User.ListUsers(context.TODO(), query.NewQueryParams(query.WithFilter("status eq \"STAGED\""), query.WithLimit(200)))
	if err != nil {
		log.Fatalf("Error calling Get Staged Users: %s\n", err)
	}
	next := ""
	checkStagedUsers(stagedUsers)
	for next != resp.NextPage && resp.NextPage != "" {
		checkRateLimit(resp.Header, UsersRL)
		fmt.Printf("Getting next block of staged users\n")
		var stagedUsers2 []*okta.User
		next = resp.NextPage
		resp, err = resp.Next(context.TODO(), &stagedUsers2)

		if err != nil {
			log.Fatalf("Error calling Inner Get Staged Users: %s\n", err)
		}
		checkStagedUsers(stagedUsers2)
	}
}

func checkStagedUsers(stagedUsers []*okta.User) {
	for _, u := range stagedUsers {
		if user, ok := (*u.Profile)["login"].(string); ok {
			if _, ok := users[user]; ok {
				staged = append(staged, user)
				delete(users, user)
			}
		} else {
			fmt.Printf("ERROR converting staged name to string: %v\n", (*u.Profile)["login"])
		}
	}
}

func checkNonStagedUsers() {
	cnt := 0
	for k, _ := range users {
		u, resp, err := client.User.GetUser(context.TODO(), k)
		if err != nil {
			nonExistent = append(nonExistent, k)
			checkRateLimit(resp.Header, UsersRL)
			continue
		}
		cnt += 1
		if (cnt)%50 == 0 {
			fmt.Printf("Checked status of %d users\n", cnt)
		}

		if u != nil {
			nowActive = append(nowActive, fmt.Sprintf("%s : %s", k, u.Status))
		} else {
			nonExistent = append(nonExistent, k)
		}
		checkRateLimit(resp.Header, UsersRL)
	}
}

func checkRateLimit(headers map[string][]string, percent int) {
	if percent < 1 || percent > 100 {
		log.Fatalf("Rate Limit value needs to be in range of [1-100]")
	}
	p := float64(percent) * 0.01
	rateLimit := headers["X-Rate-Limit-Limit"]
	rateLimitRemaining := headers["X-Rate-Limit-Remaining"]
	rateLimitReset := headers["X-Rate-Limit-Reset"]

	if len(rateLimit) > 0 && len(rateLimitRemaining) > 0 && len(rateLimitReset) > 0 {
		fmt.Printf("RateLimit: %v, RateLimitRemaining: %v\n", rateLimit, rateLimitRemaining)
		rlremain, _ := strconv.ParseFloat(rateLimitRemaining[0], 64)
		rl, _ := strconv.ParseFloat(rateLimit[0], 64)

		if rl-rlremain >= p*rl {
			rlreset, _ := strconv.ParseInt(rateLimitReset[0], 10, 64)
			fmt.Printf("Sleeping for: %v seconds\n", rlreset-time.Now().Unix()+1)
			time.Sleep(time.Duration(rlreset-time.Now().Unix()+1) * time.Second)
		}
	}
}

func writeToFile(name string, data []string) {
	f, err := os.Create("./" + name)
	if err != nil {
		log.Fatalf("Error writing to file: %s\n", err)
	}
	defer f.Close()

	for _, v := range data {
		f.WriteString(fmt.Sprintf("%s\n", v))
	}
	f.WriteString(fmt.Sprintf("\nTotal: %v\n", len(data)))
	f.Sync()
}
