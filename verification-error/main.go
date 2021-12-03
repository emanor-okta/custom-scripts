package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/okta/okta-sdk-golang/v2/okta"
	"github.com/okta/okta-sdk-golang/v2/okta/query"
)

const (
	OrgURL   string = "https://{DOMAIN}.okta.com"
	APIToken string = "{API_TOKEN}"
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
	checkNonStagedUsers()
	writeToFile("staged.txt", staged)
	writeToFile("non-existent.txt", nonExistent)
	writeToFile("now-active.txt", nowActive)
}

func getEvents() {
	users = make(map[string]int)
	events, resp, err := client.LogEvent.GetLogs(context.TODO(), query.NewQueryParams(query.WithFilter("outcome.reason eq \"VERIFICATION_ERROR\""), query.WithSince("2017-10-01T00:00:00.000Z")))
	if err != nil {
		log.Fatalf("Error calling GetLogs: %s\n", err)
	}
	next := ""
	for _, val := range events {
		users[val.Actor.AlternateId] = users[val.Actor.AlternateId] + 1
	}

	for next != resp.NextPage && resp.NextPage != "" {
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
	stagedUsers, resp, err := client.User.ListUsers(context.TODO(), query.NewQueryParams(query.WithFilter("status eq \"STAGED\"")))
	if err != nil {
		log.Fatalf("Error calling Get Staged Users: %s\n", err)
	}
	next := ""
	checkStagedUsers(stagedUsers)

	for next != resp.NextPage && resp.NextPage != "" {
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
				// staged = append(staged, fmt.Sprintf("%s : %d", user, users[user]))
				delete(users, user)
			}
		} else {
			fmt.Printf("ERROR converting staged name to string: %v\n", (*u.Profile)["login"])
		}
	}
}

func checkNonStagedUsers() {
	cnt := 0
	// for k, v := range users {
	for k, _ := range users {
		found, _, err := client.User.ListUsers(context.TODO(), query.NewQueryParams(query.WithFilter(fmt.Sprintf("profile.login eq \"%s\"", k))))
		if err != nil {
			fmt.Printf("Warning checking if user %s exists: %s, adding to nonExistent\n", k, err)
			nonExistent = append(nonExistent, k)
			// nonExistent = append(nonExistent, fmt.Sprintf("%s : %d", k, v))
			continue
		}
		cnt += 1
		if (cnt)%50 == 0 {
			fmt.Printf("Checked status of %d users\n", cnt)
		}

		if len(found) > 0 {
			nowActive = append(nowActive, fmt.Sprintf("%s : %s", k, found[0].Status))
			// nowActive = append(nowActive, fmt.Sprintf("%s : %d : %s", k, v, found[0].Status))
		} else {
			nonExistent = append(nonExistent, k)
			// nonExistent = append(nonExistent, fmt.Sprintf("%s : %d", k, v))
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
	f.Sync()
}
