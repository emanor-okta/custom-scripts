package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
)

func main() {
	http.HandleFunc("/assets/dist/labels/json/", handleI18nPropertyReq)

	if err := http.ListenAndServe(":8082", nil); err != nil {
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
