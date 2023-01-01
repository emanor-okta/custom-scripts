package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"regexp"
	"strconv"
	"strings"
)

const timeout_key = "e2bfb730-ecaa-11e6-8f88-34363bc7c4c0"
const nano = int64(60000000000)

var regx = regexp.MustCompile("^.*(okta_app_saml|okta_app_oauth|okta_app_secure_password_store|okta_app_shared_credentials|okta_app_swa|okta_app_auto_login|okta_app_basic_auth|okta_app_bookmark|okta_app_group_assignment).*$")

type config struct {
	recursive           bool
	baseDir             string
	backUp              bool
	read                int64
	update              int64
	create              int64
	oauth               bool
	saml                bool
	okta_app_auto_login bool
}

func main() {
	c := config{
		baseDir: ".",
	}
	parseArgs(&c)
	if c.create == 0 && c.read == 0 && c.update == 0 {
		useage()
		os.Exit(98)
	}
	modifyStateFiles(&c, c.baseDir)
}

func modifyStateFiles(c *config, base string) {
	files, err := os.ReadDir(base)
	if err != nil {
		log.Fatalf("Error Reading dir %v, %v", base, err)
	}

	for _, file := range files {
		if file.IsDir() && c.recursive {
			modifyStateFiles(c, fmt.Sprintf("%s/%s", base, file.Name()))
		} else if strings.HasSuffix(file.Name(), ".tfstate") {
			updateFile(c, fmt.Sprintf("%s/%s", base, file.Name()))
		}
	}
}

func updateFile(c *config, tf string) {
	b, err := os.ReadFile(tf)
	if err != nil {
		log.Fatalf("Error reading File: %s, %v\n", string(b), err)
	}

	update := false
	var m map[string]interface{}
	json.Unmarshal(b, &m)
	for _, r := range m["resources"].([]interface{}) {
		// if r.(map[string]interface{})["type"].(string) == "okta_app_oauth" {
		if regx.MatchString(r.(map[string]interface{})["type"].(string)) {
			update = true
			b64 := r.(map[string]interface{})["instances"].([]interface{})[0].(map[string]interface{})["private"]
			sDec, _ := base64.StdEncoding.DecodeString(b64.(string))
			var private map[string]interface{}

			if err := json.Unmarshal(sDec, &private); err != nil || private == nil {
				private = make(map[string]interface{}, 0)
				private[timeout_key] = map[string]interface{}{}
			}
			if c.create > 0 {
				private[timeout_key].(map[string]interface{})["create"] = c.create
			}
			if c.read > 0 {
				private[timeout_key].(map[string]interface{})["read"] = c.read
			}
			if c.update > 0 {
				private[timeout_key].(map[string]interface{})["update"] = c.update
			}
			mPrivate, err := json.Marshal(private)
			if err != nil {
				log.Fatalf("Error Marshalling `private` attribute, %+v\n", err)
			}
			sEnc := base64.StdEncoding.EncodeToString(mPrivate)
			r.(map[string]interface{})["instances"].([]interface{})[0].(map[string]interface{})["private"] = sEnc
		}
	}

	if !update {
		return
	}

	log.Printf("-Updating %v\n", tf)
	if c.backUp {
		log.Printf("--backing up %s\n", tf)
		fi, err := os.Lstat(tf)
		if err != nil {
			log.Fatal(err)
		}
		if err = os.WriteFile(fmt.Sprintf("%s.timeout.backup", tf), b, fi.Mode().Perm()); err != nil {
			log.Fatal(err)
		}
	}

	tfState, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		log.Fatalf("Error: %+v\n", err)
	}
	if err = os.WriteFile(tf, tfState, 0744); err != nil {
		log.Fatalf("Error writing, %+v\n", err)
	}
}

func parseArgs(c *config) {
	for _, a := range os.Args[1:] {
		if a == "-r" {
			c.recursive = true
		} else if a == "-b" {
			c.backUp = true
		} else if strings.HasPrefix(a, "-read") {
			parseInt(&c.read, a)
		} else if strings.HasPrefix(a, "-update") {
			parseInt(&c.update, a)
		} else if strings.HasPrefix(a, "-create") {
			parseInt(&c.create, a)
		} else {
			c.baseDir = a
		}
	}
}

func parseInt(i *int64, a string) {
	_, val, found := strings.Cut(a, "=")
	if !found {
		useage()
		os.Exit(99)
	}
	i_, err := strconv.ParseInt(val, 10, 64)
	if err != nil {
		log.Fatalf("Unable to parse timeout value: %v, err: %v\n", a, err)
	}
	*i = i_ * nano
}

func useage() {
	fmt.Printf("\n\nUseage:\n")
	fmt.Println("go run main.go [options] [parent dir]")
	fmt.Println("go run main.go [-r] [-b] [-create=90 | -read=90 | -update=90] [/my/parent_dir]")
	fmt.Println("-r          recursive")
	fmt.Println("-b          backup state file")
	fmt.Println("-create     timeout for create operation in minutes")
	fmt.Println("-read       timeout for read operation in minutes")
	fmt.Println("-update     timeout for update operation in minutes")
	fmt.Printf("parent_dir  directory to run in, defaults to ./\n\n")
}
