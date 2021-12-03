# verification-error
### To Install
```
git clone https://github.com/emanor-okta/saml-assertion-flow-with-okta.git
cd saml-assertion-flow-with-okta
go mod tidy
```

### To Run
```
go run main.go
```  

Will create 3 .txt files    
* staged.txt - staged users attempted to login and are still staged
* non-existent.txt - users that don't exist and never registered
* now-active.txt - users that were eister once Staged or didn't exist and are now non staged users. Current status is shown
   

