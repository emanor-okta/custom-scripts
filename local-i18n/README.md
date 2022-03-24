# local-i18n
### To Install
```
git clone https://github.com/emanor-okta/custom-scripts.git
cd local-i18n
go mod tidy
```

### To Run
```
go run main.go
```  

Listens on *:8082   
* serves /assets/dist/labels/json/country_*.json from properties folder
* serves /assets/dist/labels/json/login_*.json from properties folder
* adds access-control-allow header
   

