# local-i18n
### To Install
```
git clone https://github.com/emanor-okta/custom-scripts.git
cd iframe-widget
```

### Configure
```
edit embedded/parent.html  
modify {CLIENT_ID} with SPA client id
modify {DOMAIN} with Okta Org URL
```
```
edit embedded/child.html  
modify {CLIENT_ID} with SPA client id
modify {DOMAIN} with Okta Org URL
```
in SPA app add `http://localhost:8080/embedded/child.html` as a rediretURI and `http://localhost:8080/embedded/parent.html` as a logout redirectURI.


### To Run
```
run an http process from iframe-wdiget directory on listening on port 8080
```  

Navigate to http://localhost:8080/embedded/parent.html to test.   

