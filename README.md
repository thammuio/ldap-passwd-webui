# Web UI for LDAP changing password  

WebUI Client capable of connecting to backend LDAP server and changing the users password.

![Screenshot](screenshots/index.png)

The configuration is made with environment variables:

|Env variable|Default value|Description|
|------------|-------------|-----------|
|LPW_TITLE|Change your global password for example.org|Title that will appear on the page|
|LPW_HOST||LDAP Host to connect to|
|LPW_PORT|636|LDAP Port (389|636 are default LDAP/LDAPS)|
|LPW_TYPE| | AD or LDAP |
|LPW_ENCRYPTED|true|Use enrypted communication|
|LPW_START_TLS|false|Start TLS communication|
|LPW_SSL_SKIP_VERIFY|true|Skip TLS CA verification|
|LPW_USER_DN|uid=%s,ou=people,dc=example,dc=org|Filter expression to search the user for Binding|
|LPW_USER_SEARCH_FILTER|"(&(objectCategory=Person)(sAMAccountName=%s))"| Search Filter to get userDN|
|LPW_BIND_DN| | Bind DN |
|LPW_BIND_DN_PASS| | Password for Bind DN |
|LPW_USER_BASE|ou=people,dc=example,dc=org|Base to use when doing the binding|

## Running

```sh
dep ensure
go run main.go
```

Browse [http://localhost:8443/](http://localhost:8443/)


## Building and tagging

Get [Godep](https://github.com/golang/dep)
```sh
go get -u github.com/golang/dep/cmd/dep
```

```sh
make
```

## Credits
 * [Web UI for changing LDAP password - Go - Modified](https://github.com/npenkov/ldap-passwd-webui)
 * [Web UI for changing LDAP password - python](https://github.com/jirutka/ldap-passwd-webui)
 * [Gitea](https://github.com/go-gitea/gitea)
 * [dchest/captcha](https://github.com/dchest/captcha)