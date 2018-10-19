.PHONY: all build push

all: init build docker push clean

init:
	dep ensure
	
build:
	GOOS=linux go build -o ldap-pass-webui main.go

clean:
	rm -rf ldap-pass-webui