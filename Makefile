RELEASE=$(shell cat RELEASE)

build: build/aws-cvpn-pki-manager_amd64_$(RELEASE)

build/aws-cvpn-pki-manager_amd64_$(RELEASE):
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -a -ldflags '-extldflags "-static"' -o build/aws-cvpn-pki-manager_amd64_$(RELEASE) cmd/main.go

docker-build: build/aws-cvpn-pki-manager_amd64_$(RELEASE)
	docker build . -t quay.io/3scale/aws-cvpn-pki-manager:v$(RELEASE) --build-arg release=$(RELEASE)

docker-tag-latest: docker-build
	docker tag quay.io/3scale/aws-cvpn-pki-manager:v$(RELEASE) quay.io/3scale/aws-cvpn-pki-manager:latest

clean:
	rm -rf build/*