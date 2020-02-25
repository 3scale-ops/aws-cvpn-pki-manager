VAULT_RELEASE=1.2.3
ACPM_RELEASE=$(shell cat RELEASE)

build: build/aws-cvpn-pki-manager_amd64_$(ACPM_RELEASE)

build/aws-cvpn-pki-manager_amd64_$(ACPM_RELEASE):
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -a -ldflags '-extldflags "-static"' -o build/aws-cvpn-pki-manager_amd64_$(ACPM_RELEASE) cmd/main.go

docker-build: build/aws-cvpn-pki-manager_amd64_$(ACPM_RELEASE)
	docker build . -t quay.io/3scale/aws-cvpn-pki-manager:v$(ACPM_RELEASE) --build-arg ACPM_RELEASE=$(ACPM_RELEASE)

docker-tag-latest: docker-build
	docker tag quay.io/3scale/aws-cvpn-pki-manager:v$(ACPM_RELEASE) quay.io/3scale/aws-cvpn-pki-manager:latest

release: docker-tag-latest
	docker push quay.io/3scale/aws-cvpn-pki-manager:v$(ACPM_RELEASE)
	docker push quay.io/3scale/aws-cvpn-pki-manager:latest

clean:
	rm -rf build/*

# Dev Vault server
TF_CMD := docker run --rm -ti -v $$(pwd):/work -w /work --network host hashicorp/terraform:light
vault-up:
	docker run --cap-add=IPC_LOCK -d --network host --name=dev-vault -e 'VAULT_DEV_ROOT_TOKEN_ID=myroot' vault:$(VAULT_RELEASE)
	cd test/tf-dataset1 && \
		$(TF_CMD) init && \
		$(TF_CMD) apply --auto-approve
vault-down:
	docker rm -f $$(docker ps -aqf "name=dev-vault")
	find test/ -type f -name "*.tfstate*" -exec rm -f {} \;

# Dev ACPM server
ACPM_CMD := docker run --network host -d --name=dev-acpm -v $$(pwd):/work -w /work debian:buster-slim build/aws-cvpn-pki-manager_amd64_$(ACPM_RELEASE) server
acpm-up:
	$(ACPM_CMD) --vault-auth-token myroot --client-vpn-endpoint-id "placeholder" --vault-pki-paths pki
acpm-down:
	docker rm -f $$(docker ps -aqf "name=dev-acpm")

all-up: vault-up acpm-up
all-down: acpm-down vault-down

run-tests: all-up
	docker run --rm -ti --network host --name=curl-runnings -v $$(pwd):/work -w /work debian:buster-slim test/run-integration-tests.sh
	$(MAKE) all-down