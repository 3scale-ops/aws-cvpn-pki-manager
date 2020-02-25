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

# DEV environment
TF_CMD := docker run -ti -v $$(pwd):/work -w /work --network host hashicorp/terraform:light

dev-env-up:
	docker run --cap-add=IPC_LOCK -d -p 8200:8200 --name=dev-vault -e 'VAULT_DEV_ROOT_TOKEN_ID=myroot' vault:$(VAULT_RELEASE)
	cd test/tf-dataset1 && \
		$(TF_CMD) init && \
		$(TF_CMD) apply --auto-approve

dev-env-down:
	docker rm -f $$(docker ps -aqf "name=dev-vault")
	find test/ -type f -name "*.tfstate*" -exec rm -f {} \;

test:
	$(MAKE) dev-env-up
