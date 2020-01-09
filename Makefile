RELEASE=0.1.0

build-linux:
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -a -ldflags '-extldflags "-static"' -o build/aws-cvpn-pki-manager-amd64_$(RELEASE) cmd/main.go