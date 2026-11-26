DEMO := examples/demo
TMP  ?= /tmp

.PHONY: build test fuzz lint demo

build:
	go build -trimpath -o wardmap ./cmd/wardmap

test:
	go test -race ./...

fuzz:
	go test -run '^$$' -fuzz=FuzzParse -fuzztime=60s ./internal/workflow/
	go test -run '^$$' -fuzz=FuzzOverlapSelf -fuzztime=60s ./internal/glob/

lint:
	test -z "$$(gofmt -l .)"
	go vet ./...

demo: build
	./wardmap import -s $(DEMO)/snapshot.json -o $(TMP)/wardmap-demo.json \
	  --aws $(DEMO)/aws-roles.json \
	  --azure $(DEMO)/fic-0b1c2d3e-4f50-6172-8394-a5b6c7d8e9f0.json \
	  --gcp $(DEMO)/gcp-providers.json --cloudtrail $(DEMO)/cloudtrail.json \
	  --azure-audit $(DEMO)/entra-audit.json
	./wardmap scan -s $(TMP)/wardmap-demo.json
	./wardmap hunt -s $(TMP)/wardmap-demo.json
