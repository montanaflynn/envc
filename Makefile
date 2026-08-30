VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X github.com/montanaflynn/envc/internal/cli.Version=$(VERSION)

.PHONY: build test e2e vet fmt install clean release

build:
	go build -ldflags '$(LDFLAGS)' -o envc ./cmd/envc

install:
	go install -ldflags '$(LDFLAGS)' ./cmd/envc

test:
	go test -race ./...

vet:
	go vet ./...
	@test -z "$$(gofmt -l .)" || { gofmt -l .; echo 'gofmt: files need formatting'; exit 1; }

e2e: build
	./scripts/e2e.sh ./envc

clean:
	rm -rf envc dist

# cross-compile static binaries into dist/
release:
	@mkdir -p dist
	@for t in darwin/arm64 darwin/amd64 linux/amd64 linux/arm64; do \
		os=$${t%/*}; arch=$${t#*/}; \
		echo "building $$os/$$arch"; \
		CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch go build -ldflags '$(LDFLAGS)' -o dist/envc-$$os-$$arch ./cmd/envc; \
	done
