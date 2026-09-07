GO ?= go
GOARCH ?= $(shell $(GO) env GOHOSTARCH)
PREFIX ?= /usr/local

.PHONY: build test release install clean require-linux
build:
	mkdir -p dist
	CGO_ENABLED=0 GOOS=linux GOARCH=$(GOARCH) $(GO) build -buildvcs=false -trimpath -ldflags='-s -w' -o dist/impair ./cmd/impair
test: require-linux
	$(GO) test -race -cover ./...
	$(GO) vet ./...
release:
	mkdir -p dist
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build -buildvcs=false -trimpath -ldflags='-s -w' -o dist/impair-linux-amd64 ./cmd/impair
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 $(GO) build -buildvcs=false -trimpath -ldflags='-s -w' -o dist/impair-linux-arm64 ./cmd/impair
	cd dist && if command -v sha256sum >/dev/null 2>&1; then sha256sum impair-linux-amd64 impair-linux-arm64 > SHA256SUMS; else shasum -a 256 impair-linux-amd64 impair-linux-arm64 > SHA256SUMS; fi
install: require-linux build
	install -m 0755 dist/impair $(DESTDIR)$(PREFIX)/bin/impair
require-linux:
	@test "$$($(GO) env GOHOSTOS)" = linux || { echo 'Tests and installation require Linux. On macOS, use make or make release to cross-compile, then copy the binary to Linux.' >&2; exit 1; }
clean:
	rm -f dist/impair dist/impair-linux-amd64 dist/impair-linux-arm64 dist/SHA256SUMS
