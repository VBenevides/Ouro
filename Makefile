PREFIX ?= $(HOME)/.local
BINDIR ?= $(DESTDIR)$(PREFIX)/bin
VERSION := $(shell tr -d '\r\n' < VERSION)

.PHONY: build install uninstall test

build:
	CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o dist/ouro ./cmd/ouro

install: build
	install -d "$(BINDIR)"
	install -m 0755 dist/ouro "$(BINDIR)/ouro"
	@echo "Installed ouro $(VERSION) to $(BINDIR)/ouro"
	@echo "Print the agent skill with: ouro skill"

uninstall:
	rm -f "$(BINDIR)/ouro"

test:
	go test ./...
