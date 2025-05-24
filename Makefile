.PHONY: all clean build test

# Output binary names
BINARY = wrapguard
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
    LIBRARY = libwrapguard.dylib
else
    LIBRARY = libwrapguard.so
endif

# Go build flags
GO_BUILD_FLAGS = -ldflags="-s -w"

# C compiler flags
CC = gcc
CFLAGS = -fPIC -shared -Wall -O2

all: build

build: $(BINARY) $(LIBRARY)

$(BINARY): *.go go.mod
	go build $(GO_BUILD_FLAGS) -o $(BINARY) .

$(LIBRARY): lib/intercept.c
	$(CC) $(CFLAGS) -o $(LIBRARY) lib/intercept.c -ldl -lpthread

test: build
	# Test basic connectivity
	./test.sh

clean:
	rm -f $(BINARY) $(LIBRARY)
	go clean -cache

install: build
	install -m 755 $(BINARY) /usr/local/bin/
	install -m 755 $(LIBRARY) /usr/local/lib/

.PHONY: deps
deps:
	go mod download
	go mod tidy