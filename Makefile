#!/bin/make
CC=gcc
PKGS=libcrypto libssl
CFLAGS:=-Wall -pipe -O2 -g -ggdb $(shell pkg-config --cflags $(PKGS))
LDFLAGS:=
LIBS:=$(shell pkg-config --libs $(PKGS))
TARGET=echeck
SOURCES=main.c common.c cert_utils.c sgx_quote_parser.c sgx_quote_verify.c sgx_utils.c sgx_cert_verify.c ca.c
OBJECTS=$(SOURCES:.c=.o)
HEADERS=sgx_types.h common.h cert_utils.h sgx_quote_parser.h sgx_quote_verify.h sgx_utils.h sgx_cert_verify.h ca.h

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LIBS)

%.o: %.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $@ $<

test: $(TARGET)
	@echo "Running tests on all certificate files in test directory..."
	@echo "Using built-in CA certificates"
	@for file in test/*.pem; do \
		echo "\n\n===== Testing $$file with built-in CA ====="; \
		./$(TARGET) $$file || exit 1; \
	done
	@echo "\nAll tests passed successfully!"

clean:
	$(RM) $(TARGET) $(OBJECTS)

.PHONY: all clean test