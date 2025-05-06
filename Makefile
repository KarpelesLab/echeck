#!/bin/make
CC=gcc
PKGS=libcrypto libssl
CFLAGS:=-Wall -pipe -O2 -g -ggdb $(shell pkg-config --cflags $(PKGS))
LDFLAGS:=
LIBS:=$(shell pkg-config --libs $(PKGS))
TARGET=echeck
OBJECTS=main.o

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $< $(LIBS)

# Header dependencies
main.o: main.c sgx_types.h

clean:
	$(RM) $(TARGET) $(OBJECTS)
