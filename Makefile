GOCMD=go
GOBUILD=$(GOCMD) build -buildmode=plugin
GOCLEAN=$(GOCMD) clean
BINARY_NAME=nori_auth.so

ifndef PLUGIN_DIR # to allow PLUGIN_DIR to be given as args (see CI)
	DIR=$(shell pwd)
	PLUGIN_DIR=$(DIR)/bin

.PHONY: all build clean

all: build
build:
	mkdir -p $(PLUGIN_DIR);
	$(GOBUILD) -o $(PLUGIN_DIR)/$(BINARY_NAME) -v
clean:
	$(GOCLEAN)
	rm -f $(PLUGIN_DIR)/$(BINARY_NAME)