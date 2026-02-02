# Good Makefile - follows best practices

SHELL := /bin/bash
.DEFAULT_GOAL := all

# Project configuration
PROJECT := myapp
VERSION := 1.0.0
BUILD_DIR := build
SRC_DIR := src
PREFIX ?= /usr/local

# Compiler settings
CC ?= gcc
CFLAGS ?= -Wall -Wextra -O2
LDFLAGS ?=

# Source files
SRCS := $(wildcard $(SRC_DIR)/*.c)
OBJS := $(SRCS:$(SRC_DIR)/%.c=$(BUILD_DIR)/%.o)

.PHONY: all clean test lint install help

all: $(BUILD_DIR)/$(PROJECT)

$(BUILD_DIR)/$(PROJECT): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $^

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c -o $@ $<

$(BUILD_DIR):
	mkdir -p $@

test:
	python3 -m pytest tests/ -v

lint:
	flake8 scripts/
	shellcheck scripts/*.sh

clean:
	rm -rf $(BUILD_DIR)

install: $(BUILD_DIR)/$(PROJECT)
	install -d $(DESTDIR)$(PREFIX)/bin
	install -m 755 $(BUILD_DIR)/$(PROJECT) $(DESTDIR)$(PREFIX)/bin/

help:
	@echo "Targets:"
	@echo "  all      - Build $(PROJECT)"
	@echo "  test     - Run tests"
	@echo "  lint     - Run linters"
	@echo "  clean    - Remove build artifacts"
	@echo "  install  - Install to $(PREFIX)"
	@echo "  help     - Show this help"
