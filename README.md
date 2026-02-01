# makeaudit

A pure Python Makefile linter with zero dependencies. Checks for common issues, best practices, and portability problems in Makefiles.

## Features

- **Zero dependencies** - Uses only Python standard library
- **12 comprehensive rules** - Covers common Makefile pitfalls
- **Multiple output formats** - Text and JSON
- **CI-friendly** - Exit codes and severity filtering
- **Lightweight** - Single file, ~500 lines

## Installation

```bash
# Clone and use directly
git clone https://github.com/kriskimmerle/makeaudit
cd makeaudit
python3 makeaudit.py [OPTIONS] [MAKEFILE]

# Or download just the script
curl -O https://raw.githubusercontent.com/kriskimmerle/makeaudit/main/makeaudit.py
chmod +x makeaudit.py
```

## Usage

```bash
# Lint ./Makefile
makeaudit

# Lint specific file
makeaudit Makefile.prod

# JSON output
makeaudit --format json

# Only show errors and warnings
makeaudit --severity warning

# CI mode (exit 1 if errors found)
makeaudit --check

# Ignore specific rules
makeaudit --ignore MA001 --ignore MA005

# List all rules
makeaudit --list-rules
```

## Rules

### MA001: Missing .PHONY declaration
**Severity:** WARNING

Targets that don't create files should be declared `.PHONY` to avoid conflicts with files of the same name and to optimize build performance.

```makefile
# Bad
clean:
	rm -rf build/

# Good
.PHONY: clean
clean:
	rm -rf build/
```

### MA002: Undefined variable
**Severity:** ERROR

Variables referenced with `$(VAR)` or `${VAR}` must be defined. This excludes Make's automatic variables (`$@`, `$<`, etc.) and built-ins.

```makefile
# Bad
build:
	gcc -o $(OUTPUT) main.c  # OUTPUT never defined

# Good
OUTPUT = app
build:
	gcc -o $(OUTPUT) main.c
```

### MA003: Missing help target
**Severity:** INFO

A `help` target improves discoverability and is considered best practice for developer-friendly Makefiles.

```makefile
# Good
.PHONY: help
help:
	@echo "Available targets:"
	@echo "  build - Build the project"
	@echo "  test  - Run tests"
```

### MA004: Spaces instead of tabs
**Severity:** ERROR

Make requires recipe lines to be indented with **tabs**, not spaces. This is a common copy-paste error.

```makefile
# Bad
build:
    echo "spaces"  # ERROR

# Good
build:
	echo "tabs"  # Correct (tab character)
```

### MA005: Unused variable
**Severity:** INFO

Variables that are defined but never used may indicate dead code or typos.

```makefile
# Bad
UNUSED = value  # Never referenced

# Good
OUTPUT = app
build:
	gcc -o $(OUTPUT) main.c
```

### MA006: Shell portability issue
**Severity:** WARNING

Using bash-specific syntax without setting `SHELL := /bin/bash` can cause failures on systems where `/bin/sh` is not bash.

Detected bash-isms:
- `[[ ... ]]` (use `[ ... ]` or `test`)
- Process substitution `<(...)`
- Here strings `<<<`
- Brace expansion `{a..z}`

```makefile
# Bad
check:
	if [[ -f file ]]; then echo "exists"; fi

# Good
SHELL := /bin/bash
check:
	if [[ -f file ]]; then echo "exists"; fi

# Or use POSIX syntax
check:
	if [ -f file ]; then echo "exists"; fi
```

### MA007: Missing .DEFAULT_GOAL
**Severity:** INFO

Without `.DEFAULT_GOAL` or an `all` target, running `make` with no arguments may not do what you expect.

```makefile
# Good
.DEFAULT_GOAL := build

# Or
.PHONY: all
all: build test
```

### MA008: Recursive make
**Severity:** INFO

Using `$(MAKE) -C` or `make -C` is often a code smell. Recursive make can cause build issues (see "Recursive Make Considered Harmful").

```makefile
# Flagged for awareness
subdir:
	$(MAKE) -C subdirectory
```

### MA009: Hardcoded absolute paths
**Severity:** WARNING

Absolute paths like `/usr/bin/python3` reduce portability. Use `PATH` or variables.

```makefile
# Bad
install:
	/usr/bin/python3 setup.py install

# Good
PYTHON := python3
install:
	$(PYTHON) setup.py install
```

### MA010: Missing clean target
**Severity:** INFO

A `clean` target is standard practice for removing build artifacts.

```makefile
.PHONY: clean
clean:
	rm -rf build/ dist/
```

### MA011: Missing error handling
**Severity:** WARNING

Multi-line recipes should use `set -e` or `&&` chaining to stop on first error.

```makefile
# Bad - continues even if git pull fails
deploy:
	git pull
	npm install
	npm run build

# Good
deploy:
	set -e; \
	git pull && \
	npm install && \
	npm run build
```

### MA012: Excessive echo suppression
**Severity:** INFO

Overusing `@` prefix (>75% of recipe lines) makes debugging difficult.

```makefile
# Bad
build:
	@echo "step 1"
	@echo "step 2"
	@echo "step 3"
	@echo "step 4"

# Better
build:
	echo "step 1"
	@echo "step 2"  # Only suppress when needed
	echo "step 3"
	echo "step 4"
```

## Exit Codes

- `0` - No issues or only info/warnings
- `1` - Errors found (when using `--check`)

## Examples

See the `examples/` directory:
- `Makefile.good` - Clean example following best practices
- `Makefile.bad` - Triggers multiple rules for testing

```bash
# Test against examples
python3 makeaudit.py examples/Makefile.bad
python3 makeaudit.py examples/Makefile.good
```

## Why Use makeaudit?

- **Catch errors early** - Find undefined variables before runtime
- **Improve portability** - Detect bash-isms and hardcoded paths
- **Team consistency** - Enforce best practices across projects
- **CI integration** - Automated checks in build pipelines
- **Learn best practices** - Educational descriptions for each rule

## Contributing

Issues and pull requests welcome at https://github.com/kriskimmerle/makeaudit

## License

MIT License - see LICENSE file

## Credits

Created by [Kris Kimmerle](https://github.com/kriskimmerle)

Inspired by years of debugging obscure Makefile issues.
