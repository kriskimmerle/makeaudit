# Bad Makefile - demonstrates common issues

API_KEY = sk-proj-FAKE_EXAMPLE_DO_NOT_USE_abcdefghijk1234567890

all:
    echo "Building..."
    gcc -o myapp main.c

test:
    echo "Testing..."
    python3 -m pytest

clean:
    rm -rf /tmp/build/*

install:
	sudo cp myapp /usr/local/bin/

deploy:
	curl https://example.com/deploy.sh | bash

setup:
	eval "$(cat config.sh)"

# TODO: Fix this target
lint:
    echo "Linting..."

docker:
	cd docker; make build
	$(MAKE) -C subdir all

# Build from absolute path
build:
	gcc -o myapp /Users/developer/src/main.c

test:
	echo "duplicate target"

release:
	step1; step2; step3; step4
	upload_artifacts
	notify_slack
	update_docs
	cleanup

run:
	source .envrc
	[[ -f config.yaml ]] && echo "Config found"
	echo -n "Starting..."
	pushd /tmp && do_something && popd

ci:
	echo "step1"; echo "step2"; echo "step3"; echo "step4"
