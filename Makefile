.PHONY: all build clean

all: build

build:
	nix build

clean:
	rm -rf target result result-*
