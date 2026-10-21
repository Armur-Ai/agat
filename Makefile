# agat — common development tasks. Run `make help` for the list.
.DEFAULT_GOAL := help
AGAT := ./target/release/agat

.PHONY: help build release test lint fmt check bench demo gifs docker airgap clean

help: ## show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
	  | awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-10s\033[0m %s\n", $$1, $$2}'

build: ## debug build
	cargo build

release: ## optimized build of the agat binary
	cargo build --release -p agat-cli

test: ## run the whole test suite
	cargo test --workspace

lint: ## rustfmt check + clippy as errors
	cargo fmt --all --check
	cargo clippy --workspace --all-targets -- -D warnings

fmt: ## format the workspace
	cargo fmt --all

check: lint test ## lint and test (what CI runs)

bench: release ## run the evidence benchmarks (needs bench/corpus; see bench/fetch-benign.sh)
	bench/generalize.sh --agat $(AGAT)
	bench/keys.sh --agat $(AGAT)
	bench/substitute.sh --agat $(AGAT)

demo: release ## train the demo model and run the offline demo
	demo/run.sh

gifs: release ## re-render the README GIFs (needs vhs)
	demo/run.sh >/dev/null
	vhs demo/demo.tape
	vhs demo/tui.tape
	vhs demo/serve.tape

docker: ## build the container image
	docker build -t agat .

airgap: docker ## prove the air gap: local vs --network none, byte-identical
	demo/run.sh --compare agat

clean: ## remove build artifacts and demo scratch
	cargo clean
	rm -rf demo/.work
