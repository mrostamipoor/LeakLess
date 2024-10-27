LOG_LEVEL ?= trace

.PHONY: setup
setup:
	sudo apt-get update
	sudo apt-get install -y libssl-dev pkg-config build-essential git curl

.PHONY: install-rust
install-rust:
	@echo "Installing Rustup and configuring Rust 1.70.0..."
	curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
	export PATH="$$HOME/.cargo/bin:$$PATH"
	rustup install 1.70.0
	rustup default 1.70.0
	rustup target add wasm32-wasi
	rustup target add wasm32-unknown-unknown
	@echo "Rust 1.70.0 and targets installed and set as default."

.PHONY: build
build: setup install-rust
	export X86_64_UNKNOWN_LINUX_GNU_OPENSSL_LIB_DIR=/usr/lib/ssl; \
	export X86_64_UNKNOWN_LINUX_GNU_OPENSSL_INCLUDE_DIR=/usr/include/openssl; \
	cargo build --release

