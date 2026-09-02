#!/bin/bash
CARGO=/var/home/yuri/.rustup/toolchains/stable-x86_64-unknown-linux-gnu/bin/cargo
export PATH="/var/home/yuri/.rustup/toolchains/stable-x86_64-unknown-linux-gnu/bin:$PATH"

$CARGO fmt --check >> proof_output_final.txt 2>&1
$CARGO build -p warden-core -p warden-app >> proof_output_final.txt 2>&1
$CARGO test -p warden-core >> proof_output_final.txt 2>&1
$CARGO run -p warden-app --quiet -- self-test >> proof_output_final.txt 2>&1
