#!/bin/bash
CARGO_TARGET_DIR=target
cargo build --release
sudo chown root $CARGO_TARGET_DIR/release/tcp-demo
ext=$?
if [[ $ext -ne 0 ]]; then
	exit $ext
fi
$CARGO_TARGET_DIR/release/tcp-demo &
pid=$!
trap 'kill $pid' INT TERM
wait $pid
