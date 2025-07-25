#!/bin/bash

echo "=== Testing Binary Hardening Scanner ==="

echo "Building the project..."
cargo build

if [ $? -ne 0 ]; then
    echo "Build failed!"
    exit 1
fi

echo -e "\n1. Testing system binaries:"
echo "----------------------------------------"
echo "Testing /bin/ls:"
./target/debug/binhards /bin/ls

echo -e "\nTesting /bin/cat:"
./target/debug/binhards /bin/cat

echo -e "\nTesting /bin/bash:"
./target/debug/binhards /bin/bash

echo -e "\n2. Testing with JSON output:"
echo "----------------------------------------"
echo "Testing /bin/ls with JSON:"
./target/debug/binhards --json /bin/ls

echo -e "\n=== Test Complete ==="