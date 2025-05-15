#!/bin/bash

echo "Initializing Authentication System..."
echo "-----------------------------------"

# Check if Cargo is installed
if ! command -v cargo &> /dev/null; then
    echo "Error: Cargo not found. Please install Rust and Cargo first."
    exit 1
fi

# Navigate to back_end directory
cd back_end || {
    echo "Error: Could not find back_end directory."
    exit 1
}

# Run initialization
cargo run --bin initialize_security

echo "-----------------------------------"
echo "Initialization completed!"
echo "You can now start the application with the enhanced security system."
echo "Default admin credentials: admin / admin123"
echo "Be sure to change these in production."
