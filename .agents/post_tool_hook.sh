#!/usr/bin/env bash
set -uo pipefail

# Read stdin
INPUT_DATA=$(cat)

if [ -z "$INPUT_DATA" ]; then
    exit 0
fi

# Extract metadata using jq
TOOL_NAME=$(echo "$INPUT_DATA" | jq -r '.tool_name // empty')
TARGET_FILE=$(echo "$INPUT_DATA" | jq -r '.tool_input.TargetFile // empty')
CWD=$(echo "$INPUT_DATA" | jq -r '.cwd // empty')

if [ -z "$CWD" ]; then
    CWD=$(pwd)
fi

# Only run for file editing tools
if [[ "$TOOL_NAME" != "replace_file_content" && "$TOOL_NAME" != "multi_replace_file_content" && "$TOOL_NAME" != "write_to_file" ]]; then
    exit 0
fi

if [ -z "$TARGET_FILE" ]; then
    exit 0
fi

# Check if target file is under platform/ or app/
if [[ "$TARGET_FILE" == *"/platform/"* || "$TARGET_FILE" == *"platform/"* || "$TARGET_FILE" == *"/app/"* || "$TARGET_FILE" == *"app/"* ]]; then
    echo -e "\n--- Antigravity Hook: Changed file under platform/ or app/ ($TARGET_FILE) ---"
    
    # Change directory to CWD
    cd "$CWD"
    
    STATUS=0
    
    # 1. Run cargo fmt
    echo "Running: cargo fmt"
    cargo fmt || STATUS=1
    
    # 2. Run cargo clippy
    echo "Running: cargo clippy"
    cargo clippy || STATUS=1
    
    # 3. Run cargo check
    echo "Running: cargo check"
    cargo check || STATUS=1
    
    echo -e "--- Hook completed ---\n"
    exit $STATUS
fi
