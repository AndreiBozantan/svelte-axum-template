#!/usr/bin/env bash
set -uo pipefail

# Read stdin
INPUT_DATA=$(cat)

if [ -z "$INPUT_DATA" ]; then
    exit 0
fi


# Extract metadata using jq
TOOL_NAME=$(echo "$INPUT_DATA" | jq -r '.toolCall.name // empty')
TARGET_FILE=$(echo "$INPUT_DATA" | jq -r '.toolCall.args.TargetFile // empty')
CWD=$(echo "$INPUT_DATA" | jq -r '.workspacePaths[0] // empty')

if [ -z "$CWD" ]; then
    CWD=$(pwd)
fi

# Only run for file editing tools (matches with or without namespaces/prefixes)
if [[ "$TOOL_NAME" != *"replace_file_content"* && "$TOOL_NAME" != *"multi_replace_file_content"* && "$TOOL_NAME" != *"write_to_file"* ]]; then
    exit 0
fi

if [ -z "$TARGET_FILE" ]; then
    exit 0
fi

# Check if target file is under platform/ or app/
if [[ "$TARGET_FILE" == *"/platform/"* || "$TARGET_FILE" == *"platform/"* || "$TARGET_FILE" == *"/app/"* || "$TARGET_FILE" == *"app/"* ]]; then
    # Change directory to CWD
    cd "$CWD"
    
    OUTPUT=""
    STATUS=0
    
    # 1. Run cargo fmt
    FMT_OUT=$(cargo fmt 2>&1) || STATUS=1
    if [ -n "$FMT_OUT" ]; then
        OUTPUT+=$'\n--- cargo fmt ---\n'"$FMT_OUT"
    fi
    
    # 2. Run cargo clippy
    CLIPPY_OUT=$(cargo clippy --all-features 2>&1) || STATUS=1
    if [ -n "$CLIPPY_OUT" ]; then
        OUTPUT+=$'\n--- cargo clippy ---\n'"$CLIPPY_OUT"
    fi
    
    # 3. Run cargo check
    CHECK_OUT=$(cargo check --all-features 2>&1) || STATUS=1
    if [ -n "$CHECK_OUT" ]; then
        OUTPUT+=$'\n--- cargo check ---\n'"$CHECK_OUT"
    fi
    
    # Print empty JSON object to stdout for the agent runner to parse via protojson
    echo "{}"
    exit $STATUS
fi
