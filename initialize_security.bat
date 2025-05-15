@echo off
echo Initializing Authentication System...
echo -----------------------------------

REM Check if Cargo is installed
where cargo >nul 2>nul
if %ERRORLEVEL% neq 0 (
    echo Error: Cargo not found. Please install Rust and Cargo first.
    exit /b 1
)

REM Navigate to back_end directory
cd back_end || (
    echo Error: Could not find back_end directory.
    exit /b 1
)

REM Run initialization
cargo run --bin initialize_security

echo -----------------------------------
echo "Initialization completed!"
echo "You can now start the application with the enhanced security system."
echo "Default admin credentials: admin / admin123"
echo "Be sure to change these in production."
