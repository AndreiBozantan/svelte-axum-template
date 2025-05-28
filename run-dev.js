// A script to orchestrate the startup of both backend and frontend servers
// and open the browser only when both are ready
import { spawn } from 'child_process';
import { createServer } from 'net';
import http from 'http';

// Frontend Configuration
const frontEndDir = "front_end";
const frontEndCommandAndArgs = ['npm', 'run', 'dev']; // Command to start the frontend
const frontendPort = 5173; // Default Vite dev server port
const frontendReadyPattern = /localhost:/; // Pattern indicating Vite server is ready

// Backend Configuration
const backendDir = "back_end";
const backendCommandAndArgs = ['cargo', 'watch', '--ignore', './db.sqlite', '--watch', './src', '--exec', 'run']; // Command to start the backend
const backendPort = 3000; // Adjust if your backend uses a different port
const backendReadyPattern = /listening on/; // Adjust based on your backend's startup message

// Function to check if a port is already in use by trying to bind to it
async function isPortInUse(port) {
    return new Promise((resolve) => {
        const server = createServer();

        // Set up error handler (port in use)
        server.on('error', (err) => {
            if (err.code === 'EADDRINUSE') {
                // Port is in use
                resolve(true);
            } else {
                // Some other error occurred
                console.error(`Error checking port ${port}:`, err);
                resolve(false);
            }
        });

        // Set up listening handler (port is free)
        server.on('listening', () => {
            // Close the server and report port as free
            server.close();
            // sleep for a bit to ensure the port is free
            setTimeout(() => { resolve(false); }, 100);
        });

        // Try to listen on the port
        server.listen(port, '127.0.0.1');
    });
}

// Function to check if a service is accessible by attempting to connect to it
function waitForService(port, serviceName, maxAttempts = 30, intervalMs = 1000) {
    function tryHttpRequest(port, serviceName, currentAttempts, maxAttempts, intervalMs, resolve, reject) {
        const req = http.get(`http://localhost:${port}`, (res) => {
            // Any response, even a redirect or error, means the server is up
            console.log(`\x1b[32m✓ ${serviceName} responded with HTTP status ${res.statusCode}\x1b[0m`);
            res.resume(); // Consume response data to free up memory
            resolve();
        });

        req.on('error', (err) => {
            console.log(`\x1b[33m⚠️ HTTP request to ${serviceName} on port ${port} failed: ${err.message}\x1b[0m`);

            if (currentAttempts >= maxAttempts) {
                reject(new Error(`Timed out waiting for ${serviceName} on port ${port} after ${currentAttempts} attempts`));
            } else {
                setTimeout(() => {
                    tryHttpRequest(port, serviceName, currentAttempts + 1, maxAttempts, intervalMs, resolve, reject);
                }, intervalMs);
            }
        });

        req.setTimeout(2000, () => {
            req.destroy();
            console.log(`\x1b[33m⚠️ HTTP request to ${serviceName} on port ${port} timed out\x1b[0m`);

            if (currentAttempts >= maxAttempts) {
                reject(new Error(`Timed out waiting for ${serviceName} on port ${port} after ${currentAttempts} attempts`));
            } else {
                setTimeout(() => {
                    tryHttpRequest(port, serviceName, currentAttempts + 1, maxAttempts, intervalMs, resolve, reject);
                }, intervalMs);
            }
        });
    }

    return new Promise((resolve, reject) => {
        tryHttpRequest(port, serviceName, 0, maxAttempts, intervalMs, resolve, reject);
    });
}

// Start the backend process
function startBackend() {
    console.log('📦 Starting Rust backend...');

    const backend = spawn(backendCommandAndArgs[0], backendCommandAndArgs.slice(1), {
        cwd: backendDir,
        shell: true,
        stdio: 'pipe'
    });

    return new Promise((resolve, reject) => {
        // Handle backend output
        backend.stdout.on('data', (data) => {
            const output = data.toString();
            process.stdout.write(`\x1b[34m[Backend]\x1b[0m ${output}`);

            // Check if the backend has started successfully
            if (backendReadyPattern.test(output)) {
                console.log('\x1b[32m✓ Backend started successfully\x1b[0m');
                resolve(backend);
            }
        });

        backend.stderr.on('data', (data) => {
            const output = data.toString();
            process.stderr.write(`\x1b[34m[Backend]\x1b[0m ${output}`);
        });

        backend.on('error', (err) => {
            console.error('\x1b[31m✗ Failed to start backend:\x1b[0m', err);
            reject(err);
        });

        backend.on('close', (code) => {
            if (code !== 0) {
                console.error(`\x1b[31m✗ Backend process exited with code ${code}\x1b[0m`);
                reject(new Error(`Backend exited with code ${code}`));
            }
        });

        // Set a reasonable timeout for backend startup
        setTimeout(() => {
            reject(new Error('Backend startup timed out after 60 seconds'));
        }, 60000);
    });
}

// Start the frontend process
function startFrontend() {
    console.log('🌐 Starting Svelte frontend...');

    const frontend = spawn(frontEndCommandAndArgs[0], frontEndCommandAndArgs.slice(1), {
        cwd: frontEndDir,
        shell: true,
        stdio: 'pipe'
    });

    return new Promise((resolve, reject) => {
        // Handle frontend output
        frontend.stdout.on('data', (data) => {
            const output = data.toString();
            process.stdout.write(`\x1b[35m[Frontend]\x1b[0m ${output}`);

            // Check if the frontend has started successfully
            if (frontendReadyPattern.test(output)) {
                console.log('\x1b[32m✓ Frontend started successfully\x1b[0m');
                resolve(frontend);
            }
        });

        frontend.stderr.on('data', (data) => {
            const output = data.toString();
            process.stderr.write(`\x1b[35m[Frontend]\x1b[0m ${output}`);
        });

        frontend.on('error', (err) => {
            console.error('\x1b[31m✗ Failed to start frontend:\x1b[0m', err);
            reject(err);
        });

        frontend.on('close', (code) => {
            if (code !== 0) {
                console.error(`\x1b[31m✗ Frontend process exited with code ${code}\x1b[0m`);
                reject(new Error(`Frontend exited with code ${code}`));
            }
        });

        // Set a reasonable timeout for frontend startup
        setTimeout(() => {
            reject(new Error('Frontend startup timed out after 30 seconds'));
        }, 30000);
    });
}

// Function to open the browser
function openBrowser() {
    console.log('🌐 Opening browser...');
    const url = `http://localhost:${frontendPort}`;
    let commandsAndArgsMap = {
        darwin: ['open', url], // macOS
        win32: ['start', '', url], // Windows (empty string for start command)
        linux: ['xdg-open', url] // Linux
    };
    let command = commandsAndArgsMap[process.platform][0];
    let args = commandsAndArgsMap[process.platform].slice(1);
    // const browserProcess = spawn(command, args, { detached: true, stdio: 'ignore' });
    // browserProcess.unref(); // Unreference the process so it doesn't keep the Node.js process alive
    console.log(`\x1b[32m✓ Browser opened at ${url}\x1b[0m`);
}

// Main function to orchestrate everything
async function main() {
    let backendProcess;
    let frontendProcess;

    try {
        // Start the backend and frontend processes
        console.log('🚀 Starting Application...');

        const backendInUse = await isPortInUse(backendPort);
        if (backendInUse) {
            console.log(`\x1b[33m⚠️ Warning: Port ${backendPort} is already in use. Backend might already be running.\x1b[0m`);
        } else {
            backendProcess = await startBackend();
            console.log('⏳ Waiting for backend to be fully ready...');
        }
        await waitForService(backendPort, 'Backend');
        console.log(`\x1b[32m✓ Backend is ready, at http://localhost:${backendPort}\x1b[0m`);

        const frontendInUse = await isPortInUse(frontendPort);
        if (frontendInUse) {
            console.log(`\x1b[33m⚠️ Warning: Port ${frontendPort} is already in use. Frontend might already be running.\x1b[0m`);
        } else {
            frontendProcess = await startFrontend();
            console.log('⏳ Waiting for frontend to be fully ready...');
        }
        await waitForService(frontendPort, 'Frontend');

        console.log('🌐 Both backend and frontend are ready!')
        openBrowser();

        // Handle process termination
        process.on('SIGINT', () => {
            console.log('\n🛑 Shutting down...');
            if (backendProcess) backendProcess.kill();
            if (frontendProcess) frontendProcess.kill();
            process.exit(0);
        });

        console.log('\x1b[32m✅ Application started successfully!\x1b[0m');
        console.log('Press Ctrl+C to stop all processes and exit');

    } catch (error) {
        console.error('\x1b[31m❌ Error starting application:\x1b[0m', error);
        process.exit(1);
    } finally {
        // Ensure processes are killed on exit
        if (backendProcess) backendProcess.kill();
        if (frontendProcess) frontendProcess.kill();
    }
}

// Run the main function
main();
