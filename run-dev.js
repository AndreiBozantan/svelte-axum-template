// A script to orchestrate the startup of both backend and frontend servers
// and open the browser only when both are ready
import { spawn } from 'child_process';
import { createServer } from 'net';
import http from 'http';

// TODO: move the exec parts to package.json scripts;
// start frontend with `npm run dev` instead of `npm run build`,
// to avoid the embedding of the frontend assets in the backend binary,
// which is not needed for development, with 2 separate processes for frontend and backend.
// This allows for hot reloading of the frontend during development, without an expensive backend rebuild.
// keep just the waitForService and openBrowser functions here

async function main() {
    const frontEndConfig = {
        name: "Frontend",
        cwd: "front_end",
        command: "npm",
        args: ["run", "dev"],
        port: 5173, // adjust if your frontend uses a different port
        timeoutMs: 10000, // timeout for frontend startup
        readyPattern: /localhost:/, // adjust based on your frontend's startup message
        colorCode: "\x1b[35m" // purple color for frontend
    };

    const backEndConfig = {
        name: "Backend",
        cwd: "back_end",
        command: "cargo",
        args: ["watch", "--ignore", "./db.sqlite", "--watch", "./src", "--exec", "run"],
        port: 3000, // adjust if your backend uses a different port
        timeoutMs: 90000, // timeout for frontend startup
        readyPattern: /listening on/, // adjust based on your backend's startup message
        colorCode: "\x1b[34m" // blue color for backend
    };

    let backendProcess;
    let frontendProcess;
    let keepAliveInterval;

    let clean = (fn) => {
        try { fn(); }
        catch (err) { console.error(`Error during cleanup: ${err.message}`); }
    };

    process.on('exit', () => {
        console.log('🛑 Cleaning up processes...');
        clean(() => { if (backendProcess) backendProcess.kill(); });
        clean(() => { if (frontendProcess) frontendProcess.kill(); });
        clean(() => { if (keepAliveInterval) clearInterval(keepAliveInterval); });
    });
    process.on('SIGINT', () => {
        console.log('\n❌ Shutting down...');
        process.exit(0);
    });

    console.log('🚀 Starting Application...');
    try {
        keepAliveInterval = setInterval(() => { }, 1000); // this will keep the node.js event loop active
        backendProcess = await startService(backEndConfig);
        frontendProcess = await startService(frontEndConfig);
        openBrowser(`http://localhost:${frontEndConfig.port}`);
        console.log('\x1b[32m✅ Application started successfully!\x1b[0m');
        console.log('Press Ctrl+C to stop all processes and exit');
    } catch (error) {
        console.error('\x1b[31m❌ Error starting application:\x1b[0m', error);
        process.exit(1);
    }
}

async function isPortInUse(port) {
    return new Promise((resolve) => {
        const server = createServer();
        server.on('error', (err) => {
            if (err.code === 'EADDRINUSE') { // Port is in use
                resolve(true);
            } else { // Some other error occurred
                console.error(`Error checking port ${port}:`, err);
                resolve(false);
            }
        });
        server.on('listening', () => {
            server.close(); // Close the server and report port as free
            resolve(false);
        });
        // Try to listen on the port
        server.listen(port, '127.0.0.1');
    });
}

async function waitForService(port, serviceName, maxAttempts = 30, intervalMs = 1000) {
    for (let attempt = 1; attempt <= maxAttempts; attempt++) {
        try {
            await new Promise((resolve, reject) => {
                const req = http.get(`http://localhost:${port}`, { timeout: 2000 }, (res) => {
                    res.resume();
                    resolve();
                });
                req.on('error', reject);
            });
            console.log(`\x1b[32m✓ ${serviceName} is responding on port ${port}\x1b[0m`);
            return;
        } catch (error) {
            console.log(`\x1b[33m⚠️ Attempt ${attempt}/${maxAttempts}: ${serviceName} not ready (${error.message})\x1b[0m`);
            if (attempt === maxAttempts) {
                throw new Error(`Timed out waiting for ${serviceName} after ${maxAttempts} attempts`);
            }
            await new Promise(resolve => setTimeout(resolve, intervalMs));
        }
    }
}

async function startService(config) {
    console.log(`${config.colorCode}📦 Starting ${config.name}... \x1b[0m`);
    const portOpened = await isPortInUse(config.port);
    if (portOpened) {
        console.log(`\x1b[33m⚠️ Warning: Port ${config.port} is already in use. Skip starting ${config.name}, as it might already be running.\x1b[0m`);
        return null; // Skip starting the service if the port is already in use
    }

    const process = spawn(config.command, config.args, { cwd: config.cwd, shell: true, stdio: 'pipe' });

    return new Promise((resolve, reject) => {
        process.stdout.on('data', (data) => {
            const output = data.toString();
            process.stdout.write(`${config.colorCode}[${config.name}]\x1b[0m ${output}`);
            if (config.readyPattern.test(output)) {
                console.log(`\x1b[32m✓ ${config.name} started successfully\x1b[0m`);
                waitForService(config.port, config.name) // wait for the service to be fully ready
                    .then(() => {
                        console.log(`\x1b[32m✓ ${config.name} is ready at http://localhost:${config.port}\x1b[0m`);
                        resolve(process);
                    })
                    .catch((err) => {
                        console.error(`\x1b[31m✗ ${config.name} failed to become ready:\x1b[0m`, err);
                        reject(err);
                    });
            }
        });

        process.stderr.on('data', (data) => {
            const output = data.toString();
            process.stderr.write(`${config.colorCode}[${config.name}]\x1b[0m ${output}`);
        });

        process.on('error', (err) => {
            console.error(`\x1b[31m✗ Failed to start ${config.name}:\x1b[0m`, err);
            reject(err);
        });

        process.on('close', (code) => {
            if (code !== 0) {
                console.error(`\x1b[31m✗ ${config.name} process exited with code ${code}\x1b[0m`);
                reject(new Error(`${config.name} exited with code ${code}`));
            }
        });

        setTimeout(() => {
            reject(new Error(`${config.name} startup timed out after ${config.timeoutMs / 1000} seconds`));
        }, config.timeoutMs);
    });
}

function openBrowser(url) {
    console.log(`🌐 Opening browser at ${url}...`);
    let commandMap = {
        darwin: ['open', url], // macOS
        win32: ['start', '', url], // Windows (empty string for start command)
        linux: ['xdg-open', url] // Linux
    };
    const platformCommands = commandMap[process.platform];
    if (!platformCommands) {
        console.log(`\x1b[33m⚠️ Cannot open browser: unsupported platform ${process.platform}\x1b[0m`);
        return;
    }
    const [command, ...args] = platformCommands;
    const browserProcess = spawn(command, args, { detached: true, stdio: 'ignore' });
    browserProcess.unref(); // Unreference the process so it doesn't keep the Node.js process alive
    console.log(`\x1b[32m✓ Browser opened at ${url}\x1b[0m`);
}

main();
