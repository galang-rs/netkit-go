const fs = require('fs');
const path = require('path');
const readline = require('readline');

// The first argument is the script to run
const scriptPath = process.argv[2];
if (!scriptPath) {
    process.stderr.write('NK_NODE_ERROR:No script path provided\n');
    process.exit(1);
}

// Load the target script
const absolutePath = path.isAbsolute(scriptPath) ? scriptPath : path.resolve(process.cwd(), scriptPath);

if (!fs.existsSync(absolutePath)) {
    process.stderr.write(`NK_NODE_ERROR:Script not found at ${absolutePath}\n`);
    process.exit(1);
}

let exportsObj;
try {
    exportsObj = require(absolutePath);
} catch (err) {
    process.stderr.write(`NK_NODE_ERROR:${err.message}\n`);
    process.exit(1);
}

// Extract export metadata
const meta = {};
if (typeof exportsObj === 'object' && exportsObj !== null) {
    for (const key in exportsObj) {
        meta[key] = {
            type: typeof exportsObj[key],
            value: typeof exportsObj[key] !== 'function' ? exportsObj[key] : undefined
        };
    }
} else {
    meta['__default__'] = {
        type: typeof exportsObj,
        value: typeof exportsObj !== 'function' ? exportsObj : undefined
    };
}

// Send metadata to Go
process.stdout.write(`NK_NODE_READY:${JSON.stringify(meta)}\n`);

// Setup IPC for calling functions
const rl = readline.createInterface({
    input: process.stdin,
    terminal: false
});

rl.on('line', async (line) => {
    try {
        const call = JSON.parse(line);
        const { id, method, args } = call;

        let func = exportsObj;
        if (method !== '__default__') {
            func = exportsObj[method];
        }

        if (typeof func === 'function') {
            try {
                const result = await func(...args);
                process.stdout.write(`NK_NODE_RES:${JSON.stringify({ id, result })}\n`);
            } catch (err) {
                process.stdout.write(`NK_NODE_RES:${JSON.stringify({ id, error: err.message })}\n`);
            }
        } else {
            // Not a function, just return the value (though usually it's static in meta)
            process.stdout.write(`NK_NODE_RES:${JSON.stringify({ id, result: func })}\n`);
        }
    } catch (err) {
        // Ignore parsing errors for now
    }
});
