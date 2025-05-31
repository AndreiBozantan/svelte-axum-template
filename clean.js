import fs from 'fs';
import path from 'path';

const targets = [
    '.sqlx',
    'node_modules',
    'target',
    path.join('front_end', 'dist'),
    path.join('front_end', 'node_modules')
];

for (const target of targets) {
    if (fs.existsSync(target)) {
        fs.rmSync(target, { recursive: true, force: true });
        console.log(`Removed: ${target}`);
    }
}