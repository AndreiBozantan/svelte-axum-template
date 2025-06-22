import fs from 'fs';
import path from 'path';

const targets = [
    '.sqlx',
    'node_modules',
    'target',
    path.join('frontend', 'dist'),
    path.join('frontend', 'node_modules')
];

for (const target of targets) {
    if (fs.existsSync(target)) {
        fs.rmSync(target, { recursive: true, force: true });
        console.log(`Removed: ${target}`);
    }
}