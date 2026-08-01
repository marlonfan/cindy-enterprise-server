#!/usr/bin/env node

import fs from 'node:fs';
import path from 'node:path';

const gradleFile = path.resolve(process.argv[2] ?? '');
if (!gradleFile || !fs.existsSync(gradleFile)) {
  console.error('usage: node patch-android-signing.mjs <android/app/build.gradle>');
  process.exit(1);
}

let source = fs.readFileSync(gradleFile, 'utf8');
const signingAnchor = '    signingConfigs {\n        debug {';
if (!source.includes(signingAnchor)) {
  throw new Error(`Android signing anchor changed: ${gradleFile}`);
}
source = source.replace(
  signingAnchor,
  [
    '    signingConfigs {',
    '        enterprise {',
    "            storeFile file(System.getenv('CINDY_ANDROID_KEYSTORE_PATH'))",
    "            storePassword System.getenv('CINDY_ANDROID_KEYSTORE_PASSWORD')",
    "            keyAlias System.getenv('CINDY_ANDROID_KEY_ALIAS')",
    "            keyPassword System.getenv('CINDY_ANDROID_KEY_PASSWORD')",
    '        }',
    '        debug {',
  ].join('\n'),
);

const releasePattern = /(release\s*\{[\s\S]*?)signingConfig signingConfigs\.debug/;
if (!releasePattern.test(source)) {
  throw new Error(`Android release signing anchor changed: ${gradleFile}`);
}
source = source.replace(releasePattern, '$1signingConfig signingConfigs.enterprise');
fs.writeFileSync(gradleFile, source, 'utf8');
console.log(`patched enterprise Android signing: ${gradleFile}`);
