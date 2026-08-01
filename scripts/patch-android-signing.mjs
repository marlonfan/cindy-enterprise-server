#!/usr/bin/env node

import fs from 'node:fs';
import path from 'node:path';

const gradleArgument = process.argv[2] ?? '';
const gradlePropertiesArgument = process.argv[3] ?? '';
const gradleFile = path.resolve(gradleArgument);
const gradlePropertiesFile = path.resolve(gradlePropertiesArgument);
if (
  !gradleArgument ||
  !fs.existsSync(gradleFile) ||
  !gradlePropertiesArgument ||
  !fs.existsSync(gradlePropertiesFile)
) {
  console.error('usage: node patch-android-signing.mjs <android/app/build.gradle> <android/gradle.properties>');
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

let properties = fs.readFileSync(gradlePropertiesFile, 'utf8');
const jvmArgsPattern = /^org\.gradle\.jvmargs=.*$/m;
const jvmArgs = properties.match(jvmArgsPattern);
if (!jvmArgs) {
  throw new Error(`Android Gradle JVM args anchor changed: ${gradlePropertiesFile}`);
}
let memoryArgs = jvmArgs[0];
memoryArgs = /-Xmx\d+[kmgKMG]/.test(memoryArgs)
  ? memoryArgs.replace(/-Xmx\d+[kmgKMG]/, '-Xmx4096m')
  : `${memoryArgs} -Xmx4096m`;
memoryArgs = /-XX:MaxMetaspaceSize=\d+[kmgKMG]/.test(memoryArgs)
  ? memoryArgs.replace(/-XX:MaxMetaspaceSize=\d+[kmgKMG]/, '-XX:MaxMetaspaceSize=2048m')
  : `${memoryArgs} -XX:MaxMetaspaceSize=2048m`;
properties = properties.replace(jvmArgsPattern, memoryArgs);
fs.writeFileSync(gradlePropertiesFile, properties, 'utf8');
console.log(`patched Android Gradle memory: ${gradlePropertiesFile}`);
