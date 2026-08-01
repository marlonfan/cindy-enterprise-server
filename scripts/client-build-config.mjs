#!/usr/bin/env node

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const configPath = path.join(repoRoot, 'configs', 'client-build.json');

export function loadClientBuildConfig(file = configPath) {
  const config = JSON.parse(fs.readFileSync(file, 'utf8'));
  const requiredStrings = [
    'repository',
    'ref',
    'publicBaseUrl',
    'buildRegion',
    'authRealmRegion',
    'version',
    'androidPackage',
    'iosBundleId',
  ];
  for (const key of requiredStrings) {
    if (typeof config[key] !== 'string' || !config[key].trim()) {
      throw new Error(`${configPath}: ${key} must be a non-empty string`);
    }
  }
  if (!/^[0-9a-f]{40}$/.test(config.ref)) {
    throw new Error(`${configPath}: ref must be a pinned 40-character Git commit SHA`);
  }
  const baseUrl = new URL(config.publicBaseUrl);
  if (baseUrl.protocol !== 'https:' || baseUrl.username || baseUrl.password || baseUrl.search || baseUrl.hash) {
    throw new Error(`${configPath}: publicBaseUrl must be a credential-free HTTPS URL`);
  }
  if (baseUrl.pathname !== '/' && baseUrl.pathname !== '') {
    throw new Error(`${configPath}: publicBaseUrl must not contain a path`);
  }
  if (config.buildRegion !== 'dev') {
    throw new Error(`${configPath}: enterprise builds must use the isolated dev client identity`);
  }
  if (config.authRealmRegion !== 'cn') {
    throw new Error(`${configPath}: dev clients use the cn auth realm`);
  }
  if (!/^\d+\.\d+\.\d+$/.test(config.version)) {
    throw new Error(`${configPath}: version must use x.y.z format`);
  }
  if (!Number.isInteger(config.androidVersionCode) || config.androidVersionCode < 1) {
    throw new Error(`${configPath}: androidVersionCode must be a positive integer`);
  }
  for (const key of ['androidPackage', 'iosBundleId']) {
    if (!/^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z][A-Za-z0-9_]*)+$/.test(config[key])) {
      throw new Error(`${configPath}: ${key} is not a valid reverse-DNS identifier`);
    }
  }
  return Object.freeze({
    ...config,
    publicBaseUrl: config.publicBaseUrl.replace(/\/+$/, ''),
  });
}

function main() {
  const config = loadClientBuildConfig();
  const output = {
    repository: config.repository,
    ref: config.ref,
    version: process.env.CINDY_CLIENT_VERSION?.trim() || config.version,
    android_version_code:
      process.env.CINDY_ANDROID_VERSION_CODE?.trim() || String(config.androidVersionCode),
  };
  if (!/^\d+\.\d+\.\d+$/.test(output.version)) {
    throw new Error('CINDY_CLIENT_VERSION must use x.y.z format');
  }
  if (!/^[1-9]\d*$/.test(output.android_version_code)) {
    throw new Error('CINDY_ANDROID_VERSION_CODE must be a positive integer');
  }
  for (const [key, value] of Object.entries(output)) console.log(`${key}=${value}`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    main();
  } catch (error) {
    console.error(error instanceof Error ? error.message : error);
    process.exit(1);
  }
}
