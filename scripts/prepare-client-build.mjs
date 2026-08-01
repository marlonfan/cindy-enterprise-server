#!/usr/bin/env node

import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';

import { loadClientBuildConfig } from './client-build-config.mjs';

function parseArgs(argv) {
  const result = { clientDir: '', dryRun: false };
  for (let index = 0; index < argv.length; index += 1) {
    const value = argv[index];
    if (value === '--client-dir') result.clientDir = argv[++index] ?? '';
    else if (value === '--dry-run') result.dryRun = true;
    else throw new Error(`unknown argument: ${value}`);
  }
  if (!result.clientDir) throw new Error('--client-dir is required');
  return result;
}

function replaceExactlyOnce(source, pattern, replacement, label) {
  const matches = source.match(pattern);
  if (!matches || matches.length !== 1) {
    throw new Error(`${label}: expected exactly one source anchor, found ${matches?.length ?? 0}`);
  }
  return source.replace(pattern, replacement);
}

function endpointManifest(baseUrl) {
  return {
    schemaVersion: 1,
    authApiBaseUrl: baseUrl,
    authDesktopCallbackUrl: `${baseUrl}/api/auth/desktop/callback`,
    deviceLinkApiBaseUrl: baseUrl,
    oauthBrokerApiBaseUrl: '',
    ossApiBaseUrl: baseUrl,
    heartbeatUrl: baseUrl,
    telegramHookWsUrl: '',
    xHookWsUrl: '',
    slackHookWsUrl: '',
    websiteUrl: baseUrl,
    modelAccessApiBaseUrl: baseUrl,
    voiceApiBaseUrl: '',
    githubApiBaseUrl: '',
    skillhubApiBaseUrl: '',
    pluginApiBaseUrl: '',
    cdnBaseUrl: baseUrl,
    mobileUpdateBaseUrl: '',
    review: '',
  };
}

function regionBuildConfig(config) {
  const emptyRegion = (authRegion) => ({
    authRegion,
    iosBundleId: '',
    iosAppStoreId: '',
    androidPackage: '',
    androidStoreUrl: '',
    npkgExpectBundle: '',
    tapdb: { clientId: '', clientToken: '' },
    oss: { cdnBaseUrl: '', bucket: '', prefix: '', ossRegion: '' },
    iosSigning: { teamId: '', profileName: '', signIdentity: '', profilePath: '' },
    androidSigning: { keyAlias: '', keystorePath: '' },
  });
  return {
    cn: emptyRegion('cn'),
    global: { ...emptyRegion('global'), google: { webClientId: '', iosClientId: '', iosUrlScheme: '' } },
    dev: {
      ...emptyRegion('dev'),
      iosBundleId: config.iosBundleId,
      androidPackage: config.androidPackage,
      npkgExpectBundle: config.androidPackage,
    },
  };
}

function writeJson(file, value) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, `${JSON.stringify(value, null, 2)}\n`, 'utf8');
}

function main() {
  const args = parseArgs(process.argv.slice(2));
  const config = loadClientBuildConfig();
  const clientDir = path.resolve(args.clientDir);
  const packageJsonPath = path.join(clientDir, 'package.json');
  if (!fs.existsSync(packageJsonPath)) throw new Error(`Cindy checkout not found: ${clientDir}`);

  const actualRef = execFileSync('git', ['-C', clientDir, 'rev-parse', 'HEAD'], { encoding: 'utf8' }).trim();
  if (!args.dryRun && config.ref !== 'main' && actualRef !== config.ref) {
    throw new Error(`client checkout mismatch: expected ${config.ref}, got ${actualRef}`);
  }

  const cachePath = path.join(clientDir, 'apps', 'desktop', 'src', 'main', 'endpointManifestCache.ts');
  const cacheSource = fs.readFileSync(cachePath, 'utf8');
  const cacheReplacement = [
    "export const REGION_ENDPOINT_DOMAIN: Readonly<Record<'cn' | 'global', string>> = {",
    `  cn: '${new URL(config.publicBaseUrl).hostname}',`,
    `  global: '${new URL(config.publicBaseUrl).hostname}',`,
    '};',
  ].join('\n');
  const patchedCache = replaceExactlyOnce(
    cacheSource,
    /export const REGION_ENDPOINT_DOMAIN: Readonly<Record<'cn' \| 'global', string>> = \{\r?\n  cn: '[^']+',\r?\n  global: '[^']+',\r?\n\};/g,
    cacheReplacement,
    cachePath,
  );

  const version = process.env.CINDY_CLIENT_VERSION?.trim() || config.version;
  const androidVersionCode = Number(
    process.env.CINDY_ANDROID_VERSION_CODE?.trim() || config.androidVersionCode,
  );
  if (!/^\d+\.\d+\.\d+$/.test(version)) throw new Error('client version must use x.y.z format');
  if (!Number.isInteger(androidVersionCode) || androidVersionCode < 1) {
    throw new Error('Android versionCode must be a positive integer');
  }

  const appJsonPath = path.join(clientDir, 'apps', 'mobile', 'app.json');
  const appJson = JSON.parse(fs.readFileSync(appJsonPath, 'utf8'));
  appJson.expo.version = version;
  appJson.expo.android = { ...appJson.expo.android, versionCode: androidVersionCode };

  if (args.dryRun) {
    console.log(`validated client build injection for ${clientDir}`);
    console.log(`source ref: ${actualRef} (configured: ${config.ref})`);
    console.log(`endpoint: ${config.publicBaseUrl}`);
    console.log(`version: ${version} (${androidVersionCode})`);
    return;
  }

  const manifest = endpointManifest(config.publicBaseUrl);
  for (const name of ['endpoint.json', 'endpoint.global.json', 'endpoint.dev.json']) {
    writeJson(path.join(clientDir, 'config', name), manifest);
  }
  fs.writeFileSync(cachePath, patchedCache, 'utf8');
  writeJson(appJsonPath, appJson);
  writeJson(
    path.join(clientDir, 'apps', 'mobile', 'scripts', 'self-host-regions.json'),
    regionBuildConfig(config),
  );

  console.log(`prepared ${config.repository}@${actualRef} (configured: ${config.ref})`);
  console.log(`endpoint: ${config.publicBaseUrl}`);
  console.log(`desktop identity: ${config.buildRegion}`);
  console.log(`Android package: ${config.androidPackage}`);
  console.log(`version: ${version} (${androidVersionCode})`);
}

try {
  main();
} catch (error) {
  console.error(error instanceof Error ? error.message : error);
  process.exit(1);
}
