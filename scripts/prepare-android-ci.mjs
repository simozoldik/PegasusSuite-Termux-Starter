#!/usr/bin/env node
/* Prepare a freshly generated Capacitor Android project using recovered native files. */
import fs from 'node:fs';
import path from 'node:path';

const root = process.cwd();
const android = path.join(root, 'android');
const nativeRoot = path.join(root, 'native-plugins');
const javaOut = path.join(android, 'app/src/main/java/com/pegasus/suite');
const resOut = path.join(android, 'app/src/main/res/xml');

const required = [
  path.join(android, 'app/src/main/AndroidManifest.xml'),
  path.join(android, 'app/build.gradle'),
  path.join(nativeRoot, 'java/MainActivity.java'),
  path.join(nativeRoot, 'java/CellTowerPlugin.java'),
  path.join(nativeRoot, 'java/PhoneScannerPlugin.java'),
  path.join(nativeRoot, 'java/WiFiCrackerPlugin.java'),
  path.join(nativeRoot, 'res/xml/network_security_config.xml'),
];
for (const file of required) {
  if (!fs.existsSync(file)) throw new Error(`Required file missing: ${path.relative(root, file)}`);
}
fs.mkdirSync(javaOut, { recursive: true });
fs.mkdirSync(resOut, { recursive: true });
for (const f of ['MainActivity.java', 'CellTowerPlugin.java', 'PhoneScannerPlugin.java', 'WiFiCrackerPlugin.java']) {
  fs.copyFileSync(path.join(nativeRoot, 'java', f), path.join(javaOut, f));
}
fs.copyFileSync(path.join(nativeRoot, 'res/xml/network_security_config.xml'), path.join(resOut, 'network_security_config.xml'));

const manifestPath = path.join(android, 'app/src/main/AndroidManifest.xml');
let manifest = fs.readFileSync(manifestPath, 'utf8');
const permissions = [
  '<uses-permission android:name="android.permission.INTERNET" />',
  '<uses-permission android:name="android.permission.ACCESS_NETWORK_STATE" />',
  '<uses-permission android:name="android.permission.ACCESS_COARSE_LOCATION" />',
  '<uses-permission android:name="android.permission.ACCESS_FINE_LOCATION" />',
  '<uses-permission android:name="android.permission.ACCESS_WIFI_STATE" />',
  '<uses-permission android:name="android.permission.CHANGE_WIFI_STATE" />',
  '<uses-permission android:name="android.permission.NEARBY_WIFI_DEVICES" android:usesPermissionFlags="neverForLocation" />',
];
const missing = permissions.filter(line => !manifest.includes(line.match(/android:name="([^"]+)/)[1]));
if (missing.length) {
  const appAt = manifest.search(/\s*<application\b/);
  if (appAt < 0) throw new Error('Could not find <application> in AndroidManifest.xml');
  manifest = manifest.slice(0, appAt) + '\n    ' + missing.join('\n    ') + '\n\n' + manifest.slice(appAt);
}
if (!manifest.includes('android:usesCleartextTraffic=')) {
  manifest = manifest.replace(/<application\b/, '<application android:usesCleartextTraffic="true"');
}
if (!manifest.includes('android:networkSecurityConfig=')) {
  manifest = manifest.replace(/<application\b/, '<application android:networkSecurityConfig="@xml/network_security_config"');
}
if (!manifest.includes('android.hardware.telephony')) {
  manifest = manifest.replace(/\s*<application\b/, '\n    <uses-feature android:name="android.hardware.telephony" android:required="false" />\n    <uses-feature android:name="android.hardware.wifi" android:required="false" />\n\n    <application');
}
fs.writeFileSync(manifestPath, manifest);

const gradlePath = path.join(android, 'app/build.gradle');
let gradle = fs.readFileSync(gradlePath, 'utf8');
if (/versionCode\s+1\b/.test(gradle)) {
  gradle = gradle.replace(/versionCode\s+1\b/, "versionCode (System.getenv('PEGASUS_VERSION_CODE') ?: '1').toInteger()");
} else if (!/PEGASUS_VERSION_CODE/.test(gradle)) {
  throw new Error('Could not safely patch versionCode in generated app/build.gradle');
}
gradle = gradle.replace(/versionName\s+["']1\.0\.0["']/, 'versionName "1.0.${System.getenv(\'PEGASUS_VERSION_CODE\') ?: \'1\'}"');
fs.writeFileSync(gradlePath, gradle);

console.log('Prepared Android project with recovered Pegasus native plugins, permissions, network policy, and CI versioning.');
