// SPDX-FileCopyrightText: 2026 Alok Kumar Mishra <alok16022006@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

// scan_secret.js -- find the decoded secret in libnative.so.
// Load with: Frlj docs/examples/hooks/scan_secret.js

var nativeModule = null;
var modules = Process.enumerateModules();
for (var i = 0; i < modules.length; i++) {
  if (modules[i].name === 'libnative.so') {
    nativeModule = modules[i];
    break;
  }
}
if (nativeModule === null) {
  throw new Error('libnative.so is not loaded');
}

var pattern = '72 7a 66 72 69 64 61 7b 66 31 6e 64 5f 74 68 33 5f 73 33 63 72 33 74 7d';
var hits = Memory.scanSync(nativeModule.base, nativeModule.size, pattern);
if (hits.length === 0) {
  throw new Error('the full secret pattern was not found');
}
console.log('full-secret hits: ' + hits.map(function (hit) {
  return hit.address.toString();
}).join(', '));
