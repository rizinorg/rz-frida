// SPDX-FileCopyrightText: 2026 Alok Kumar Mishra <alok16022006@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

// break_native_check.js -- make the native license check always pass.
// Load with: fridalj docs/examples/hooks/break_native_check.js

Java.perform(function () {
  var Vault = Java.use('re.frida.minapp.secret.SecretVault');
  Vault.nativeCheckSecret.implementation = function (input) {
    console.log('nativeCheckSecret bypassed, input was "' + input + '"');
    return true;
  };
  console.log('native check bypassed');
});
