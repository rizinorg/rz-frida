// SPDX-FileCopyrightText: 2026 Alok Kumar Mishra <alok16022006@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

// extract_secret.js -- reveal the secret every time SecretVault is asked for it.
// Load with: fridalj docs/examples/hooks/extract_secret.js

Java.perform(function () {
  var Vault = Java.use('re.frida.minapp.secret.SecretVault');
  Vault.getSecret.implementation = function () {
    var real = this.getSecret();
    console.log('getSecret() -> ' + real);
    return real;
  };
  Vault.checkSecret.implementation = function (input) {
    var real = this.checkSecret(input);
    console.log('checkSecret("' + input + '") -> ' + real);
    return real;
  };
  console.log('SecretVault hooks installed');
});
