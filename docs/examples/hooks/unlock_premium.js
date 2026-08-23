// SPDX-FileCopyrightText: 2026 Alok Kumar Mishra <alok16022006@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

// unlock_premium.js -- flip the premium flag without paying.
// Load with: fridalj docs/examples/hooks/unlock_premium.js

Java.perform(function () {
  var GameState = Java.use('re.frida.minapp.game.GameState');
  GameState.premium.value = true;
  console.log('premium is now ' + GameState.premium.value);

  // the app caches its status line, so refresh it on the UI thread after
  // changing the field from instrumentation.
  Java.scheduleOnMainThread(function () {
    Java.choose('re.frida.minapp.MainActivity', {
      onMatch: function (activity) {
        activity.refreshStatus();
      },
      onComplete: function () {
        console.log('premium status refreshed');
      }
    });
  });
});
