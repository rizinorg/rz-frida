// SPDX-FileCopyrightText: 2026 Alok Kumar Mishra <alok16022006@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

// watch_coins.js -- log every coin credit as the app applies it.
// Load with: fridalj docs/examples/hooks/watch_coins.js

Java.perform(function () {
  var GameState = Java.use('re.frida.minapp.game.GameState');
  GameState.addCoins.implementation = function (n) {
    var before = GameState.coins.value;
    this.addCoins(n);
    console.log('addCoins(' + n + ') coins ' + before + ' -> ' + GameState.coins.value);
    Java.scheduleOnMainThread(function () {
      Java.choose('re.frida.minapp.MainActivity', {
        onMatch: function (activity) {
          activity.refreshStatus();
        },
        onComplete: function () {}
      });
    });
  };
  console.log('coins monitor installed');
});
