// SPDX-FileCopyrightText: 2026 Alok Kumar Mishra <alok16022006@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "FridaPlugin.h"
#include "FridaDockWidget.h"

#include <MainWindow.h>

void FridaPlugin::setupPlugin() {}

void FridaPlugin::setupInterface(MainWindow *main)
{
	dock = new FridaDockWidget(main);
	main->addPluginDockWidget(dock);
}
