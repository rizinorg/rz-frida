// SPDX-FileCopyrightText: 2026 Alok Kumar Mishra <alok16022006@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "FridaPlugin.h"
#include "FridaDockWidget.h"

#include <MainWindow.h>
#include <QMessageLogContext>

static QtMessageHandler s_prevMsgHandler = nullptr;

static void filterPosixCollationWarnings(QtMsgType type, const QMessageLogContext &ctx, const QString &msg)
{
	if (!msg.contains(QStringLiteral("posix collation implementation"))) {
		s_prevMsgHandler(type, ctx, msg);
	}
}

void FridaPlugin::setupPlugin()
{
	// Cutter's bundled Qt lacks ICU, so its posix collator warns on every
	// locale-aware sort.
	s_prevMsgHandler = qInstallMessageHandler(filterPosixCollationWarnings);
}

void FridaPlugin::setupInterface(MainWindow *main)
{
	dock = new FridaDockWidget(main);
	main->addPluginDockWidget(dock);
}
