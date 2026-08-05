// SPDX-FileCopyrightText: 2026 Alok Kumar Mishra <alok16022006@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "FridaPlugin.h"
#include "FridaDockWidget.h"

#include <MainWindow.h>
#include <QApplication>
#include <QDir>
#include <QMessageLogContext>
#include <QSettings>
#include <QStandardPaths>
#include <QTranslator>

static QtMessageHandler s_prevMsgHandler = nullptr;

static void filterPosixCollationWarnings(QtMsgType type, const QMessageLogContext &ctx, const QString &msg)
{
	if (!msg.contains(QStringLiteral("posix collation implementation"))) {
		s_prevMsgHandler(type, ctx, msg);
	}
}

static QLocale currentCutterLocale()
{
	QSettings s(QSettings::UserScope, QStringLiteral("rizin"), QStringLiteral("cutter"));
	QVariant v = s.value(QStringLiteral("locale"));
	return v.isValid() ? v.toLocale() : QLocale();
}

static QStringList fridaTranslationDirectories()
{
	QStringList dirs;
	for (const QString &base : QStandardPaths::standardLocations(QStandardPaths::AppDataLocation)) {
		dirs << QDir(base + QStringLiteral("/translations")).absolutePath();
	}
	QString appDir = QCoreApplication::applicationDirPath();
	dirs << QDir(appDir + QStringLiteral("/../share/rizin/cutter/translations")).absolutePath();
	dirs << QDir(appDir + QStringLiteral("/../share/cutter/translations")).absolutePath();
	return dirs;
}

// Install the plugin translation, named frida_<locale>.qm like main
// Cutter's cutter_<locale>.qm, searched in Cutter's translation install dir.
// Nothing found keeps <en> interface.
static void installTranslation()
{
	auto *tr = new QTranslator(qApp);
	QLocale locale = currentCutterLocale();
	for (const QString &dir : fridaTranslationDirectories()) {
		if (tr->load(locale, QStringLiteral("frida"), QStringLiteral("_"), dir)) {
			QApplication::installTranslator(tr);
			return;
		}
	}
	tr->deleteLater();
}

void FridaPlugin::setupPlugin()
{
	installTranslation();

	// Cutter's bundled Qt lacks ICU, so its posix collator warns on every
	// locale-aware sort.
	s_prevMsgHandler = qInstallMessageHandler(filterPosixCollationWarnings);
}

void FridaPlugin::setupInterface(MainWindow *main)
{
	dock = new FridaDockWidget(main);
	main->addPluginDockWidget(dock);
}
