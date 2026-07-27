// SPDX-FileCopyrightText: 2026 Alok Kumar Mishra <alok16022006@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef FRIDA_PLUGIN_H
#define FRIDA_PLUGIN_H

#include <CutterPlugin.h>

class FridaDockWidget;

class FridaPlugin : public QObject, CutterPlugin
{
    Q_OBJECT
    Q_PLUGIN_METADATA(IID "re.rizin.cutter.plugins.CutterPlugin")
    Q_INTERFACES(CutterPlugin)

public:
    void setupPlugin() override;
    void setupInterface(MainWindow *main) override;

    QString getName() const override { return "Frida Plugin"; }
    QString getAuthor() const override { return "Alok Kumar Mishra"; }
    QString getDescription() const override { return "Frida integration frontend for Cutter."; }
    QString getVersion() const override { return "0.1.0"; }

private:
    FridaDockWidget *dock;
};

#endif

