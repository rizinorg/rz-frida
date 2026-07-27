// SPDX-FileCopyrightText: 2026 Alok Kumar Mishra <alok16022006@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef FRIDA_DESCRIPTIONS_H
#define FRIDA_DESCRIPTIONS_H

#include <QMetaType>
#include <QString>

struct FridaDevice
{
	QString name;
	QString id;
	QString type;
};

struct FridaProcess
{
	int pid;
	QString name;
	QString path;
};

struct FridaApp
{
	QString name;
	QString identifier;
	int pid;
};

Q_DECLARE_METATYPE(FridaDevice)
Q_DECLARE_METATYPE(FridaProcess)
Q_DECLARE_METATYPE(FridaApp)

#endif // FRIDA_DESCRIPTIONS_H
