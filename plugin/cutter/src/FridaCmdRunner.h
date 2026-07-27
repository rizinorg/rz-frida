// SPDX-FileCopyrightText: 2026 Alok Kumar Mishra <alok16022006@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef FRIDA_CMD_RUNNER_H
#define FRIDA_CMD_RUNNER_H

#include <QJsonObject>
#include <QString>

#include <functional>

class QWidget;

namespace FridaCmdRunner {

QJsonObject parseEnvelope(const QString &json);

QJsonObject runSync(const QString &cmd);

void runAsyncQuiet(const QString &cmd, QWidget *parent,
	std::function<void(const QJsonObject &)> onOk,
	std::function<void(const QString &)> onErr);

} // namespace FridaCmdRunner

#endif // FRIDA_CMD_RUNNER_H
