// SPDX-FileCopyrightText: 2026 Alok Kumar Mishra <alok16022006@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "FridaCmdRunner.h"

#include "common/RizinTask.h"
#include "core/Cutter.h"

#include <QJsonDocument>
#include <QPointer>

#include <memory>

QJsonObject FridaCmdRunner::parseEnvelope(const QString &json)
{
	if (json.isEmpty()) {
		throw QString(QObject::tr("empty response — rz-frida plugin may not be loaded"));
	}
	QJsonDocument doc = QJsonDocument::fromJson(json.toUtf8());
	if (doc.isNull() || !doc.isObject()) {
		if (json.contains("does not exist") || json.contains("unknown command")) {
			throw QString(QObject::tr(
				"rz-frida rizin plugin not loaded — install rz-frida or run Cutter on Linux/WSL"));
		}
		throw QString(QObject::tr("invalid JSON response: %1").arg(json.left(200)));
	}
	QJsonObject obj = doc.object();
	if (!obj["ok"].toBool()) {
		QJsonObject err = obj["error"].toObject();
		throw err["message"].toString();
	}
	return obj["result"].toObject();
}

QJsonObject FridaCmdRunner::runSync(const QString &cmd)
{
	return parseEnvelope(Core()->cmdRaw(cmd).trimmed());
}

void FridaCmdRunner::runAsyncQuiet(const QString &cmd, QWidget *parent,
	std::function<void(const QJsonObject &)> onOk,
	std::function<void(const QString &)> onErr)
{
	auto task = std::make_shared<RizinCmdTask>(cmd);
	QPointer<QWidget> guard(parent);

	QObject::connect(task.get(), &RizinTask::finished, parent, [task, guard, onOk, onErr]() {
		if (!guard) {
			return;
		}
		try {
			onOk(parseEnvelope(task->getResult().trimmed()));
		} catch (const QString &e) {
			onErr(e);
		} catch (...) {
			onErr(QObject::tr("Command failed."));
		}
	});

	task->startTask();
}
