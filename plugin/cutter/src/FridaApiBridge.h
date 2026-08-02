// SPDX-FileCopyrightText: 2026 Alok Kumar Mishra <alok16022006@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#pragma once

#include <QString>
#include <QJsonObject>
#include <QList>
#include <QMutex>
#include <functional>
#include "PjHandle.h"

typedef struct rz_frida_session_t RzFridaSession;

class FridaApiBridge {
public:
	FridaApiBridge();
	~FridaApiBridge();

	QJsonObject openSession(const QString &action, const QString &transport,
		const QString &device, const QString &target);
	QJsonObject closeSession();
	QJsonObject resumeSession();
	bool hasSession() const;
	QJsonObject javaAvailable();

	QJsonObject listDevices();
	QJsonObject listProcesses(const QString &transport, const QString &device);
	QJsonObject listApps(const QString &transport, const QString &device);

	QJsonObject ranges(bool refresh = false);
	QJsonObject modules(bool refresh = false);
	QJsonObject threads();
	QJsonObject exports(const QString &moduleName);
	QJsonObject imports(const QString &moduleName);
	QJsonObject symbols(const QString &moduleName);
	QJsonObject memRead(quint64 address, quint64 size);
	QJsonObject memWrite(quint64 address, const QByteArray &hexBytes);

	QJsonObject loaders();
	QJsonObject classes(const QString &prefix = QString());
	QJsonObject describeClass(const QString &className, quint64 loaderId = 0);
	QJsonObject importClass(const QString &className, quint64 loaderId = 0);
	QJsonObject classLoadMonitor(bool enable);
	QJsonObject newlyLoadedClasses();

	QJsonObject eval(const QString &source);
	QJsonObject loadScript(const QString &filePath);
	QJsonObject ping();

	QJsonObject messages();

	QJsonObject bpSet(quint64 address);
	QJsonObject bpList();
	QJsonObject bpRemove(const QString &address);
	QJsonObject bpRemoveAll();

	QJsonObject wpSet(quint64 address, quint64 size, const QString &conditions);
	QJsonObject wpList();
	QJsonObject wpRemove(const QString &address);
	QJsonObject wpRemoveAll();

	QJsonObject continueThread(const QString &threadId = QString());
	QJsonObject regRead(quint64 threadId);
	QJsonObject regWrite(quint64 threadId, const QString &reg, const QString &value);

	QJsonObject rnSet(bool enable);
	QJsonObject rnList();
	QJsonObject rnImport();

	QJsonObject flagImport();

	QJsonObject dexDiff(const QString &prefix = QString());

private:
	QMutex m_mutex;
	RzFridaSession *session() const;
	QJsonObject callBackend(std::function<bool(RzFridaSession *, void *)> fn);
	QJsonObject callBackendNoSession(std::function<bool(void *)> fn);
	QJsonObject callBackendWithCore(std::function<bool(RzFridaSession *, void *, void *)> fn);
	QJsonObject drainAndParseResponse(PjHandle &pj, bool ok, const QString &fallbackError);
	static QJsonObject parseEnvelope(const QString &json);
};
