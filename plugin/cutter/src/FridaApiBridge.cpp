// SPDX-FileCopyrightText: 2026 Alok Kumar Mishra <alok16022006@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "FridaApiBridge.h"

#include "core/Cutter.h"

#include <rz_frida.h>
#include <rz_core.h>
#include <rz_util.h>

#include <QCoreApplication>
#include <QJsonDocument>
#include <QFile>

FridaApiBridge::FridaApiBridge() = default;
FridaApiBridge::~FridaApiBridge() = default;

static QString envelopeError(const QString &json, const QString &fallback)
{
	QJsonDocument doc = QJsonDocument::fromJson(json.toUtf8());
	if (!doc.isNull() && doc.isObject()) {
		QJsonObject obj = doc.object();
		if (!obj["ok"].toBool()) {
			QJsonObject err = obj["error"].toObject();
			QString message = err["message"].toString();
			if (!message.isEmpty()) {
				return message;
			}
		}
	}
	return fallback;
}

RzFridaSession *FridaApiBridge::session() const
{
	RzCoreLocked coreLocked = Core()->lock();
	RzCore *core = (RzCore *)coreLocked.operator->();
	RzFridaSession *s = rz_frida_session_from_core(core);
	if (!s) {
		throw QCoreApplication::translate("FridaApiBridge", "No active Frida session");
	}
	return s;
}

bool FridaApiBridge::hasSession() const
{
	RzCoreLocked coreLocked = Core()->lock();
	RzCore *core = (RzCore *)coreLocked.operator->();
	return rz_frida_session_from_core(core) != nullptr;
}

QJsonObject FridaApiBridge::callBackend(std::function<bool(RzFridaSession *, void *)> fn)
{
	QMutexLocker lock(&m_mutex);
	RzFridaSession *s = session();
	PJ *pj = pj_new();
	if (!pj) {
		throw QCoreApplication::translate("FridaApiBridge", "JSON allocation failed");
	}
	bool ok = fn(s, pj);
	char *json = pj_drain(pj);
	QString jsonStr = QString::fromUtf8(json ? json : "");
	free(json);
	if (!ok) {
		throw envelopeError(jsonStr, QCoreApplication::translate("FridaApiBridge", "Frida backend call failed"));
	}
	return parseEnvelope(jsonStr);
}

QJsonObject FridaApiBridge::callBackendNoSession(std::function<bool(void *)> fn)
{
	PJ *pj = pj_new();
	if (!pj) {
		throw QCoreApplication::translate("FridaApiBridge", "JSON allocation failed");
	}
	bool ok = fn(pj);
	char *json = pj_drain(pj);
	QString jsonStr = QString::fromUtf8(json ? json : "");
	free(json);
	if (!ok) {
		throw envelopeError(jsonStr, QCoreApplication::translate("FridaApiBridge", "Frida backend call failed"));
	}
	return parseEnvelope(jsonStr);
}

QJsonObject FridaApiBridge::callBackendWithCore(std::function<bool(RzFridaSession *, void *, void *)> fn)
{
	QMutexLocker lock(&m_mutex);
	PJ *pj = pj_new();
	if (!pj) {
		throw QCoreApplication::translate("FridaApiBridge", "JSON allocation failed");
	}
	RzCoreLocked coreLocked = Core()->lock();
	RzCore *core = (RzCore *)coreLocked.operator->();
	RzFridaSession *s = rz_frida_session_from_core(core);
	if (!s) {
		pj_free(pj);
		throw QCoreApplication::translate("FridaApiBridge", "No active Frida session");
	}
	bool ok = fn(s, core, pj);
	char *json = pj_drain(pj);
	QString jsonStr = QString::fromUtf8(json ? json : "");
	free(json);
	if (!ok) {
		throw envelopeError(jsonStr, QCoreApplication::translate("FridaApiBridge", "Frida backend call failed"));
	}
	return parseEnvelope(jsonStr);
}

QJsonObject FridaApiBridge::drainAndParseResponse(PJ *pj, bool ok, const QString &fallbackError)
{
	char *json = pj_drain(pj);
	QString jsonStr = QString::fromUtf8(json ? json : "");
	free(json);
	if (!ok) {
		throw envelopeError(jsonStr, fallbackError);
	}
	return parseEnvelope(jsonStr);
}

QJsonObject FridaApiBridge::parseEnvelope(const QString &json)
{
	if (json.isEmpty()) {
		throw QCoreApplication::translate("FridaApiBridge", "empty response from Frida backend");
	}
	QJsonDocument doc = QJsonDocument::fromJson(json.toUtf8());
	if (doc.isNull() || !doc.isObject()) {
		throw QCoreApplication::translate("FridaApiBridge", "invalid JSON response: %1").arg(json.left(200));
	}
	QJsonObject obj = doc.object();
	if (!obj["ok"].toBool()) {
		QJsonObject err = obj["error"].toObject();
		throw err["message"].toString();
	}
	return obj["result"].toObject();
}

QJsonObject FridaApiBridge::openSession(const QString &action, const QString &transport,
	const QString &device, const QString &target)
{
	QMutexLocker lock(&m_mutex);
	QByteArray actionBytes = action.toUtf8();
	QByteArray transportBytes = transport.toUtf8();
	QByteArray deviceBytes = device.toUtf8();
	QByteArray targetBytes = target.toUtf8();

	PJ *pj = pj_new();
	if (!pj) {
		throw QCoreApplication::translate("FridaApiBridge", "JSON allocation failed");
	}

	RzCoreLocked coreLocked = Core()->lock();
	RzCore *core = (RzCore *)coreLocked.operator->();

	RzFridaSession *existing = rz_frida_session_from_core(core);
	if (existing) {
		pj_free(pj);
		throw QCoreApplication::translate("FridaApiBridge", "A session is already open");
	}

	RzFridaUri uri = {};
	if (!rz_frida_uri_from_parts(actionBytes.constData(), transportBytes.constData(),
		deviceBytes.constData(), targetBytes.constData(), &uri)) {
		pj_free(pj);
		throw QCoreApplication::translate("FridaApiBridge", "Invalid Frida URI");
	}

	RzFridaSession *sess = rz_frida_session_new();
	if (!sess) {
		rz_frida_uri_fini(&uri);
		pj_free(pj);
		throw QCoreApplication::translate("FridaApiBridge", "Cannot allocate session");
	}

	ut64 timeout = rz_config_get_integer(core->config, "frida.timeout");
	if (!timeout) {
		timeout = RZ_FRIDA_DEFAULT_TIMEOUT_MS;
	}
	rz_frida_session_set_timeout(sess, timeout);

	if (!rz_frida_session_set_uri(sess, &uri)) {
		rz_frida_uri_fini(&uri);
		rz_frida_session_free(sess);
		pj_free(pj);
		throw QCoreApplication::translate("FridaApiBridge", "Cannot store session URI");
	}
	rz_frida_uri_fini(&uri);

	bool opened = rz_frida_backend_open(sess, pj);
	if (!opened) {
		rz_frida_session_free(sess);
		return drainAndParseResponse(pj, false, QCoreApplication::translate("FridaApiBridge", "Failed to open Frida session"));
	}

	rz_frida_session_store_to_core(core, sess);
	if (rz_frida_session_from_core(core) != sess) {
		rz_frida_session_free(sess);
		pj_free(pj);
		throw QCoreApplication::translate("FridaApiBridge", "Failed to store session in rizin plugin context");
	}

	return drainAndParseResponse(pj, true, QString());
}

QJsonObject FridaApiBridge::closeSession()
{
	QMutexLocker lock(&m_mutex);
	PJ *pj = pj_new();
	if (!pj) {
		throw QCoreApplication::translate("FridaApiBridge", "JSON allocation failed");
	}

	RzCoreLocked coreLocked = Core()->lock();
	RzCore *core = (RzCore *)coreLocked.operator->();
	RzFridaSession *s = rz_frida_session_from_core(core);
	if (!s) {
		pj_free(pj);
		throw QCoreApplication::translate("FridaApiBridge", "No active Frida session");
	}

	bool ok = rz_frida_backend_close(s, pj);
	rz_frida_session_store_to_core(core, NULL);
	rz_frida_session_free(s);

	char *json = pj_drain(pj);
	QString jsonStr = QString::fromUtf8(json ? json : "");
	free(json);
	if (!ok) {
		throw envelopeError(jsonStr, QCoreApplication::translate("FridaApiBridge", "Failed to close Frida session"));
	}
	return parseEnvelope(jsonStr);
}

QJsonObject FridaApiBridge::resumeSession()
{
	return callBackend([](RzFridaSession *s, void *pjPtr) {
		return rz_frida_backend_resume(s, (PJ *)pjPtr);
	});
}

QJsonObject FridaApiBridge::javaAvailable()
{
	return callBackend([](RzFridaSession *s, void *pjPtr) {
		return rz_frida_backend_java_available(s, (PJ *)pjPtr);
	});
}

QJsonObject FridaApiBridge::listDevices()
{
	return callBackendNoSession([](void *pjPtr) {
		return rz_frida_devices_json((PJ *)pjPtr);
	});
}

QJsonObject FridaApiBridge::listProcesses(const QString &transport, const QString &device)
{
	QByteArray transportBytes = transport.toUtf8();
	QByteArray deviceBytes = device.toUtf8();

	return callBackendNoSession([&](void *pjPtr) {
		RzFridaUri uri = {};
		if (!rz_frida_uri_from_parts("list", transportBytes.constData(),
			deviceBytes.constData(), "", &uri)) {
			return false;
		}
		bool result = rz_frida_processes_json(&uri, (PJ *)pjPtr);
		rz_frida_uri_fini(&uri);
		return result;
	});
}

QJsonObject FridaApiBridge::listApps(const QString &transport, const QString &device)
{
	QByteArray transportBytes = transport.toUtf8();
	QByteArray deviceBytes = device.toUtf8();

	return callBackendNoSession([&](void *pjPtr) {
		RzFridaUri uri = {};
		if (!rz_frida_uri_from_parts("apps", transportBytes.constData(),
			deviceBytes.constData(), "", &uri)) {
			return false;
		}
		bool result = rz_frida_apps_json(&uri, (PJ *)pjPtr);
		rz_frida_uri_fini(&uri);
		return result;
	});
}

QJsonObject FridaApiBridge::ranges(bool refresh)
{
	return callBackend([refresh](RzFridaSession *s, void *pjPtr) {
		return rz_frida_backend_ranges(s, refresh, (PJ *)pjPtr);
	});
}

QJsonObject FridaApiBridge::modules(bool refresh)
{
	return callBackend([refresh](RzFridaSession *s, void *pjPtr) {
		return rz_frida_backend_modules(s, refresh, (PJ *)pjPtr);
	});
}

QJsonObject FridaApiBridge::threads()
{
	return callBackend([](RzFridaSession *s, void *pjPtr) {
		return rz_frida_backend_threads(s, (PJ *)pjPtr);
	});
}

QJsonObject FridaApiBridge::exports(const QString &moduleName)
{
	QByteArray modBytes = moduleName.toUtf8();
	return callBackend([&](RzFridaSession *s, void *pjPtr) {
		return rz_frida_backend_exports(s, modBytes.constData(), (PJ *)pjPtr);
	});
}

QJsonObject FridaApiBridge::imports(const QString &moduleName)
{
	QByteArray modBytes = moduleName.toUtf8();
	return callBackend([&](RzFridaSession *s, void *pjPtr) {
		return rz_frida_backend_imports(s, modBytes.constData(), (PJ *)pjPtr);
	});
}

QJsonObject FridaApiBridge::symbols(const QString &moduleName)
{
	QByteArray modBytes = moduleName.toUtf8();
	return callBackend([&](RzFridaSession *s, void *pjPtr) {
		return rz_frida_backend_symbols(s, modBytes.constData(), (PJ *)pjPtr);
	});
}

QJsonObject FridaApiBridge::memRead(quint64 address, quint64 size)
{
	return callBackend([=](RzFridaSession *s, void *pjPtr) {
		return rz_frida_backend_mem_read(s, address, size, (PJ *)pjPtr);
	});
}

QJsonObject FridaApiBridge::memWrite(quint64 address, const QByteArray &hexBytes)
{
	QByteArray cleanHex = hexBytes.simplified().replace(" ", "");
	int len = cleanHex.length() / 2;
	if (len <= 0 || cleanHex.length() % 2) {
		throw QCoreApplication::translate("FridaApiBridge", "Expected an even-length hex byte string");
	}
	ut8 *bytes = RZ_NEWS(ut8, len);
	if (!bytes) {
		throw QCoreApplication::translate("FridaApiBridge", "Cannot allocate write buffer");
	}
	int actual = rz_hex_str2bin(cleanHex.constData(), bytes);
	if (actual < 1) {
		free(bytes);
		throw QCoreApplication::translate("FridaApiBridge", "Invalid hex byte string");
	}
	try {
		auto result = callBackend([=](RzFridaSession *s, void *pjPtr) {
			return rz_frida_backend_mem_write(s, address, bytes, (size_t)actual, (PJ *)pjPtr);
		});
		free(bytes);
		return result;
	} catch (...) {
		free(bytes);
		throw;
	}
}

QJsonObject FridaApiBridge::loaders()
{
	return callBackend([](RzFridaSession *s, void *pjPtr) {
		return rz_frida_backend_loaders(s, (PJ *)pjPtr);
	});
}

QJsonObject FridaApiBridge::classes(const QString &prefix)
{
	QByteArray prefixBytes;
	const char *prefixPtr = nullptr;
	if (!prefix.isEmpty()) {
		prefixBytes = prefix.toUtf8();
		prefixPtr = prefixBytes.constData();
	}

	RzCoreLocked coreLocked = Core()->lock();
	RzCore *core = (RzCore *)coreLocked.operator->();
	ut64 max = rz_config_get_integer(core->config, "frida.java.max");

	return callBackend([=](RzFridaSession *s, void *pjPtr) {
		return rz_frida_backend_classes(s, prefixPtr, max, (PJ *)pjPtr);
	});
}

QJsonObject FridaApiBridge::describeClass(const QString &className, quint64 loaderId)
{
	QByteArray nameBytes = className.toUtf8();
	return callBackend([=](RzFridaSession *s, void *pjPtr) {
		return rz_frida_backend_class_describe(s, nameBytes.constData(), loaderId, (PJ *)pjPtr);
	});
}

QJsonObject FridaApiBridge::importClass(const QString &className, quint64 loaderId)
{
	QByteArray nameBytes = className.toUtf8();
	return callBackendWithCore([=](RzFridaSession *s, void *corePtr, void *pjPtr) {
		return rz_frida_backend_import_class(s, (RzCore *)corePtr, nameBytes.constData(), loaderId, (PJ *)pjPtr);
	});
}

QJsonObject FridaApiBridge::classLoadMonitor(bool enable)
{
	return callBackend([=](RzFridaSession *s, void *pjPtr) {
		return rz_frida_backend_class_load_monitor(s, enable, (PJ *)pjPtr);
	});
}

QJsonObject FridaApiBridge::newlyLoadedClasses()
{
	return callBackend([](RzFridaSession *s, void *pjPtr) {
		return rz_frida_backend_newly_loaded_classes(s, (PJ *)pjPtr);
	});
}

QJsonObject FridaApiBridge::eval(const QString &source)
{
	QByteArray srcBytes = source.toUtf8();
	return callBackend([&](RzFridaSession *s, void *pjPtr) {
		return rz_frida_backend_eval(s, srcBytes.constData(), (PJ *)pjPtr);
	});
}

QJsonObject FridaApiBridge::loadScript(const QString &filePath)
{
	QFile file(filePath);
	if (!file.open(QIODevice::ReadOnly | QIODevice::Text)) {
		throw QCoreApplication::translate("FridaApiBridge", "Cannot read script file: %1").arg(filePath);
	}
	QByteArray source = file.readAll();
	file.close();
	return eval(QString::fromUtf8(source));
}

QJsonObject FridaApiBridge::ping()
{
	return callBackend([](RzFridaSession *s, void *pjPtr) {
		return rz_frida_backend_ping(s, (PJ *)pjPtr);
	});
}

QJsonObject FridaApiBridge::messages()
{
	return callBackend([](RzFridaSession *s, void *pjPtr) {
		return rz_frida_backend_messages(s, (PJ *)pjPtr);
	});
}

QJsonObject FridaApiBridge::bpSet(quint64 address)
{
	return callBackend([=](RzFridaSession *s, void *pjPtr) {
		return rz_frida_backend_bp_set(s, address, (PJ *)pjPtr);
	});
}

QJsonObject FridaApiBridge::bpList()
{
	return callBackend([](RzFridaSession *s, void *pjPtr) {
		return rz_frida_backend_bp_list(s, (PJ *)pjPtr);
	});
}

QJsonObject FridaApiBridge::bpRemove(const QString &address)
{
	QByteArray addrBytes = address.toUtf8();
	return callBackend([&](RzFridaSession *s, void *pjPtr) {
		return rz_frida_backend_bp_remove(s, addrBytes.constData(), (PJ *)pjPtr);
	});
}

QJsonObject FridaApiBridge::bpRemoveAll()
{
	return callBackend([](RzFridaSession *s, void *pjPtr) {
		return rz_frida_backend_bp_remove(s, "*", (PJ *)pjPtr);
	});
}

QJsonObject FridaApiBridge::wpSet(quint64 address, quint64 size, const QString &conditions)
{
	QByteArray condBytes;
	const char *condPtr = nullptr;
	if (!conditions.isEmpty()) {
		condBytes = conditions.toUtf8();
		condPtr = condBytes.constData();
	}

	RzCoreLocked coreLocked = Core()->lock();
	RzCore *core = (RzCore *)coreLocked.operator->();
	ut64 wpSlots = rz_config_get_integer(core->config, "frida.hw.watchpoints");

	return callBackend([=](RzFridaSession *s, void *pjPtr) {
		return rz_frida_backend_wp_set(s, address, size, condPtr, wpSlots, (PJ *)pjPtr);
	});
}

QJsonObject FridaApiBridge::wpList()
{
	return callBackend([](RzFridaSession *s, void *pjPtr) {
		return rz_frida_backend_wp_list(s, (PJ *)pjPtr);
	});
}

QJsonObject FridaApiBridge::wpRemove(const QString &address)
{
	QByteArray addrBytes = address.toUtf8();
	return callBackend([&](RzFridaSession *s, void *pjPtr) {
		return rz_frida_backend_wp_remove(s, addrBytes.constData(), (PJ *)pjPtr);
	});
}

QJsonObject FridaApiBridge::wpRemoveAll()
{
	return callBackend([](RzFridaSession *s, void *pjPtr) {
		return rz_frida_backend_wp_remove(s, "*", (PJ *)pjPtr);
	});
}

QJsonObject FridaApiBridge::continueThread(const QString &threadId)
{
	QByteArray tidBytes;
	const char *tidPtr = nullptr;
	if (!threadId.isEmpty()) {
		tidBytes = threadId.toUtf8();
		tidPtr = tidBytes.constData();
	}
	return callBackend([=](RzFridaSession *s, void *pjPtr) {
		return rz_frida_backend_continue(s, tidPtr, (PJ *)pjPtr);
	});
}

QJsonObject FridaApiBridge::regRead(quint64 threadId)
{
	return callBackend([=](RzFridaSession *s, void *pjPtr) {
		return rz_frida_backend_reg_read(s, threadId, (PJ *)pjPtr);
	});
}

QJsonObject FridaApiBridge::regWrite(quint64 threadId, const QString &reg, const QString &value)
{
	QByteArray regBytes = reg.toUtf8();
	QByteArray valBytes = value.toUtf8();
	return callBackend([&](RzFridaSession *s, void *pjPtr) {
		return rz_frida_backend_reg_write(s, threadId, regBytes.constData(), valBytes.constData(), (PJ *)pjPtr);
	});
}

QJsonObject FridaApiBridge::rnSet(bool enable)
{
	return callBackend([=](RzFridaSession *s, void *pjPtr) {
		return rz_frida_backend_rn_set(s, enable, (PJ *)pjPtr);
	});
}

QJsonObject FridaApiBridge::rnList()
{
	return callBackend([](RzFridaSession *s, void *pjPtr) {
		return rz_frida_backend_rn_list(s, (PJ *)pjPtr);
	});
}

QJsonObject FridaApiBridge::rnImport()
{
	return callBackendWithCore([](RzFridaSession *s, void *corePtr, void *pjPtr) {
		return rz_frida_backend_rn_import(s, (RzCore *)corePtr, (PJ *)pjPtr);
	});
}

QJsonObject FridaApiBridge::flagImport()
{
	return callBackendWithCore([](RzFridaSession *s, void *corePtr, void *pjPtr) {
		return rz_frida_backend_flag_import(s, (RzCore *)corePtr, (PJ *)pjPtr);
	});
}

QJsonObject FridaApiBridge::dexDiff(const QString &prefix)
{
	QByteArray prefixBytes;
	const char *prefixPtr = nullptr;
	if (!prefix.isEmpty()) {
		prefixBytes = prefix.toUtf8();
		prefixPtr = prefixBytes.constData();
	}
	return callBackendWithCore([=](RzFridaSession *s, void *corePtr, void *pjPtr) {
		return rz_frida_backend_dex_diff(s, (RzCore *)corePtr, prefixPtr, (PJ *)pjPtr);
	});
}
