// SPDX-FileCopyrightText: 2026 Alok Kumar Mishra <alok16022006@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#pragma once

#include <QObject>
#include <QJsonObject>
#include <functional>

/**
 * \brief Serialized async task runner for blocking Frida C API calls.
 *
 * Runs one task at a time on a worker thread, then sends the
 * result/error back on Qt main thread via callbacks. The rz-frida
 * backend assumes a single in-flight request per session, so tasks must never
 * run concurrently, the worker queue ensures that only.
 */
class FridaTaskRunner : public QObject {
	Q_OBJECT
public:
	using Task = std::function<QJsonObject()>;
	using OkCallback = std::function<void(const QJsonObject &)>;
	using ErrCallback = std::function<void(const QString &)>;

	explicit FridaTaskRunner(QObject *parent = nullptr);
	~FridaTaskRunner() override;

	/**
	 * \brief Queue a blocking task for the worker thread.
	 * \param task The blocking function to run on the worker thread.
	 * \param parent The QWidget parent for lifetime guarding (can be nullptr).
	 * \param onOk Called on the main thread with the result on success.
	 * \param onErr Called on the main thread with an error message on failure.
	 */
	void run(Task task, QObject *parent, OkCallback onOk, ErrCallback onErr);

	/**
	 * \brief Block until all queued and running tasks have finished.
	 *
	 * Safe to call from the main thread. After this returns, no tasks are
	 * running and it is safe to destroy resources they depend on.
	 */
	void waitForAll();

private:
	class Private;
	Private *d;

	void workerLoop();
};
