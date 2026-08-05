// SPDX-FileCopyrightText: 2026 Alok Kumar Mishra <alok16022006@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "FridaTaskRunner.h"

#include <QThread>
#include <QPointer>
#include <QQueue>
#include <QMutex>
#include <QWaitCondition>
#include <QMetaObject>

class FridaTaskRunner::Private {
public:
	struct PendingTask {
		Task task;
		QPointer<QObject> guard;
		OkCallback onOk;
		ErrCallback onErr;
	};

	QQueue<PendingTask> queue;
	QMutex mutex;
	QWaitCondition workCond;
	QWaitCondition idleCond;
	QThread *thread = nullptr;
	bool running = false;
	bool quit = false;
};

FridaTaskRunner::FridaTaskRunner(QObject *parent)
	: QObject(parent)
	, d(new Private)
{
	d->thread = QThread::create([this]() { workerLoop(); });
	d->thread->start();
}

FridaTaskRunner::~FridaTaskRunner()
{
	{
		QMutexLocker lock(&d->mutex);
		d->quit = true;
	}
	d->workCond.wakeAll();
	d->thread->wait();
	delete d->thread;
	delete d;
}

void FridaTaskRunner::waitForAll()
{
	QMutexLocker lock(&d->mutex);
	while (!d->queue.isEmpty() || d->running) {
		d->idleCond.wait(&d->mutex);
	}
}

void FridaTaskRunner::run(Task task, QObject *parent, OkCallback onOk, ErrCallback onErr)
{
	Private::PendingTask pending;
	pending.task = std::move(task);
	pending.guard = parent;
	pending.onOk = std::move(onOk);
	pending.onErr = std::move(onErr);

	{
		QMutexLocker lock(&d->mutex);
		d->queue.enqueue(pending);
	}
	d->workCond.wakeOne();
}

void FridaTaskRunner::workerLoop()
{
	for (;;) {
		Private::PendingTask pending;
		{
			QMutexLocker lock(&d->mutex);
			while (d->queue.isEmpty() && !d->quit) {
				d->workCond.wait(&d->mutex);
			}
			if (d->quit) {
				// drop queued tasks instead of running them
				break;
			}
			pending = d->queue.dequeue();
			d->running = true;
		}

		bool ok = true;
		QJsonObject result;
		QString error;
		try {
			result = pending.task();
		} catch (const QString &e) {
			ok = false;
			error = e;
		} catch (const std::exception &e) {
			ok = false;
			error = QString::fromUtf8(e.what());
		} catch (...) {
			ok = false;
			error = tr("Unknown error");
		}

		{
			QMutexLocker lock(&d->mutex);
			d->running = false;
			if (d->queue.isEmpty()) {
				d->idleCond.wakeAll();
			}
		}

		QPointer<QObject> guard = pending.guard;
		OkCallback onOk = pending.onOk;
		ErrCallback onErr = pending.onErr;
		QMetaObject::invokeMethod(this, [guard, onOk, onErr, ok, result, error]() {
			if (guard.isNull()) {
				return;
			}
			if (ok && onOk) {
				onOk(result);
			} else if (!ok && onErr) {
				onErr(error);
			}
		}, Qt::QueuedConnection);
	}
}
