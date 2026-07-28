// SPDX-FileCopyrightText: 2026 Alok Kumar Mishra <alok16022006@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "FridaDockWidget.h"
#include "FridaConnectDialog.h"
#include "FridaCmdRunner.h"

#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QGroupBox>
#include <QFormLayout>
#include <QHeaderView>
#include <QJsonDocument>
#include <QJsonArray>
#include <QJsonObject>
#include <QMessageBox>
#include <QFileDialog>
#include <QStandardItemModel>
#include <QSortFilterProxyModel>

// ---- constructor ----

FridaDockWidget::FridaDockWidget(MainWindow *main)
	: CutterDockWidget(main),
	  m_hasSession(false)
{
	setObjectName("FridaDockWidget");
	setWindowTitle(tr("Frida"));

	tabs = new QTabWidget(this);

	setupSessionTab();
	setupRuntimeTab();
	setupJavaTab();
	setupScriptTab();
	setupMessagesTab();
	setupDexDiffTab();
	setupRnTab();
	setupFlagsTab();
	setupDebugTab();

	// status bar
	auto *statusWidget = new QWidget(this);
	auto *statusLayout = new QHBoxLayout(statusWidget);
	statusLayout->setContentsMargins(4, 2, 4, 2);
	sessionLabel = new QLabel(tr("Not connected"), statusWidget);
	targetLabel = new QLabel(statusWidget);
	agentLabel = new QLabel(statusWidget);
	connectButton = new QPushButton(tr("Connect"), statusWidget);
	disconnectButton = new QPushButton(tr("Disconnect"), statusWidget);
	disconnectButton->setVisible(false);
	statusLayout->addWidget(sessionLabel);
	statusLayout->addWidget(agentLabel);
	statusLayout->addWidget(targetLabel, 1);
	statusLayout->addWidget(connectButton);
	statusLayout->addWidget(disconnectButton);

	auto *mainWidget = new QWidget(this);
	auto *mainLayout = new QVBoxLayout(mainWidget);
	mainLayout->setContentsMargins(0, 0, 0, 0);
	mainLayout->addWidget(statusWidget);
	mainLayout->addWidget(tabs);
	setWidget(mainWidget);

	// core connections
	connect(connectButton, &QPushButton::clicked, this, &FridaDockWidget::onConnectClicked);
	connect(disconnectButton, &QPushButton::clicked, this, &FridaDockWidget::onDisconnectClicked);
	connect(Core(), &CutterCore::refreshAll, this, &FridaDockWidget::refreshAll);

	updateSessionState();
}

// ---- status bar + session management ----

void FridaDockWidget::updateSessionState()
{
	try {
		QJsonObject result = FridaCmdRunner::runSync("fridasj");
		m_hasSession = result["active"].toBool();
	} catch (const QString &) {
		m_hasSession = false;
	}
	setSessionEnabled(m_hasSession);
}

void FridaDockWidget::setSessionEnabled(bool enabled)
{
	connectButton->setVisible(!enabled);
	disconnectButton->setVisible(enabled);
	sessionLabel->setText(enabled ? tr("Connected") : tr("Not connected"));

	for (int i = 1; i < tabs->count(); i++) {
		tabs->setTabEnabled(i, enabled);
	}
}

void FridaDockWidget::onConnectClicked()
{
	FridaConnectDialog dlg(this);
	if (dlg.exec() != QDialog::Accepted) {
		return;
	}
	const QString cmd = dlg.getCommand();
	connectButton->setEnabled(false);
	targetLabel->setText(tr("Connecting..."));
	FridaCmdRunner::runAsyncQuiet(cmd, this,
		[this](const QJsonObject &result) {
			bool spawned = (result["action"].toString() == "spawn");
			targetLabel->setText(tr("session opened"));
			connectButton->setEnabled(true);
			if (spawned) {
				FridaCmdRunner::runAsyncQuiet("fridarj", this,
					[this](const QJsonObject &) {
						updateSessionState();
					},
					[this](const QString &) {
						updateSessionState();
					});
			} else {
				updateSessionState();
			}
		},
		[this](const QString &err) {
			QMessageBox::warning(this, tr("Connection Failed"), err);
			targetLabel->setText(err);
			connectButton->setEnabled(true);
		});
}

void FridaDockWidget::onDisconnectClicked()
{
	try {
		FridaCmdRunner::runSync("fridacj");
		updateSessionState();
	} catch (const QString &) {
	} catch (...) {
	}
}

void FridaDockWidget::refreshAll()
{
	updateSessionState();
}

// ---- common helpers (used in lambdas) ----

static QStandardItem *makeItem(const QString &text)
{
	auto *item = new QStandardItem(text);
	item->setFlags(item->flags() & ~Qt::ItemIsEditable);
	return item;
}

static void clearModel(QTableView *table)
{
	auto *model = static_cast<QStandardItemModel *>(
		static_cast<QSortFilterProxyModel *>(table->model())->sourceModel());
	model->removeRows(0, model->rowCount());
}

// ---- Session tab ----

void FridaDockWidget::setupSessionTab()
{
	auto *page = new QWidget(this);
	auto *layout = new QVBoxLayout(page);

	// transport
	auto *transportGroup = new QGroupBox(tr("Transport"), page);
	auto *transportLayout = new QHBoxLayout(transportGroup);
	transportCombo_session = new QComboBox(transportGroup);
	transportCombo_session->addItem(tr("Local"), "local");
	transportCombo_session->addItem(tr("USB"), "usb");
	transportCombo_session->addItem(tr("Remote"), "remote");
	transportCombo_session->setCurrentIndex(1);
	hostPortEdit_session = new QLineEdit(transportGroup);
	hostPortEdit_session->setPlaceholderText("host:port");
	hostPortEdit_session->setVisible(false);
	transportLayout->addWidget(new QLabel(tr("Transport:"), transportGroup));
	transportLayout->addWidget(transportCombo_session, 1);
	transportLayout->addWidget(hostPortEdit_session, 2);
	layout->addWidget(transportGroup);

	connect(transportCombo_session, QOverload<int>::of(&QComboBox::currentIndexChanged),
		this, [this](int idx) {
			hostPortEdit_session->setVisible(transportCombo_session->itemData(idx).toString() == "remote");
		});

	// device
	auto *deviceGroup = new QGroupBox(tr("Device"), page);
	auto *deviceLayout = new QHBoxLayout(deviceGroup);
	deviceCombo_session = new QComboBox(deviceGroup);
	deviceCombo_session->setMinimumWidth(250);
	refreshDevicesBtn_session = new QPushButton(tr("Refresh"), deviceGroup);
	deviceLayout->addWidget(new QLabel(tr("Device:"), deviceGroup));
	deviceLayout->addWidget(deviceCombo_session, 1);
	deviceLayout->addWidget(refreshDevicesBtn_session);
	layout->addWidget(deviceGroup);

	connect(refreshDevicesBtn_session, &QPushButton::clicked, this, [this]() {
		refreshDevicesBtn_session->setEnabled(false);
		FridaCmdRunner::runAsyncQuiet("fridadj", this,
			[this](const QJsonObject &result) {
				QJsonArray devices = result["devices"].toArray();
				m_devices.clear();
				deviceCombo_session->clear();
				for (const auto &d : devices) {
					QJsonObject dev = d.toObject();
					FridaDevice fd;
					fd.name = dev["name"].toString();
					fd.id = dev["id"].toString();
					fd.type = dev["type"].toString();
					m_devices.append(fd);
					deviceCombo_session->addItem(QString("%1 (%2)").arg(fd.name, fd.type), fd.id);
				}
				refreshDevicesBtn_session->setEnabled(true);
			}, [this](const QString &) { refreshDevicesBtn_session->setEnabled(true); });
	});

	// target
	auto *targetGroup = new QGroupBox(tr("Target"), page);
	auto *targetLayout = new QVBoxLayout(targetGroup);
	auto *targetRow = new QHBoxLayout();
	targetTypeCombo_session = new QComboBox(targetGroup);
	targetTypeCombo_session->addItem(tr("PID / Process Name"), "process");
	targetTypeCombo_session->addItem(tr("Package Name"), "package");
	targetEdit_session = new QLineEdit(targetGroup);
	targetEdit_session->setPlaceholderText(tr("PID, process name, or package"));
	refreshTargetsBtn_session = new QPushButton(tr("Refresh"), targetGroup);
	targetRow->addWidget(targetTypeCombo_session);
	targetRow->addWidget(targetEdit_session, 1);
	targetRow->addWidget(refreshTargetsBtn_session);
	targetLayout->addLayout(targetRow);

	actionCombo_session = new QComboBox(targetGroup);
	actionCombo_session->addItem(tr("Attach"), "attach");
	actionCombo_session->addItem(tr("Spawn"), "spawn");
	actionCombo_session->addItem(tr("Launch"), "launch");
	targetLayout->addWidget(actionCombo_session);
	layout->addWidget(targetGroup);

	connect(refreshTargetsBtn_session, &QPushButton::clicked, this, [this]() {
		QString transport = transportCombo_session->currentData().toString();
		QString device;
		int idx = deviceCombo_session->currentIndex();
		if (idx >= 0 && idx < m_devices.size()) device = m_devices[idx].id;
		QString uri = QString("frida://list/%1/%2/").arg(transport, device);
		QString cmd = (targetTypeCombo_session->currentData().toString() == "package")
			? ("fridaaj " + uri) : ("fridapj " + uri);
		bool isPkg = (targetTypeCombo_session->currentData().toString() == "package");
		refreshTargetsBtn_session->setEnabled(false);
		FridaCmdRunner::runAsyncQuiet(cmd, this,
			[this, isPkg](const QJsonObject &result) {
				m_processes.clear();
				QJsonArray arr = result[isPkg ? "apps" : "processes"].toArray();
				for (const auto &v : arr) {
					QJsonObject obj = v.toObject();
					FridaProcess fp;
					fp.pid = obj["pid"].toInt();
					fp.name = obj["name"].toString();
					m_processes.append(fp);
				}
				refreshTargetsBtn_session->setEnabled(true);
			}, [this](const QString &) { refreshTargetsBtn_session->setEnabled(true); });
	});

	// connect button
	auto *btnLayout = new QHBoxLayout();
	btnLayout->addStretch();
	auto *connectBtn = new QPushButton(tr("Connect"), page);
	connectBtn->setDefault(true);
	auto *disconnectBtn = new QPushButton(tr("Disconnect"), page);
	btnLayout->addWidget(connectBtn);
	btnLayout->addWidget(disconnectBtn);
	layout->addLayout(btnLayout);

	connect(connectBtn, &QPushButton::clicked, this, [this, connectBtn]() {
		QString action = actionCombo_session->currentData().toString();
		QString transport = transportCombo_session->currentData().toString();
		QString device = (transport == "remote") ? hostPortEdit_session->text()
			: (transport == "local") ? QString()
			: ((deviceCombo_session->currentIndex() >= 0 &&
			    deviceCombo_session->currentIndex() < m_devices.size())
			   ? m_devices[deviceCombo_session->currentIndex()].id : QString());
		QString target = targetEdit_session->text().trimmed();
		QString uri = QString("%1/%2/%3/%4").arg(action, transport, device, target);
		connectBtn->setEnabled(false);
		connectButton->setEnabled(false);
		targetLabel->setText(tr("Connecting..."));
		FridaCmdRunner::runAsyncQuiet("fridaoj " + uri, this,
			[this, connectBtn, transport, device, target](const QJsonObject &result) {
				bool spawned = (result["action"].toString() == "spawn");
				targetLabel->setText(QString("%1:%2 (%3)").arg(transport, device, target));
				connectBtn->setEnabled(true);
				connectButton->setEnabled(true);
				if (spawned) {
					FridaCmdRunner::runAsyncQuiet("fridarj", this,
						[this](const QJsonObject &) {
							updateSessionState();
						},
						[this](const QString &) {
							updateSessionState();
						});
				} else {
					updateSessionState();
				}
			},
			[this, connectBtn](const QString &err) {
				QMessageBox::warning(this, tr("Connection Failed"), err);
				targetLabel->setText(err);
				connectBtn->setEnabled(true);
				connectButton->setEnabled(true);
			});
	});

	connect(disconnectBtn, &QPushButton::clicked, this, &FridaDockWidget::onDisconnectClicked);

	layout->addStretch();
	tabs->addTab(page, tr("Session"));
}

// ---- Runtime, Java, Script, Messages, DexDiff, RegNat, Flags, Debug ----

void FridaDockWidget::setupRuntimeTab()
{
	auto *page = new QWidget(this);
	auto *layout = new QVBoxLayout(page);

	auto *btnRow = new QHBoxLayout();
	auto *refreshBtn = new QPushButton(tr("Refresh"), page);
	btnRow->addWidget(refreshBtn);
	btnRow->addStretch();
	layout->addLayout(btnRow);

	auto *subTabs = new QTabWidget(page);

	rangesTable = setupFridaTable(subTabs, {tr("Base"), tr("Size"), tr("Protection"), tr("File")});
	modulesTable = setupFridaTable(subTabs, {tr("Name"), tr("Base"), tr("Size"), tr("Path")});
	threadsTable = setupFridaTable(subTabs, {tr("ID"), tr("State"), tr("PC"), tr("SP")});

	subTabs->addTab(rangesTable, tr("Ranges"));
	subTabs->addTab(modulesTable, tr("Modules"));
	subTabs->addTab(threadsTable, tr("Threads"));
	layout->addWidget(subTabs);

	// module detail
	auto *modDetailGroup = new QGroupBox(tr("Module Detail"), page);
	auto *modDetailLayout = new QVBoxLayout(modDetailGroup);
	auto *modBtnRow = new QHBoxLayout();
	modExportsBtn = new QPushButton(tr("Exports"), modDetailGroup);
	modImportsBtn = new QPushButton(tr("Imports"), modDetailGroup);
	modSymbolsBtn = new QPushButton(tr("Symbols"), modDetailGroup);
	modBtnRow->addWidget(modExportsBtn);
	modBtnRow->addWidget(modImportsBtn);
	modBtnRow->addWidget(modSymbolsBtn);
	modBtnRow->addStretch();
	modDetailLayout->addLayout(modBtnRow);
	moduleDetailTable = setupFridaTable(modDetailGroup, {tr("Type"), tr("Name"), tr("Address")});
	modDetailLayout->addWidget(moduleDetailTable);
	layout->addWidget(modDetailGroup);

	// memory
	auto *memGroup = new QGroupBox(tr("Memory"), page);
	auto *memLayout = new QVBoxLayout(memGroup);
	auto *memRow1 = new QHBoxLayout();
	memAddrEdit = new QLineEdit(memGroup);
	memAddrEdit->setPlaceholderText("0x1000");
	memSizeEdit = new QLineEdit(memGroup);
	memSizeEdit->setPlaceholderText("64");
	auto *readBtn = new QPushButton(tr("Read"), memGroup);
	memRow1->addWidget(new QLabel(tr("Addr:"), memGroup));
	memRow1->addWidget(memAddrEdit);
	memRow1->addWidget(new QLabel(tr("Size:"), memGroup));
	memRow1->addWidget(memSizeEdit);
	memRow1->addWidget(readBtn);
	memLayout->addLayout(memRow1);

	auto *memRow2 = new QHBoxLayout();
	memHexEdit = new QLineEdit(memGroup);
	memHexEdit->setPlaceholderText(tr("hex bytes, e.g. deadbeef"));
	auto *writeBtn = new QPushButton(tr("Write"), memGroup);
	memRow2->addWidget(new QLabel(tr("Hex:"), memGroup));
	memRow2->addWidget(memHexEdit, 1);
	memRow2->addWidget(writeBtn);
	memLayout->addLayout(memRow2);
	layout->addWidget(memGroup);

	memOutput = new QPlainTextEdit(page);
	memOutput->setReadOnly(true);
	memOutput->setMaximumBlockCount(1000);
	layout->addWidget(memOutput);

	connect(refreshBtn, &QPushButton::clicked, this, [this, refreshBtn]() {
		if (!m_hasSession) return;
		refreshBtn->setEnabled(false);
		FridaCmdRunner::runAsyncQuiet("fridaRj", this,
			[this, refreshBtn](const QJsonObject &result) {
				auto *rm = static_cast<QStandardItemModel *>(static_cast<QSortFilterProxyModel *>(rangesTable->model())->sourceModel());
				rm->removeRows(0, rm->rowCount());
				for (const auto &v : result["ranges"].toArray()) {
					QJsonObject r = v.toObject();
					QJsonObject file = r["file"].toObject();
					rm->appendRow({makeItem(r["base"].toString()), makeItem(QString::number(r["size"].toInt())),
						makeItem(r["protection"].toString()), makeItem(file["path"].toString())});
				}
				refreshBtn->setEnabled(true);
			}, [this, refreshBtn](const QString &) { refreshBtn->setEnabled(true); });
		FridaCmdRunner::runAsyncQuiet("fridaMj", this,
			[this](const QJsonObject &result) {
				auto *mm = static_cast<QStandardItemModel *>(static_cast<QSortFilterProxyModel *>(modulesTable->model())->sourceModel());
				mm->removeRows(0, mm->rowCount());
				for (const auto &v : result["modules"].toArray()) {
					QJsonObject m = v.toObject();
					mm->appendRow({makeItem(m["name"].toString()), makeItem(m["base"].toString()),
						makeItem(QString::number(m["size"].toInt())), makeItem(m["path"].toString())});
				}
			}, [this](const QString &) {});
		FridaCmdRunner::runAsyncQuiet("fridatj", this,
			[this](const QJsonObject &result) {
				auto *tm = static_cast<QStandardItemModel *>(static_cast<QSortFilterProxyModel *>(threadsTable->model())->sourceModel());
				tm->removeRows(0, tm->rowCount());
				for (const auto &v : result["threads"].toArray()) {
					QJsonObject t = v.toObject();
					QJsonObject ctx = t["context"].toObject();
					tm->appendRow({makeItem(QString::number(t["id"].toInt())), makeItem(t["state"].toString()),
						makeItem(ctx["pc"].toString()), makeItem(ctx["sp"].toString())});
				}
			}, [this](const QString &) {});
	});

	// memory read
	connect(readBtn, &QPushButton::clicked, this, [this, readBtn]() {
		QString addr = memAddrEdit->text().trimmed();
		QString size = memSizeEdit->text().trimmed();
		if (addr.isEmpty() || size.isEmpty()) return;
		if (!m_hasSession) return;
		readBtn->setEnabled(false);
		FridaCmdRunner::runAsyncQuiet(QString("fridaxj %1 %2").arg(addr, size), this,
			[this, readBtn](const QJsonObject &result) {
				memOutput->setPlainText(result["bytes"].toString());
				readBtn->setEnabled(true);
			}, [this, readBtn](const QString &e) {
				memOutput->setPlainText(tr("Error: %1").arg(e));
				readBtn->setEnabled(true);
			});
	});

	// memory write
	connect(writeBtn, &QPushButton::clicked, this, [this, writeBtn]() {
		QString addr = memAddrEdit->text().trimmed();
		QString hex = memHexEdit->text().trimmed();
		if (addr.isEmpty() || hex.isEmpty()) return;
		if (!m_hasSession) return;
		writeBtn->setEnabled(false);
		FridaCmdRunner::runAsyncQuiet(QString("fridawj %1 %2").arg(addr, hex), this,
			[this, writeBtn](const QJsonObject &result) {
				memOutput->setPlainText(tr("Written %1 byte(s)").arg(result["size"].toInt()));
				writeBtn->setEnabled(true);
			}, [this, writeBtn](const QString &e) {
				memOutput->setPlainText(tr("Error: %1").arg(e));
				writeBtn->setEnabled(true);
			});
	});

	// module detail: exports
	connect(modExportsBtn, &QPushButton::clicked, this, [this]() {
		if (!m_hasSession) return;
		auto *proxy = static_cast<QSortFilterProxyModel *>(modulesTable->model());
		QModelIndex idx = modulesTable->currentIndex();
		if (!idx.isValid()) return;
		QString modName = proxy->data(proxy->index(idx.row(), 0)).toString();
		modExportsBtn->setEnabled(false);
		clearModel(moduleDetailTable);
		FridaCmdRunner::runAsyncQuiet("fridaEj " + modName, this,
			[this](const QJsonObject &result) {
				auto *dm = static_cast<QStandardItemModel *>(static_cast<QSortFilterProxyModel *>(moduleDetailTable->model())->sourceModel());
				for (const auto &v : result["exports"].toArray()) {
					QJsonObject e = v.toObject();
					dm->appendRow({makeItem(e["type"].toString()), makeItem(e["name"].toString()),
						makeItem(e["address"].toString())});
				}
				modExportsBtn->setEnabled(true);
			}, [this](const QString &) { modExportsBtn->setEnabled(true); });
	});

	// module detail: imports
	connect(modImportsBtn, &QPushButton::clicked, this, [this]() {
		if (!m_hasSession) return;
		auto *proxy = static_cast<QSortFilterProxyModel *>(modulesTable->model());
		QModelIndex idx = modulesTable->currentIndex();
		if (!idx.isValid()) return;
		QString modName = proxy->data(proxy->index(idx.row(), 0)).toString();
		modImportsBtn->setEnabled(false);
		clearModel(moduleDetailTable);
		FridaCmdRunner::runAsyncQuiet("fridaIj " + modName, this,
			[this](const QJsonObject &result) {
				auto *dm = static_cast<QStandardItemModel *>(static_cast<QSortFilterProxyModel *>(moduleDetailTable->model())->sourceModel());
				for (const auto &v : result["imports"].toArray()) {
					QJsonObject e = v.toObject();
					dm->appendRow({makeItem(e["type"].toString()), makeItem(e["name"].toString()),
						makeItem(e["address"].toString())});
				}
				modImportsBtn->setEnabled(true);
			}, [this](const QString &) { modImportsBtn->setEnabled(true); });
	});

	// module detail: symbols
	connect(modSymbolsBtn, &QPushButton::clicked, this, [this]() {
		if (!m_hasSession) return;
		auto *proxy = static_cast<QSortFilterProxyModel *>(modulesTable->model());
		QModelIndex idx = modulesTable->currentIndex();
		if (!idx.isValid()) return;
		QString modName = proxy->data(proxy->index(idx.row(), 0)).toString();
		modSymbolsBtn->setEnabled(false);
		clearModel(moduleDetailTable);
		FridaCmdRunner::runAsyncQuiet("fridaSj " + modName, this,
			[this](const QJsonObject &result) {
				auto *dm = static_cast<QStandardItemModel *>(static_cast<QSortFilterProxyModel *>(moduleDetailTable->model())->sourceModel());
				for (const auto &v : result["symbols"].toArray()) {
					QJsonObject e = v.toObject();
					dm->appendRow({makeItem(e["type"].toString()), makeItem(e["name"].toString()),
						makeItem(e["address"].toString())});
				}
				modSymbolsBtn->setEnabled(true);
			}, [this](const QString &) { modSymbolsBtn->setEnabled(true); });
	});

	tabs->addTab(page, tr("Runtime"));
}

void FridaDockWidget::setupJavaTab()
{
	auto *page = new QWidget(this);
	auto *layout = new QVBoxLayout(page);

	// class loaders
	auto *loaderGroup = new QGroupBox(tr("Class Loaders"), page);
	auto *loaderLayout = new QVBoxLayout(loaderGroup);
	auto *loaderBtnRow = new QHBoxLayout();
	auto *refreshLoadersBtn = new QPushButton(tr("Refresh"), loaderGroup);
	loaderBtnRow->addWidget(refreshLoadersBtn);
	loaderBtnRow->addStretch();
	loaderLayout->addLayout(loaderBtnRow);
	loaderTable = setupFridaTable(loaderGroup, {tr("ID"), tr("Type")});
	loaderLayout->addWidget(loaderTable);
	layout->addWidget(loaderGroup);

	connect(refreshLoadersBtn, &QPushButton::clicked, this, [this, refreshLoadersBtn]() {
		if (!m_hasSession) return;
		refreshLoadersBtn->setEnabled(false);
		FridaCmdRunner::runAsyncQuiet("fridaLj", this,
			[this, refreshLoadersBtn](const QJsonObject &result) {
				auto *lm = static_cast<QStandardItemModel *>(static_cast<QSortFilterProxyModel *>(loaderTable->model())->sourceModel());
				lm->removeRows(0, lm->rowCount());
				for (const auto &v : result["loaders"].toArray()) {
					QJsonObject lo = v.toObject();
					lm->appendRow({makeItem(QString::number(lo["id"].toInt())), makeItem(lo["type"].toString())});
				}
				refreshLoadersBtn->setEnabled(true);
			}, [this, refreshLoadersBtn](const QString &) { refreshLoadersBtn->setEnabled(true); });
	});

	// class load monitor
	auto *clmGroup = new QGroupBox(tr("Class Load Monitor"), page);
	auto *clmLayout = new QVBoxLayout(clmGroup);
	auto *clmBtnRow = new QHBoxLayout();
	clmStartBtn = new QPushButton(tr("Start"), clmGroup);
	clmStopBtn = new QPushButton(tr("Stop"), clmGroup);
	clmRefreshBtn = new QPushButton(tr("Refresh New"), clmGroup);
	clmStatusLabel = new QLabel(tr("Status: stopped"), clmGroup);
	clmBtnRow->addWidget(clmStartBtn);
	clmBtnRow->addWidget(clmStopBtn);
	clmBtnRow->addWidget(clmRefreshBtn);
	clmBtnRow->addStretch();
	clmBtnRow->addWidget(clmStatusLabel);
	clmLayout->addLayout(clmBtnRow);
	clmTable = setupFridaTable(clmGroup, {tr("New Class")});
	clmLayout->addWidget(clmTable);
	layout->addWidget(clmGroup);

	connect(clmStartBtn, &QPushButton::clicked, this, [this]() {
		if (!m_hasSession) return;
		clmStartBtn->setEnabled(false);
		FridaCmdRunner::runAsyncQuiet("fridaNj start", this,
			[this](const QJsonObject &result) {
				bool ok = result["enabled"].toBool();
				clmStatusLabel->setText(ok ? tr("Status: monitoring") : tr("Status: java unavailable"));
				clmStartBtn->setEnabled(true);
			}, [this](const QString &e) {
				clmStatusLabel->setText(tr("Error: %1").arg(e));
				clmStartBtn->setEnabled(true);
			});
	});

	connect(clmStopBtn, &QPushButton::clicked, this, [this]() {
		if (!m_hasSession) return;
		clmStopBtn->setEnabled(false);
		FridaCmdRunner::runAsyncQuiet("fridaNj stop", this,
			[this](const QJsonObject &result) {
				clmStatusLabel->setText(tr("Status: stopped"));
				clmStopBtn->setEnabled(true);
			}, [this](const QString &e) {
				clmStatusLabel->setText(tr("Error: %1").arg(e));
				clmStopBtn->setEnabled(true);
			});
	});

	connect(clmRefreshBtn, &QPushButton::clicked, this, [this]() {
		if (!m_hasSession) return;
		clmRefreshBtn->setEnabled(false);
		FridaCmdRunner::runAsyncQuiet("fridaNj", this,
			[this](const QJsonObject &result) {
				auto *cm = static_cast<QStandardItemModel *>(static_cast<QSortFilterProxyModel *>(clmTable->model())->sourceModel());
				cm->removeRows(0, cm->rowCount());
				for (const auto &v : result["classes"].toArray())
					cm->appendRow({makeItem(v.toString())});
				clmRefreshBtn->setEnabled(true);
			}, [this](const QString &e) {
				clmStatusLabel->setText(tr("Error: %1").arg(e));
				clmRefreshBtn->setEnabled(true);
			});
	});

	// classes
	auto *classGroup = new QGroupBox(tr("Classes"), page);
	auto *classLayout = new QVBoxLayout(classGroup);
	auto *filterRow = new QHBoxLayout();
	filterRow->addWidget(new QLabel(tr("Prefix:"), classGroup));
	prefixFilter = new QLineEdit(classGroup);
	prefixFilter->setPlaceholderText("re.frida.minapp");
	filterRow->addWidget(prefixFilter);
	classLayout->addLayout(filterRow);

	classTable = setupFridaTable(classGroup, {tr("Class Name")});
	classLayout->addWidget(classTable);

	auto *btnRow = new QHBoxLayout();
	auto *refreshClassesBtn = new QPushButton(tr("Refresh"), classGroup);
	describeBtn = new QPushButton(tr("Describe"), classGroup);
	importBtn = new QPushButton(tr("Import to Analysis"), classGroup);
	btnRow->addWidget(refreshClassesBtn);
	btnRow->addStretch();
	btnRow->addWidget(describeBtn);
	btnRow->addWidget(importBtn);
	classLayout->addLayout(btnRow);
	layout->addWidget(classGroup);

	classDetailOutput = new QPlainTextEdit(page);
	classDetailOutput->setReadOnly(true);
	classDetailOutput->setMaximumBlockCount(2000);
	layout->addWidget(classDetailOutput);

	connect(refreshClassesBtn, &QPushButton::clicked, this, [this, refreshClassesBtn]() {
		if (!m_hasSession) return;
		QString prefix = prefixFilter->text().trimmed();
		QString cmd = prefix.isEmpty() ? QString("fridaCj") : QString("fridaCj %1").arg(prefix);
		refreshClassesBtn->setEnabled(false);
		FridaCmdRunner::runAsyncQuiet(cmd, this,
			[this, refreshClassesBtn](const QJsonObject &result) {
				auto *cm = static_cast<QStandardItemModel *>(static_cast<QSortFilterProxyModel *>(classTable->model())->sourceModel());
				cm->removeRows(0, cm->rowCount());
				for (const auto &v : result["classes"].toArray())
					cm->appendRow({makeItem(v.toObject()["name"].toString())});
				refreshClassesBtn->setEnabled(true);
			}, [this, refreshClassesBtn](const QString &e) {
				classDetailOutput->setPlainText(tr("Error: %1").arg(e));
				refreshClassesBtn->setEnabled(true);
			});
	});

	connect(describeBtn, &QPushButton::clicked, this, [this]() {
		if (!m_hasSession) return;
		auto *proxy = static_cast<QSortFilterProxyModel *>(classTable->model());
		QModelIndex idx = classTable->currentIndex();
		if (!idx.isValid()) return;
		QString name = proxy->data(idx).toString();
		describeBtn->setEnabled(false);
		FridaCmdRunner::runAsyncQuiet("fridaDj " + name, this,
			[this](const QJsonObject &result) {
				classDetailOutput->setPlainText(QJsonDocument(result).toJson(QJsonDocument::Indented));
				describeBtn->setEnabled(true);
			}, [this](const QString &e) {
				classDetailOutput->setPlainText(tr("Error: %1").arg(e));
				describeBtn->setEnabled(true);
			});
	});

	connect(importBtn, &QPushButton::clicked, this, [this]() {
		if (!m_hasSession) return;
		auto *proxy = static_cast<QSortFilterProxyModel *>(classTable->model());
		QModelIndex idx = classTable->currentIndex();
		if (!idx.isValid()) return;
		QString name = proxy->data(idx).toString();
		importBtn->setEnabled(false);
		FridaCmdRunner::runAsyncQuiet("fridaImj " + name, this,
			[this](const QJsonObject &) {
				Core()->triggerRefreshAll();
				importBtn->setEnabled(true);
			}, [this](const QString &e) {
				classDetailOutput->setPlainText(tr("Error: %1").arg(e));
				importBtn->setEnabled(true);
			});
	});

	tabs->addTab(page, tr("Java"));
}

void FridaDockWidget::setupScriptTab()
{
	auto *page = new QWidget(this);
	auto *layout = new QVBoxLayout(page);

	// load script
	auto *loadGroup = new QGroupBox(tr("Load Script"), page);
	auto *loadLayout = new QHBoxLayout(loadGroup);
	scriptPathEdit = new QLineEdit(loadGroup);
	scriptBrowseBtn = new QPushButton(tr("Browse"), loadGroup);
	scriptLoadBtn = new QPushButton(tr("Load"), loadGroup);
	loadLayout->addWidget(scriptPathEdit, 1);
	loadLayout->addWidget(scriptBrowseBtn);
	loadLayout->addWidget(scriptLoadBtn);
	layout->addWidget(loadGroup);

	// eval
	auto *evalGroup = new QGroupBox(tr("Eval JS"), page);
	auto *evalLayout = new QVBoxLayout(evalGroup);
	evalInput = new QPlainTextEdit(evalGroup);
	evalInput->setPlaceholderText("Process.arch");
	evalInput->setMaximumBlockCount(50);
	evalLayout->addWidget(evalInput);
	auto *evalRow = new QHBoxLayout();
	evalRow->addStretch();
	evalBtn = new QPushButton(tr("Run"), evalGroup);
	evalRow->addWidget(evalBtn);
	evalLayout->addLayout(evalRow);
	layout->addWidget(evalGroup);

	scriptOutput = new QPlainTextEdit(page);
	scriptOutput->setReadOnly(true);
	scriptOutput->setMaximumBlockCount(1000);
	layout->addWidget(scriptOutput);

	connect(scriptBrowseBtn, &QPushButton::clicked, this, [this]() {
		QString path = QFileDialog::getOpenFileName(this, tr("Open Script"), QString(),
			tr("JavaScript (*.js);;All Files (*)"));
		if (!path.isEmpty()) scriptPathEdit->setText(path);
	});

	connect(scriptLoadBtn, &QPushButton::clicked, this, [this]() {
		if (scriptPathEdit->text().isEmpty()) return;
		if (!m_hasSession) return;
		scriptLoadBtn->setEnabled(false);
		FridaCmdRunner::runAsyncQuiet("fridalj '" + scriptPathEdit->text() + "'", this,
			[this](const QJsonObject &result) {
				scriptOutput->setPlainText(tr("Loaded: %1").arg(result["loaded"].toBool() ? "OK" : "Failed"));
				scriptLoadBtn->setEnabled(true);
			}, [this](const QString &e) {
				scriptOutput->setPlainText(tr("Error: %1").arg(e));
				scriptLoadBtn->setEnabled(true);
			});
	});

	connect(evalBtn, &QPushButton::clicked, this, [this]() {
		QString source = evalInput->toPlainText().trimmed();
		if (source.isEmpty()) return;
		if (!m_hasSession) return;
		evalBtn->setEnabled(false);
		FridaCmdRunner::runAsyncQuiet("fridaej '" + source + "'", this,
			[this](const QJsonObject &result) {
				scriptOutput->setPlainText(QString("%1 (%2)").arg(
					result["value"].toVariant().toString(), result["type"].toString()));
				evalBtn->setEnabled(true);
			}, [this](const QString &e) {
				scriptOutput->setPlainText(tr("Error: %1").arg(e));
				evalBtn->setEnabled(true);
			});
	});

	tabs->addTab(page, tr("Script"));
}

void FridaDockWidget::setupMessagesTab()
{
	auto *page = new QWidget(this);
	auto *layout = new QVBoxLayout(page);

	auto *btnRow = new QHBoxLayout();
	messagesRefreshBtn = new QPushButton(tr("Refresh"), page);
	droppedLabel = new QLabel(tr("Dropped: 0"), page);
	btnRow->addWidget(messagesRefreshBtn);
	btnRow->addWidget(droppedLabel);
	btnRow->addStretch();
	layout->addLayout(btnRow);

	messageLog = new QPlainTextEdit(page);
	messageLog->setReadOnly(true);
	messageLog->setMaximumBlockCount(2000);
	layout->addWidget(messageLog);

	connect(messagesRefreshBtn, &QPushButton::clicked, this, [this]() {
		if (!m_hasSession) return;
		messagesRefreshBtn->setEnabled(false);
		FridaCmdRunner::runAsyncQuiet("fridamj", this,
			[this](const QJsonObject &result) {
				messageLog->clear();
				for (const auto &m : result["messages"].toArray()) {
					QJsonObject msg = m.toObject();
					messageLog->appendPlainText(QString("[%1] %2").arg(
						msg["type"].toString(),
						QJsonDocument(msg["payload"].toObject()).toJson(QJsonDocument::Compact)));
				}
				messageLog->appendPlainText("---");
				droppedLabel->setText(tr("Dropped: %1").arg(result["dropped"].toInt()));
				messagesRefreshBtn->setEnabled(true);
			}, [this](const QString &e) {
				messageLog->appendPlainText(tr("Error: %1").arg(e));
				messagesRefreshBtn->setEnabled(true);
			});
	});

	tabs->addTab(page, tr("Messages"));
}

void FridaDockWidget::setupDexDiffTab()
{
	auto *page = new QWidget(this);
	auto *layout = new QVBoxLayout(page);

	auto *inputRow = new QHBoxLayout();
	inputRow->addWidget(new QLabel(tr("Prefix:"), page));
	dexPrefixEdit = new QLineEdit(page);
	dexPrefixEdit->setPlaceholderText("com.example");
	inputRow->addWidget(dexPrefixEdit);
	dexCompareBtn = new QPushButton(tr("Compare"), page);
	inputRow->addWidget(dexCompareBtn);
	inputRow->addStretch();
	layout->addLayout(inputRow);

	auto *resultGroup = new QGroupBox(tr("Result"), page);
	auto *resultLayout = new QFormLayout(resultGroup);
	dexLoadedBinLabel = new QLabel(tr("No binary loaded"), resultGroup);
	dexOnlyStaticLabel = new QLabel("-", resultGroup);
	dexOnlyRuntimeLabel = new QLabel("-", resultGroup);
	dexBothLabel = new QLabel("-", resultGroup);
	resultLayout->addRow(tr("Binary loaded:"), dexLoadedBinLabel);
	resultLayout->addRow(tr("Only in static:"), dexOnlyStaticLabel);
	resultLayout->addRow(tr("Only in runtime:"), dexOnlyRuntimeLabel);
	resultLayout->addRow(tr("Both:"), dexBothLabel);
	layout->addWidget(resultGroup);

	layout->addStretch();

	connect(dexCompareBtn, &QPushButton::clicked, this, [this]() {
		if (!m_hasSession) return;
		QString prefix = dexPrefixEdit->text().trimmed();
		QString cmd = prefix.isEmpty() ? QString("fridaXj") : QString("fridaXj %1").arg(prefix);
		dexCompareBtn->setEnabled(false);
		FridaCmdRunner::runAsyncQuiet(cmd, this,
			[this](const QJsonObject &result) {
				dexLoadedBinLabel->setText(tr("%1").arg(result["loaded_bin"].toBool() ? "Yes" : "No"));
				dexOnlyStaticLabel->setText(QString::number(result["only_static"].toInt()));
				dexOnlyRuntimeLabel->setText(QString::number(result["only_runtime"].toInt()));
				dexBothLabel->setText(QString::number(result["both"].toInt()));
				dexCompareBtn->setEnabled(true);
			}, [this](const QString &e) {
				dexOnlyStaticLabel->setText(tr("Error: %1").arg(e));
				dexCompareBtn->setEnabled(true);
			});
	});

	tabs->addTab(page, tr("DEX Diff"));
}

void FridaDockWidget::setupRnTab()
{
	auto *page = new QWidget(this);
	auto *layout = new QVBoxLayout(page);

	auto *btnRow = new QHBoxLayout();
	rnOnBtn = new QPushButton(tr("Enable Hook"), page);
	rnOffBtn = new QPushButton(tr("Disable Hook"), page);
	rnRefreshBtn = new QPushButton(tr("Refresh"), page);
	rnImportBtn = new QPushButton(tr("Import to Analysis"), page);
	btnRow->addWidget(rnOnBtn);
	btnRow->addWidget(rnOffBtn);
	btnRow->addWidget(rnRefreshBtn);
	btnRow->addWidget(rnImportBtn);
	btnRow->addStretch();
	layout->addLayout(btnRow);

	rnTable = setupFridaTable(page, {tr("Class"), tr("Method"), tr("Signature"), tr("Address")});
	layout->addWidget(rnTable);

	connect(rnOnBtn, &QPushButton::clicked, this, [this]() {
		if (!m_hasSession) return;
		rnOnBtn->setEnabled(false);
		FridaCmdRunner::runAsyncQuiet("fridaRNj on", this,
			[this](const QJsonObject &) { rnOnBtn->setEnabled(true); },
			[this](const QString &) { rnOnBtn->setEnabled(true); });
	});
	connect(rnOffBtn, &QPushButton::clicked, this, [this]() {
		if (!m_hasSession) return;
		rnOffBtn->setEnabled(false);
		FridaCmdRunner::runAsyncQuiet("fridaRNj off", this,
			[this](const QJsonObject &) { rnOffBtn->setEnabled(true); },
			[this](const QString &) { rnOffBtn->setEnabled(true); });
	});
	connect(rnRefreshBtn, &QPushButton::clicked, this, [this]() {
		if (!m_hasSession) return;
		rnRefreshBtn->setEnabled(false);
		FridaCmdRunner::runAsyncQuiet("fridaRNj", this,
			[this](const QJsonObject &result) {
				auto *rm = static_cast<QStandardItemModel *>(static_cast<QSortFilterProxyModel *>(rnTable->model())->sourceModel());
				rm->removeRows(0, rm->rowCount());
				for (const auto &v : result["invocations"].toArray()) {
					QJsonObject entry = v.toObject();
					QString cn = entry["className"].toString();
					for (const auto &m : entry["methods"].toArray()) {
						QJsonObject meth = m.toObject();
						rm->appendRow({makeItem(cn), makeItem(meth["name"].toString()),
							makeItem(meth["signature"].toString()), makeItem(meth["address"].toString())});
					}
				}
				rnRefreshBtn->setEnabled(true);
			}, [this](const QString &) { rnRefreshBtn->setEnabled(true); });
	});
	connect(rnImportBtn, &QPushButton::clicked, this, [this]() {
		if (!m_hasSession) return;
		rnImportBtn->setEnabled(false);
		FridaCmdRunner::runAsyncQuiet("fridaRNj import", this,
			[this](const QJsonObject &) {
				Core()->triggerRefreshAll();
				rnImportBtn->setEnabled(true);
			}, [this](const QString &) { rnImportBtn->setEnabled(true); });
	});

	tabs->addTab(page, tr("RegNat"));
}

void FridaDockWidget::setupFlagsTab()
{
	auto *page = new QWidget(this);
	auto *layout = new QVBoxLayout(page);

	flagsImportBtn = new QPushButton(tr("Import Runtime Modules as Flags"), page);
	layout->addWidget(flagsImportBtn);

	flagsOutput = new QPlainTextEdit(page);
	flagsOutput->setReadOnly(true);
	flagsOutput->setMaximumBlockCount(500);
	layout->addWidget(flagsOutput);

	connect(flagsImportBtn, &QPushButton::clicked, this, [this]() {
		if (!m_hasSession) return;
		flagsImportBtn->setEnabled(false);
		FridaCmdRunner::runAsyncQuiet("fridafj", this,
			[this](const QJsonObject &result) {
				flagsOutput->setPlainText(tr("Imported %1 module(s) into frida.libs flag space")
					.arg(result["modules"].toInt()));
				Core()->triggerRefreshAll();
				flagsImportBtn->setEnabled(true);
			}, [this](const QString &e) {
				flagsOutput->setPlainText(tr("Error: %1").arg(e));
				flagsImportBtn->setEnabled(true);
			});
	});

	tabs->addTab(page, tr("Flags"));
}

// ---- Debug tab ----

void FridaDockWidget::setupDebugTab()
{
	auto *page = new QWidget(this);
	auto *layout = new QVBoxLayout(page);

	// --- Breakpoints ---
	auto *bpGroup = new QGroupBox(tr("Breakpoints"), page);
	auto *bpLayout = new QVBoxLayout(bpGroup);

	auto *bpRow1 = new QHBoxLayout();
	bpAddrEdit = new QLineEdit(bpGroup);
	bpAddrEdit->setPlaceholderText("0x1000");
	bpSetBtn = new QPushButton(tr("Set"), bpGroup);
	bpRemoveBtn = new QPushButton(tr("Remove"), bpGroup);
	bpRemoveAllBtn = new QPushButton(tr("Remove All"), bpGroup);
	bpListBtn = new QPushButton(tr("Refresh"), bpGroup);
	bpRow1->addWidget(new QLabel(tr("Addr:"), bpGroup));
	bpRow1->addWidget(bpAddrEdit);
	bpRow1->addWidget(bpSetBtn);
	bpRow1->addWidget(bpRemoveBtn);
	bpRow1->addWidget(bpRemoveAllBtn);
	bpRow1->addWidget(bpListBtn);
	bpRow1->addStretch();
	bpLayout->addLayout(bpRow1);

	auto *bpRow2 = new QHBoxLayout();
	bpContinueTidEdit = new QLineEdit(bpGroup);
	bpContinueTidEdit->setPlaceholderText(tr("TID (blank = last)"));
	bpContinueBtn = new QPushButton(tr("Continue"), bpGroup);
	bpContinueLastBtn = new QPushButton(tr("Continue Last"), bpGroup);
	bpRow2->addWidget(new QLabel(tr("TID:"), bpGroup));
	bpRow2->addWidget(bpContinueTidEdit);
	bpRow2->addWidget(bpContinueBtn);
	bpRow2->addWidget(bpContinueLastBtn);
	bpRow2->addStretch();
	bpLayout->addLayout(bpRow2);

	bpTable = setupFridaTable(bpGroup, {tr("ID"), tr("Address")});
	bpLayout->addWidget(bpTable);
	layout->addWidget(bpGroup);

	// bp set
	connect(bpSetBtn, &QPushButton::clicked, this, [this]() {
		if (!m_hasSession) return;
		QString addr = bpAddrEdit->text().trimmed();
		if (addr.isEmpty()) return;
		bpSetBtn->setEnabled(false);
		FridaCmdRunner::runAsyncQuiet("fridabj " + addr, this,
			[this](const QJsonObject &) { bpSetBtn->setEnabled(true); bpListBtn->click(); },
			[this](const QString &e) { bpSetBtn->setEnabled(true); bpNotifyLog->appendPlainText(tr("BP Error: %1").arg(e)); });
	});

	// bp remove
	connect(bpRemoveBtn, &QPushButton::clicked, this, [this]() {
		if (!m_hasSession) return;
		QString addr = bpAddrEdit->text().trimmed();
		if (addr.isEmpty()) return;
		bpRemoveBtn->setEnabled(false);
		FridaCmdRunner::runAsyncQuiet("fridab-j " + addr, this,
			[this](const QJsonObject &) { bpRemoveBtn->setEnabled(true); bpListBtn->click(); },
			[this](const QString &e) { bpRemoveBtn->setEnabled(true); bpNotifyLog->appendPlainText(tr("BP Error: %1").arg(e)); });
	});

	// bp remove all
	connect(bpRemoveAllBtn, &QPushButton::clicked, this, [this]() {
		if (!m_hasSession) return;
		bpRemoveAllBtn->setEnabled(false);
		FridaCmdRunner::runAsyncQuiet("fridab-j *", this,
			[this](const QJsonObject &) { bpRemoveAllBtn->setEnabled(true); bpListBtn->click(); },
			[this](const QString &e) { bpRemoveAllBtn->setEnabled(true); bpNotifyLog->appendPlainText(tr("BP Error: %1").arg(e)); });
	});

	// bp list
	connect(bpListBtn, &QPushButton::clicked, this, [this]() {
		if (!m_hasSession) return;
		bpListBtn->setEnabled(false);
		FridaCmdRunner::runAsyncQuiet("fridabj", this,
			[this](const QJsonObject &result) {
				clearModel(bpTable);
				auto *bm = static_cast<QStandardItemModel *>(static_cast<QSortFilterProxyModel *>(bpTable->model())->sourceModel());
				for (const auto &v : result["breakpoints"].toArray()) {
					QJsonObject bp = v.toObject();
					bm->appendRow({makeItem(QString::number(bp["bp"].toInt())), makeItem(bp["address"].toString())});
				}
				bpListBtn->setEnabled(true);
			}, [this](const QString &) { bpListBtn->setEnabled(true); });
	});

	// bp continue
	connect(bpContinueBtn, &QPushButton::clicked, this, [this]() {
		if (!m_hasSession) return;
		QString tid = bpContinueTidEdit->text().trimmed();
		if (tid.isEmpty()) return;
		bpContinueBtn->setEnabled(false);
		FridaCmdRunner::runAsyncQuiet("fridagj " + tid, this,
			[this](const QJsonObject &result) {
				bpNotifyLog->appendPlainText(tr("Continue TID %1: resumed=%2").arg(
					QString::number(result["threadId"].toInt()),
					result["resumed"].toBool() ? "true" : "false"));
				bpContinueBtn->setEnabled(true);
				bpListBtn->click();
			}, [this](const QString &e) {
				bpNotifyLog->appendPlainText(tr("Continue Error: %1").arg(e));
				bpContinueBtn->setEnabled(true);
			});
	});

	// bp continue last
	connect(bpContinueLastBtn, &QPushButton::clicked, this, [this]() {
		if (!m_hasSession) return;
		bpContinueLastBtn->setEnabled(false);
		FridaCmdRunner::runAsyncQuiet("fridagj", this,
			[this](const QJsonObject &result) {
				bpNotifyLog->appendPlainText(tr("Continue last: resumed=%1").arg(
					result["resumed"].toBool() ? "true" : "false"));
				bpContinueLastBtn->setEnabled(true);
				bpListBtn->click();
			}, [this](const QString &e) {
				bpNotifyLog->appendPlainText(tr("Continue Error: %1").arg(e));
				bpContinueLastBtn->setEnabled(true);
			});
	});

	// --- Watchpoints ---
	auto *wpGroup = new QGroupBox(tr("Watchpoints"), page);
	auto *wpLayout = new QVBoxLayout(wpGroup);

	auto *wpRow = new QHBoxLayout();
	wpAddrEdit = new QLineEdit(wpGroup);
	wpAddrEdit->setPlaceholderText("0x1000");
	wpSizeEdit = new QLineEdit(wpGroup);
	wpSizeEdit->setPlaceholderText("8");
	wpCondCombo = new QComboBox(wpGroup);
	wpCondCombo->addItem("rw");
	wpCondCombo->addItem("w");
	wpCondCombo->addItem("r");
	wpSetBtn = new QPushButton(tr("Set"), wpGroup);
	wpRemoveBtn = new QPushButton(tr("Remove"), wpGroup);
	wpRemoveAllBtn = new QPushButton(tr("Remove All"), wpGroup);
	wpListBtn = new QPushButton(tr("Refresh"), wpGroup);
	wpRow->addWidget(new QLabel(tr("Addr:"), wpGroup));
	wpRow->addWidget(wpAddrEdit);
	wpRow->addWidget(new QLabel(tr("Size:"), wpGroup));
	wpRow->addWidget(wpSizeEdit);
	wpRow->addWidget(wpCondCombo);
	wpRow->addWidget(wpSetBtn);
	wpRow->addWidget(wpRemoveBtn);
	wpRow->addWidget(wpRemoveAllBtn);
	wpRow->addWidget(wpListBtn);
	wpRow->addStretch();
	wpLayout->addLayout(wpRow);

	wpTable = setupFridaTable(wpGroup, {tr("Slot"), tr("Address"), tr("Size"), tr("Condition")});
	wpLayout->addWidget(wpTable);
	layout->addWidget(wpGroup);

	// wp set
	connect(wpSetBtn, &QPushButton::clicked, this, [this]() {
		if (!m_hasSession) return;
		QString addr = wpAddrEdit->text().trimmed();
		if (addr.isEmpty()) return;
		QString size = wpSizeEdit->text().trimmed();
		QString cond = wpCondCombo->currentText();
		QString cmd = size.isEmpty() ? QString("fridaWj %1 %2").arg(addr, cond)
			: QString("fridaWj %1 %2 %3").arg(addr, size, cond);
		wpSetBtn->setEnabled(false);
		FridaCmdRunner::runAsyncQuiet(cmd, this,
			[this](const QJsonObject &) { wpSetBtn->setEnabled(true); wpListBtn->click(); },
			[this](const QString &e) { wpSetBtn->setEnabled(true); bpNotifyLog->appendPlainText(tr("WP Error: %1").arg(e)); });
	});

	// wp remove
	connect(wpRemoveBtn, &QPushButton::clicked, this, [this]() {
		if (!m_hasSession) return;
		QString addr = wpAddrEdit->text().trimmed();
		if (addr.isEmpty()) return;
		wpRemoveBtn->setEnabled(false);
		FridaCmdRunner::runAsyncQuiet("fridaW-j " + addr, this,
			[this](const QJsonObject &) { wpRemoveBtn->setEnabled(true); wpListBtn->click(); },
			[this](const QString &e) { wpRemoveBtn->setEnabled(true); bpNotifyLog->appendPlainText(tr("WP Error: %1").arg(e)); });
	});

	// wp remove all
	connect(wpRemoveAllBtn, &QPushButton::clicked, this, [this]() {
		if (!m_hasSession) return;
		wpRemoveAllBtn->setEnabled(false);
		FridaCmdRunner::runAsyncQuiet("fridaW-j *", this,
			[this](const QJsonObject &) { wpRemoveAllBtn->setEnabled(true); wpListBtn->click(); },
			[this](const QString &e) { wpRemoveAllBtn->setEnabled(true); bpNotifyLog->appendPlainText(tr("WP Error: %1").arg(e)); });
	});

	// wp list
	connect(wpListBtn, &QPushButton::clicked, this, [this]() {
		if (!m_hasSession) return;
		wpListBtn->setEnabled(false);
		FridaCmdRunner::runAsyncQuiet("fridaWj", this,
			[this](const QJsonObject &result) {
				clearModel(wpTable);
				auto *wm = static_cast<QStandardItemModel *>(static_cast<QSortFilterProxyModel *>(wpTable->model())->sourceModel());
				for (const auto &v : result["watchpoints"].toArray()) {
					QJsonObject wp = v.toObject();
					wm->appendRow({makeItem(QString::number(wp["slot"].toInt())), makeItem(wp["address"].toString()),
						makeItem(QString::number(wp["size"].toInt())), makeItem(wp["conditions"].toString())});
				}
				wpListBtn->setEnabled(true);
			}, [this](const QString &) { wpListBtn->setEnabled(true); });
	});

	// --- Registers ---
	auto *regGroup = new QGroupBox(tr("Registers (stopped thread)"), page);
	auto *regLayout = new QVBoxLayout(regGroup);

	auto *regRow = new QHBoxLayout();
	regTidEdit = new QLineEdit(regGroup);
	regTidEdit->setPlaceholderText(tr("Thread ID"));
	regReadBtn = new QPushButton(tr("Read"), regGroup);
	regRow->addWidget(new QLabel(tr("TID:"), regGroup));
	regRow->addWidget(regTidEdit);
	regRow->addWidget(regReadBtn);
	regRow->addStretch();
	regLayout->addLayout(regRow);

	regTable = setupFridaTable(regGroup, {tr("Register"), tr("Value")});
	regLayout->addWidget(regTable);

	auto *regWriteRow = new QHBoxLayout();
	regNameEdit = new QLineEdit(regGroup);
	regNameEdit->setPlaceholderText(tr("reg name, e.g. pc"));
	regValueEdit = new QLineEdit(regGroup);
	regValueEdit->setPlaceholderText("0x401000");
	regWriteBtn = new QPushButton(tr("Write"), regGroup);
	regWriteRow->addWidget(new QLabel(tr("Reg:"), regGroup));
	regWriteRow->addWidget(regNameEdit);
	regWriteRow->addWidget(new QLabel(tr("Val:"), regGroup));
	regWriteRow->addWidget(regValueEdit);
	regWriteRow->addWidget(regWriteBtn);
	regWriteRow->addStretch();
	regLayout->addLayout(regWriteRow);
	layout->addWidget(regGroup);

	// reg read
	connect(regReadBtn, &QPushButton::clicked, this, [this]() {
		if (!m_hasSession) return;
		QString tid = regTidEdit->text().trimmed();
		if (tid.isEmpty()) return;
		regReadBtn->setEnabled(false);
		FridaCmdRunner::runAsyncQuiet("fridaBj " + tid, this,
			[this](const QJsonObject &result) {
				clearModel(regTable);
				auto *rm = static_cast<QStandardItemModel *>(static_cast<QSortFilterProxyModel *>(regTable->model())->sourceModel());
				// response: {threadId, bp, address}, context isn't returned directly
				// but we can just show the stopped thread info
				rm->appendRow({makeItem("threadId"), makeItem(QString::number(result["threadId"].toInt()))});
				rm->appendRow({makeItem("bp"), makeItem(QString::number(result["bp"].toInt()))});
				rm->appendRow({makeItem("address"), makeItem(result["address"].toString())});
				// also read the context from msgs
				regReadBtn->setEnabled(true);
			}, [this](const QString &e) {
				regReadBtn->setEnabled(true);
				bpNotifyLog->appendPlainText(tr("Reg Error: %1").arg(e));
			});
	});

	// reg write
	connect(regWriteBtn, &QPushButton::clicked, this, [this]() {
		if (!m_hasSession) return;
		QString tid = regTidEdit->text().trimmed();
		QString reg = regNameEdit->text().trimmed();
		QString val = regValueEdit->text().trimmed();
		if (tid.isEmpty() || reg.isEmpty() || val.isEmpty()) return;
		regWriteBtn->setEnabled(false);
		FridaCmdRunner::runAsyncQuiet(QString("fridaBj %1 %2 %3").arg(tid, reg, val), this,
			[this](const QJsonObject &result) {
				bpNotifyLog->appendPlainText(tr("Write %1 = %2").arg(
					result["register"].toString(), result["value"].toString()));
				regWriteBtn->setEnabled(true);
				regReadBtn->click();
			}, [this](const QString &e) {
				bpNotifyLog->appendPlainText(tr("Reg Write Error: %1").arg(e));
				regWriteBtn->setEnabled(true);
			});
	});

	// --- Notification log ---
	auto *notifyGroup = new QGroupBox(tr("Break / Watchpoint Notifications"), page);
	auto *notifyLayout = new QVBoxLayout(notifyGroup);
	bpNotifyLog = new QPlainTextEdit(notifyGroup);
	bpNotifyLog->setReadOnly(true);
	bpNotifyLog->setMaximumBlockCount(500);
	notifyLayout->addWidget(bpNotifyLog);
	layout->addWidget(notifyGroup);

	// check messages for bp/wp notifs
	connect(bpListBtn, &QPushButton::clicked, this, [this]() {
		if (!m_hasSession) return;
		FridaCmdRunner::runAsyncQuiet("fridamj", this,
			[this](const QJsonObject &result) {
				for (const auto &m : result["messages"].toArray()) {
					QJsonObject msg = m.toObject();
					QString payload = QJsonDocument(msg["payload"].toObject()).toJson(QJsonDocument::Compact);
					if (payload.contains("frida.bp") || payload.contains("frida.wp")) {
						bpNotifyLog->appendPlainText(QString("[%1] %2").arg(
							msg["type"].toString(), payload));
					}
				}
			}, [this](const QString &) {});
	});

	tabs->addTab(page, tr("Debug"));
}

// ---- helpers ----

QTableView *FridaDockWidget::setupFridaTable(QWidget *parent, const QStringList &headers)
{
	auto *model = new QStandardItemModel(0, headers.size(), parent);
	for (int i = 0; i < headers.size(); i++) {
		model->setHeaderData(i, Qt::Horizontal, headers[i]);
	}
	auto *proxy = new QSortFilterProxyModel(parent);
	proxy->setSourceModel(model);

	auto *view = new QTableView(parent);
	view->setModel(proxy);
	view->setSortingEnabled(true);
	view->setSelectionBehavior(QAbstractItemView::SelectRows);
	view->setEditTriggers(QAbstractItemView::NoEditTriggers);
	view->horizontalHeader()->setStretchLastSection(true);
	view->verticalHeader()->setVisible(false);
	view->setAlternatingRowColors(true);
	return view;
}
