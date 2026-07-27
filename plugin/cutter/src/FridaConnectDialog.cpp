// SPDX-FileCopyrightText: 2026 Alok Kumar Mishra <alok16022006@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "FridaConnectDialog.h"
#include "FridaCmdRunner.h"

#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QGroupBox>
#include <QJsonArray>
#include <QJsonObject>

FridaConnectDialog::FridaConnectDialog(QWidget *parent)
	: QDialog(parent)
{
	setWindowTitle(tr("Connect to Frida Device"));
	setMinimumWidth(480);
	setWindowFlags(windowFlags() & ~Qt::WindowContextHelpButtonHint);

	auto *mainLayout = new QVBoxLayout(this);

	auto *transportGroup = new QGroupBox(tr("Transport"), this);
	auto *transportLayout = new QVBoxLayout(transportGroup);
	localRadio = new QRadioButton(tr("Local"), transportGroup);
	usbRadio = new QRadioButton(tr("USB"), transportGroup);
	remoteRadio = new QRadioButton(tr("Remote"), transportGroup);
	auto *remoteLayout = new QHBoxLayout();
	remoteLayout->addWidget(new QLabel(tr("host:port"), transportGroup));
	hostPortEdit = new QLineEdit(transportGroup);
	hostPortEdit->setPlaceholderText("127.0.0.1:27042");
	hostPortEdit->setVisible(false);
	remoteLayout->addWidget(hostPortEdit);
	transportLayout->addWidget(localRadio);
	transportLayout->addWidget(usbRadio);
	transportLayout->addWidget(remoteRadio);
	transportLayout->addLayout(remoteLayout);
	mainLayout->addWidget(transportGroup);

	auto *deviceGroup = new QGroupBox(tr("Device"), this);
	auto *deviceLayout = new QVBoxLayout(deviceGroup);
	auto *deviceRow = new QHBoxLayout();
	deviceCombo = new QComboBox(deviceGroup);
	deviceCombo->setMinimumWidth(300);
	deviceRow->addWidget(deviceCombo);
	refreshDevicesBtn = new QPushButton(tr("Refresh"), deviceGroup);
	deviceRow->addWidget(refreshDevicesBtn);
	deviceLayout->addLayout(deviceRow);
	mainLayout->addWidget(deviceGroup);

	auto *targetGroup = new QGroupBox(tr("Target"), this);
	auto *targetLayout = new QVBoxLayout(targetGroup);
	auto *targetRow = new QHBoxLayout();
	targetTypeCombo = new QComboBox(targetGroup);
	targetTypeCombo->addItem(tr("PID / Process Name"), "process");
	targetTypeCombo->addItem(tr("Package Name"), "package");
	targetRow->addWidget(targetTypeCombo);
	targetEdit = new QLineEdit(targetGroup);
	targetRow->addWidget(targetEdit);
	refreshTargetsBtn = new QPushButton(tr("Refresh"), targetGroup);
	targetRow->addWidget(refreshTargetsBtn);
	targetLayout->addLayout(targetRow);
	mainLayout->addWidget(targetGroup);

	auto *actionGroup = new QGroupBox(tr("Action"), this);
	auto *actionLayout = new QHBoxLayout(actionGroup);
	attachRadio = new QRadioButton(tr("Attach"), actionGroup);
	spawnRadio = new QRadioButton(tr("Spawn"), actionGroup);
	launchRadio = new QRadioButton(tr("Launch"), actionGroup);
	attachRadio->setChecked(true);
	actionLayout->addWidget(attachRadio);
	actionLayout->addWidget(spawnRadio);
	actionLayout->addWidget(launchRadio);
	mainLayout->addWidget(actionGroup);

	statusLabel = new QLabel(this);
	mainLayout->addWidget(statusLabel);

	buttonBox = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, this);
	buttonBox->button(QDialogButtonBox::Ok)->setText(tr("Connect"));
	mainLayout->addWidget(buttonBox);

	connect(remoteRadio, &QRadioButton::toggled, this, &FridaConnectDialog::onTransportChanged);
	connect(refreshDevicesBtn, &QPushButton::clicked, this, &FridaConnectDialog::onRefreshDevices);
	connect(refreshTargetsBtn, &QPushButton::clicked, this, &FridaConnectDialog::onRefreshTargets);
	connect(buttonBox, &QDialogButtonBox::accepted, this, &FridaConnectDialog::onAccepted);
	connect(buttonBox, &QDialogButtonBox::rejected, this, &QDialog::reject);

	restoreSettings();
}

static QString deviceForTransport(QRadioButton *localRadio, QRadioButton *remoteRadio,
	QLineEdit *hostPortEdit, QComboBox *deviceCombo, const QList<FridaDevice> &m_devices)
{
	if (localRadio->isChecked())
		return QString();
	if (remoteRadio->isChecked())
		return hostPortEdit->text();
	int idx = deviceCombo->currentIndex();
	if (idx >= 0 && idx < m_devices.size())
		return m_devices[idx].id;
	return QString();
}

QString FridaConnectDialog::getUri() const
{
	QString action = attachRadio->isChecked() ? "attach" : spawnRadio->isChecked() ? "spawn" : "launch";
	QString transport = localRadio->isChecked() ? "local" : usbRadio->isChecked() ? "usb" : "remote";
	QString device = deviceForTransport(localRadio, remoteRadio, hostPortEdit, deviceCombo, m_devices);
	return QString("frida://%1/%2/%3/%4").arg(action, transport, device, targetEdit->text().trimmed());
}

QString FridaConnectDialog::getCommand() const
{
	QString action = attachRadio->isChecked() ? "attach" : spawnRadio->isChecked() ? "spawn" : "launch";
	QString transport = localRadio->isChecked() ? "local" : usbRadio->isChecked() ? "usb" : "remote";
	QString device = deviceForTransport(localRadio, remoteRadio, hostPortEdit, deviceCombo, m_devices);
	return QString("fridaoj %1/%2/%3/%4").arg(action, transport, device, targetEdit->text().trimmed());
}

bool FridaConnectDialog::validate()
{
	if (remoteRadio->isChecked() && hostPortEdit->text().isEmpty()) {
		statusLabel->setText(tr("host:port is required for remote transport"));
		return false;
	}
	if (targetEdit->text().trimmed().isEmpty()) {
		statusLabel->setText(tr("target must not be empty"));
		return false;
	}
	return true;
}

void FridaConnectDialog::onTransportChanged()
{
	bool remote = remoteRadio->isChecked();
	hostPortEdit->setVisible(remote);
	deviceCombo->setEnabled(!remote);
	refreshDevicesBtn->setEnabled(!remote);
}

void FridaConnectDialog::onRefreshDevices()
{
	statusLabel->setText(tr("Refreshing devices..."));
	try {
		QJsonObject result = FridaCmdRunner::runSync("fridadj");
		QJsonArray devices = result["devices"].toArray();
		m_devices.clear();
		deviceCombo->clear();
		for (const auto &d : devices) {
			QJsonObject dev = d.toObject();
			FridaDevice fd;
			fd.name = dev["name"].toString();
			fd.id = dev["id"].toString();
			fd.type = dev["type"].toString();
			m_devices.append(fd);
			deviceCombo->addItem(QString("%1 (%2)").arg(fd.name, fd.type), fd.id);
		}
		statusLabel->setText(m_devices.isEmpty() ? tr("No devices found") :
			tr("%1 device(s) found").arg(m_devices.size()));
	} catch (const QString &err) {
		statusLabel->setText(tr("Error: %1").arg(err));
	} catch (...) {
		statusLabel->setText(tr("Unknown error refreshing devices"));
	}
}

void FridaConnectDialog::onRefreshTargets()
{
	statusLabel->setText(tr("Refreshing targets..."));
	QString transport = localRadio->isChecked() ? "local" : usbRadio->isChecked() ? "usb" : "remote";
	QString device;
	if (localRadio->isChecked()) {
		device = QString();
	} else if (remoteRadio->isChecked()) {
		device = hostPortEdit->text();
	} else {
		int idx = deviceCombo->currentIndex();
		if (idx >= 0 && idx < m_devices.size())
			device = m_devices[idx].id;
	}
	QString uri = QString("frida://list/%1/%2/").arg(transport, device);
	QString cmd = (targetTypeCombo->currentData().toString() == "package") ? ("fridaaj " + uri) : ("fridapj " + uri);
	try {
		QJsonObject result = FridaCmdRunner::runSync(cmd);
		if (targetTypeCombo->currentData().toString() == "package") {
			QJsonArray apps = result["apps"].toArray();
			m_apps.clear();
			for (const auto &a : apps) {
				QJsonObject app = a.toObject();
				FridaApp fa;
				fa.name = app["name"].toString();
				fa.identifier = app["identifier"].toString();
				fa.pid = app["pid"].toInt();
				m_apps.append(fa);
			}
			statusLabel->setText(m_apps.isEmpty() ? tr("No apps found") : tr("%1 app(s) found").arg(m_apps.size()));
		} else {
			QJsonArray procs = result["processes"].toArray();
			m_processes.clear();
			for (const auto &p : procs) {
				QJsonObject proc = p.toObject();
				FridaProcess fp;
				fp.pid = proc["pid"].toInt();
				fp.name = proc["name"].toString();
				fp.path = proc["path"].toString();
				m_processes.append(fp);
			}
			statusLabel->setText(m_processes.isEmpty() ? tr("No processes found") : tr("%1 process(es) found").arg(m_processes.size()));
		}
	} catch (const QString &err) {
		statusLabel->setText(tr("Error: %1").arg(err));
	} catch (...) {
		statusLabel->setText(tr("Unknown error refreshing targets"));
	}
}

void FridaConnectDialog::onAccepted()
{
	if (!validate()) return;
	saveSettings();
	accept();
}

void FridaConnectDialog::restoreSettings()
{
	QSettings settings("rizinorg", "rz-frida");
	QString lastTransport = settings.value("connect/transport", "usb").toString();
	if (lastTransport == "local") localRadio->setChecked(true);
	else if (lastTransport == "usb") usbRadio->setChecked(true);
	else remoteRadio->setChecked(true);
	hostPortEdit->setText(settings.value("connect/hostport").toString());
	targetEdit->setText(settings.value("connect/target").toString());
}

void FridaConnectDialog::saveSettings()
{
	QSettings settings("rizinorg", "rz-frida");
	settings.setValue("connect/transport",
		localRadio->isChecked() ? "local" : usbRadio->isChecked() ? "usb" : "remote");
	settings.setValue("connect/hostport", hostPortEdit->text());
	settings.setValue("connect/target", targetEdit->text());
}
