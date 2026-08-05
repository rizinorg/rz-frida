// SPDX-FileCopyrightText: 2026 Alok Kumar Mishra <alok16022006@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef FRIDA_CONNECT_DIALOG_H
#define FRIDA_CONNECT_DIALOG_H

#include <QDialog>
#include <QComboBox>
#include <QLineEdit>
#include <QRadioButton>
#include <QLabel>
#include <QPushButton>
#include <QDialogButtonBox>
#include <QSettings>

#include "FridaDescriptions.h"
#include "FridaApiBridge.h"

class FridaConnectDialog : public QDialog
{
	Q_OBJECT

public:
	explicit FridaConnectDialog(QWidget *parent = nullptr);
	~FridaConnectDialog() override = default;

	QString action() const;
	QString transport() const;
	QString device() const;
	QString target() const;
	bool validate();
	void setApi(FridaApiBridge *api);

private slots:
	void onTransportChanged();
	void onRefreshDevices();
	void onRefreshTargets();
	void onAccepted();

private:
	QRadioButton *localRadio;
	QRadioButton *usbRadio;
	QRadioButton *remoteRadio;
	QLineEdit *hostPortEdit;
	QComboBox *deviceCombo;
	QPushButton *refreshDevicesBtn;
	QComboBox *targetTypeCombo;
	QLineEdit *targetEdit;
	QPushButton *refreshTargetsBtn;
	QRadioButton *attachRadio;
	QRadioButton *spawnRadio;
	QRadioButton *launchRadio;
	QDialogButtonBox *buttonBox;
	QLabel *statusLabel;

	QList<FridaDevice> m_devices;
	QList<FridaProcess> m_processes;
	QList<FridaApp> m_apps;

	FridaApiBridge *m_api = nullptr;

	void restoreSettings();
	void saveSettings();
};

#endif // FRIDA_CONNECT_DIALOG_H
