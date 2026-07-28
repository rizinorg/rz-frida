// SPDX-FileCopyrightText: 2026 Alok Kumar Mishra <alok16022006@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef FRIDA_DOCK_WIDGET_H
#define FRIDA_DOCK_WIDGET_H

#include <QTabWidget>
#include <QTableView>
#include <QPlainTextEdit>
#include <QLineEdit>
#include <QComboBox>
#include <QLabel>
#include <QPushButton>
#include <QGroupBox>

#include <widgets/CutterDockWidget.h>
#include <core/Cutter.h>
#include <core/MainWindow.h>

#include "FridaDescriptions.h"

class FridaDockWidget : public CutterDockWidget
{
	Q_OBJECT

public:
	explicit FridaDockWidget(MainWindow *main);
	~FridaDockWidget() override = default;

private slots:
	void onConnectClicked();
	void onDisconnectClicked();
	void refreshAll();
	void updateSessionState();

private:
	/// status bar widgets
	QLabel *sessionLabel;
	QLabel *targetLabel;
	QLabel *agentLabel;
	QPushButton *connectButton;
	QPushButton *disconnectButton;
	bool m_hasSession;

	/// tab container
	QTabWidget *tabs;

	/// ----- Session tab -----
	void setupSessionTab();
	QComboBox *transportCombo_session;
	QLineEdit *hostPortEdit_session;
	QComboBox *deviceCombo_session;
	QPushButton *refreshDevicesBtn_session;
	QComboBox *targetTypeCombo_session;
	QLineEdit *targetEdit_session;
	QPushButton *refreshTargetsBtn_session;
	QComboBox *actionCombo_session;
	QList<FridaDevice> m_devices;
	QList<FridaProcess> m_processes;

	/// ----- Runtime tab -----
	void setupRuntimeTab();
	QTableView *rangesTable;
	QTableView *modulesTable;
	QTableView *threadsTable;
	QLineEdit *memAddrEdit;
	QLineEdit *memSizeEdit;
	QPlainTextEdit *memOutput;
	QLineEdit *memHexEdit;
	/// module detail
	QTableView *moduleDetailTable;
	QPushButton *modExportsBtn;
	QPushButton *modImportsBtn;
	QPushButton *modSymbolsBtn;

	/// ----- Java tab -----
	void setupJavaTab();
	QTableView *loaderTable;
	QLineEdit *prefixFilter;
	QTableView *classTable;
	QPushButton *describeBtn;
	QPushButton *importBtn;
	QPlainTextEdit *classDetailOutput;
	/// class load monitor
	QLabel *clmStatusLabel;
	QPushButton *clmStartBtn;
	QPushButton *clmStopBtn;
	QPushButton *clmRefreshBtn;
	QTableView *clmTable;

	/// ----- Script tab -----
	void setupScriptTab();
	QLineEdit *scriptPathEdit;
	QPushButton *scriptBrowseBtn;
	QPushButton *scriptLoadBtn;
	QPlainTextEdit *evalInput;
	QPushButton *evalBtn;
	QPlainTextEdit *scriptOutput;

	/// ----- Messages tab -----
	void setupMessagesTab();
	QPlainTextEdit *messageLog;
	QLabel *droppedLabel;
	QPushButton *messagesRefreshBtn;

	/// ----- DEX Diff tab -----
	void setupDexDiffTab();
	QLineEdit *dexPrefixEdit;
	QPushButton *dexCompareBtn;
	QLabel *dexLoadedBinLabel;
	QLabel *dexOnlyStaticLabel;
	QLabel *dexOnlyRuntimeLabel;
	QLabel *dexBothLabel;

	/// ----- RN (RegisterNatives) tab -----
	void setupRnTab();
	QPushButton *rnOnBtn;
	QPushButton *rnOffBtn;
	QPushButton *rnImportBtn;
	QPushButton *rnRefreshBtn;
	QTableView *rnTable;

	/// ----- Flags (Frida Libs) tab -----
	void setupFlagsTab();
	QPushButton *flagsImportBtn;
	QPlainTextEdit *flagsOutput;

	/// ----- Debug tab -----
	void setupDebugTab();
	QLineEdit *bpAddrEdit;
	QPushButton *bpSetBtn;
	QPushButton *bpRemoveBtn;
	QPushButton *bpRemoveAllBtn;
	QPushButton *bpListBtn;
	QTableView *bpTable;
	QLineEdit *bpContinueTidEdit;
	QPushButton *bpContinueBtn;
	QPushButton *bpContinueLastBtn;
	QLineEdit *wpAddrEdit;
	QLineEdit *wpSizeEdit;
	QComboBox *wpCondCombo;
	QPushButton *wpSetBtn;
	QPushButton *wpRemoveBtn;
	QPushButton *wpRemoveAllBtn;
	QPushButton *wpListBtn;
	QTableView *wpTable;
	QLineEdit *regTidEdit;
	QPushButton *regReadBtn;
	QTableView *regTable;
	QLineEdit *regNameEdit;
	QLineEdit *regValueEdit;
	QPushButton *regWriteBtn;
	QPlainTextEdit *bpNotifyLog;

	/// common helpers
	void setSessionEnabled(bool enabled);

	QTableView *setupFridaTable(QWidget *parent, const QStringList &headers);
};

#endif // FRIDA_DOCK_WIDGET_H
