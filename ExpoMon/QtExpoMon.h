/****************************************************************************

    MIT License

    Copyright (c) 2023 milCERT

    Permission is hereby granted, free of charge, to any person obtaining a 
    copy of this software and associated documentation files (the "Software"), 
    to deal in the Software without restriction, including without limitation 
    the rights to use, copy, modify, merge, publish, distribute, sublicense, 
    and/or sell copies of the Software, and to permit persons to whom the 
    Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included 
    in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS 
    OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, 
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL 
    THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER 
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, 
    ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR 
    OTHER DEALINGS IN THE SOFTWARE.

****************************************************************************/

#ifndef _QTExpoMon_H_
#define _QTExpoMon_H_

/***************************************************************************/

/* StdLib */
#include <functional>
#include <string>

/* Qt Lib */
#include <QtWidgets/QMainWindow>
#include <QMessageBox>
#include <QDesktopWidget>
#include <QLabel>
#include <QStringList>
#include <QClipboard>
#include <QShortcut>
#include <QScopedPointer>
#include <QSharedPointer>
#include <QDateTime>
#include <QScopedArrayPointer>
#include <QFont>
#include <QMenu>
#include <QLineEdit>
#include <QBuffer>

#if 0

	#include <QMediaPlayer>
	#include <QSound>

#endif

/* Qt Generated Headers */
#include "ui_QtExpoMon.h"

/* MSVC resources */
#include "resource.h"

/***************************************************************************/

#define Menu_Type_Root		    (QTreeWidgetItem::UserType + 0)
#define Menu_Type_Regs		    (QTreeWidgetItem::UserType + 1)
#define Menu_Type_Callstack     (QTreeWidgetItem::UserType + 2)

/***************************************************************************/

struct QCustomAction
{
    std::function<void(QTreeWidget*)> Func;
};

Q_DECLARE_METATYPE(QCustomAction)

/***************************************************************************/

class QChildTreeWidgetItem : public QTreeWidgetItem
{
public:

    explicit QChildTreeWidgetItem(int type = Type) : 
        QTreeWidgetItem(type) {};

    explicit QChildTreeWidgetItem(const QStringList &strings, int type = Type) : 
        QTreeWidgetItem(strings, type) {};

public:

    /* Child items should be unsortable */
    bool operator<(const QTreeWidgetItem &other) const
    {
        return false;
    }
};

/***************************************************************************/

class QtExpoMon : public QMainWindow
{
	Q_OBJECT

public:
	QtExpoMon(QWidget *parent = Q_NULLPTR);
	~QtExpoMon();

public:
	void LogMessage(QString msg);

private:
    QAction* CreateCustomAction(const QString& Text, 
        const std::function<void(QTreeWidget*)>& Func);
    void ResetFilter(QTreeWidget* TreeWidget);
    void ApplyFilter(QTreeWidget* TreeWidget, QString& Filters, std::vector<int> Columns);

private slots:
    void on_BtnDisEnableMonitor_clicked();
	void on_BtnStartStop_clicked();
    void on_BtnReset_clicked();
    void on_BtnAccessFilter_clicked();
    void on_BtnHijackFilter_clicked();
	void on_CbBreak_toggled();
    void on_CbMonitorCond_toggled();
    void on_CbHijack_toggled();
    void on_CbBreakHijack_toggled();
    void on_ClickContextMenuItem(QAction* Action);
	void on_CustomContextMenuRequested(const QPoint &Pos);
	void on_LstLog_customContextMenuRequested(const QPoint &Pos);
	void on_CopyLogToClipboard();

private:
    /* Menus for TreeWidget Exports Access and TreeWidget Exports Hijacked */
    struct 
    {
        QMenu RootExpAccess;
        QMenu RootExpHijack;
        QMenu Regs;
	    QMenu Callstack;
    } Menus;
	
    /* Menu for the log ListWidget */
	QMenu MenuLog;

protected:
    void showEvent(QShowEvent* Event) override;

public:
	Ui::ExpoMonClass ui;

	/* Log */
	QVector<QSharedPointer<QShortcut>> LogShortcuts;
};

/***************************************************************************/

#endif // _QTExpoMon_H_