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

/* Graphical (Qt) objects */
#include "QtExpoMon.h"

/* Plugin logic */
#include "ExpoMon.h"
#include "Utils.h"

/***************************************************************************/

QtExpoMon::QtExpoMon(QWidget *parent) : QMainWindow(parent)
{
    std::function<void(QTreeWidget*)> ActionFunc;

    ui.setupUi(this);

    ui.LstLog->setSelectionMode(QAbstractItemView::ExtendedSelection);

    ui.TreeExpAccessed->setContextMenuPolicy(Qt::CustomContextMenu);
    ui.TreeExpAccessed->setFont(QFont("Consolas", 10));

    ui.TreeExpHijacked->setContextMenuPolicy(Qt::CustomContextMenu);
    ui.TreeExpHijacked->setFont(QFont("Consolas", 10));

    /* Could also use QKeySequence("Ctrl+C") */
    LogShortcuts.push_back(QSharedPointer<QShortcut>(
        new QShortcut(QKeySequence::Copy, ui.LstLog)));

    connect(LogShortcuts[0].data(), SIGNAL(activated()), 
        this, SLOT(on_CopyLogToClipboard()));

    connect(ui.EditAccessFilter, SIGNAL(returnPressed()), 
        this, SLOT(on_BtnAccessFilter_clicked()));

    connect(ui.EditHijackFilter, SIGNAL(returnPressed()), 
        this, SLOT(on_BtnHijackFilter_clicked()));

    connect(&Menus.RootExpAccess, SIGNAL(triggered(QAction*)), 
        this, SLOT(on_ClickContextMenuItem(QAction*)));

    connect(&Menus.Regs, SIGNAL(triggered(QAction*)), 
        this, SLOT(on_ClickContextMenuItem(QAction*)));

    connect(&Menus.Callstack, SIGNAL(triggered(QAction*)), 
        this, SLOT(on_ClickContextMenuItem(QAction*)));

    /* 
        Not needed if QMetaObject::connectSlotsByName() is called 
            -> multiple signal connects = multiple calls on events! 
    */
    connect(ui.TreeExpAccessed, SIGNAL(customContextMenuRequested(QPoint)),
        this, SLOT(on_CustomContextMenuRequested(QPoint)));

    connect(ui.TreeExpHijacked, SIGNAL(customContextMenuRequested(QPoint)),
        this, SLOT(on_CustomContextMenuRequested(QPoint)));

    /* Display the version */
    LogMessage(QString("%1 (%2) %3")
        .arg(ExpoMon_PLUGIN_NAME_LONG)
        .arg(ExpoMon_PLUGIN_NAME_SHORT)
        .arg(ExpoMon_VERSION_STR));

    ExpoMon::IsEnabled = FALSE;
    ExpoMon::IsStarted = FALSE;

    ui.BtnDisEnableMonitor->setEnabled(false);

    /* Setup the Accessed Exports TableWidgets */
    ui.TreeExpAccessed->setSortingEnabled(true);
    ui.TreeExpAccessed->setColumnCount(7);

    ui.TreeExpAccessed->setHeaderLabels({ "", "Function Name", "Module Name", 
        "From Address", "From Module", "Thread Id", "Access Operation"});

#if 0

    /* Note: this prevents interactive resizing */
    for (int i = 0; i < ui.TreeExpAccessed->columnCount(); i++)
        ui.TreeExpAccessed->header()->setSectionResizeMode(i, QHeaderView::ResizeToContents);

#endif

    /* Setup the Hijacked Exports TableWidgets */
    ui.TreeExpHijacked->setSortingEnabled(true);
    ui.TreeExpHijacked->setColumnCount(7);

    ui.TreeExpHijacked->setHeaderLabels({ "", "Function Name", "Module Name", 
        "Return Address", "Return Module", "Thread Id", "Access Operation"});

    /* Setup the menu that is invoked on right-clicking on a root item */
    Menus.RootExpAccess.addAction(CreateCustomAction(QString("Follow in Disassembler"), 
        [this](QTreeWidget* TreeWidget) { 
            auto Item = TreeWidget->currentItem();
            if (Item != nullptr)
            {
                std::string Address = Item->text(3).toStdString();
                DbgCmdExec(Utils::StringFormat(
                    "disasm %s", Address.c_str()).c_str());
            }
    }));

    Menus.RootExpAccess.addAction(CreateCustomAction(QString("Follow in Memory Map"), 
        [this](QTreeWidget* TreeWidget) {  
            auto Item = TreeWidget->currentItem();
            if (Item != nullptr)
            {
                std::string Address = Item->text(3).toStdString();
                DbgCmdExec(Utils::StringFormat(
                    "memmapdump %s", Address.c_str()).c_str());
            }
    }));

    Menus.RootExpAccess.addSeparator();

    Menus.RootExpAccess.addAction(CreateCustomAction(QString("Copy <Function Name>"), 
        [this](QTreeWidget* TreeWidget) {  
            auto Item = TreeWidget->currentItem();
            if (Item != nullptr)
                QApplication::clipboard()->setText(Item->text(1));
    }));

    Menus.RootExpAccess.addAction(CreateCustomAction(QString("Copy <Module Name>"), 
        [this](QTreeWidget* TreeWidget) {  
            auto Item = TreeWidget->currentItem();
            if (Item != nullptr)
                QApplication::clipboard()->setText(Item->text(2));
    }));

    ActionFunc = [this](QTreeWidget* TreeWidget) {   
        auto Item = TreeWidget->currentItem();
        if (Item != nullptr)
            QApplication::clipboard()->setText(Item->text(3));
    };

    Menus.RootExpAccess.addAction(CreateCustomAction(QString("Copy <From Address>"), ActionFunc));
    Menus.RootExpHijack.addAction(CreateCustomAction(QString("Copy <Return Address>"), ActionFunc));

    ActionFunc = [this](QTreeWidget* TreeWidget) {   
        auto Item = TreeWidget->currentItem();
        if (Item != nullptr)
            QApplication::clipboard()->setText(Item->text(4));
    };

    Menus.RootExpAccess.addAction(CreateCustomAction(QString("Copy <From Module>"), ActionFunc));
    Menus.RootExpHijack.addAction(CreateCustomAction(QString("Copy <Return Module>"), ActionFunc));

    Menus.RootExpAccess.addAction(CreateCustomAction(QString("Copy <Thread Id>"), 
        [this](QTreeWidget* TreeWidget) {   
            auto Item = TreeWidget->currentItem();
            if (Item != nullptr)
                QApplication::clipboard()->setText(Item->text(5));
    }));

    Menus.RootExpAccess.addSeparator();

    Menus.RootExpAccess.addAction(CreateCustomAction(QString("Collapse All"), 
        [this](QTreeWidget* TreeWidget) {   
            TreeWidget->collapseAll(); 
    }));

    Menus.RootExpAccess.addAction(CreateCustomAction(QString("Expand All"), 
        [this](QTreeWidget* TreeWidget) {   
            TreeWidget->expandAll(); 
    }));

    Menus.RootExpAccess.addAction(CreateCustomAction(QString("Clear"), 
        [this](QTreeWidget* TreeWidget) {  
            TreeWidget->clear(); 
    }));

    /* Setup the menu that is invoked on right-clicking on a register child item */
    Menus.Regs.addAction(CreateCustomAction(QString("Copy"), [this](QTreeWidget* TreeWidget) {   
        auto Item = TreeWidget->currentItem();
        if (Item != nullptr)
            QApplication::clipboard()->setText(Item->text(1));
    }));

    /* Setup the menu that is invoked on right-clicking on a callstack child item */
    Menus.Callstack.addAction(CreateCustomAction(QString("Follow in Disassembler"), 
        [this](QTreeWidget* TreeWidget) {   
            auto Item = TreeWidget->currentItem();
            if (Item != nullptr)
            {
                std::string Address = ExpoMon::GetStringAfterChr(
                    Item->text(1).toStdString(), ".");

                DbgCmdExec(Utils::StringFormat(
                    "disasm %s", Address.c_str()).c_str());
            }
    }));

    Menus.Callstack.addAction(CreateCustomAction(QString("Add <Function Name> to comment at address"), 
        [this](QTreeWidget* TreeWidget) {  
            auto Item = TreeWidget->currentItem();
            if (Item != nullptr &&
                Item->parent() != nullptr && 
                Item->parent()->parent() != nullptr)
            {
                bool ValidEval = false;

                duint Address = DbgEval(ExpoMon::GetStringAfterChr(
                    Item->text(1).toStdString(), ".").c_str(), &ValidEval);

                std::string FunctionName = Item->parent()->parent()->text(1).toStdString();

                if (ValidEval)
                {
                    char Buffer[MAX_COMMENT_SIZE];
                
                    Script::Comment::CommentInfo CommentInfo = { 0 };
                    Script::Comment::GetInfo(Address, &CommentInfo);
  
                    if (!CommentInfo.manual)
                    {
                        DbgSetCommentAt(Address, FunctionName.c_str());
                    }
                    else
                    {
                        DbgGetCommentAt(Address, Buffer);

                        if (strlen(Buffer) > 0)
                            strcat_s(Buffer, MAX_COMMENT_SIZE, ", ");

                        strcat_s(Buffer, MAX_COMMENT_SIZE, FunctionName.c_str());

                        DbgSetCommentAt(Address, Buffer);
                    }
                }
            }
    }));

    Menus.Callstack.addAction(CreateCustomAction(QString("Reset comment at address"), 
        [this](QTreeWidget* TreeWidget) {   
            auto Item = TreeWidget->currentItem();
            if (Item != nullptr)
            {
                bool ValidEval = false;

                duint Address = DbgEval(ExpoMon::GetStringAfterChr(
                    Item->text(1).toStdString(), ".").c_str(), &ValidEval);

                if (ValidEval)
                {
                    DbgSetCommentAt(Address, "");
                }
            }
    }));

    Menus.Callstack.addAction(CreateCustomAction(QString("Copy"), 
        [this](QTreeWidget* TreeWidget) {   
            auto Item = TreeWidget->currentItem();
            if (Item != nullptr)
                QApplication::clipboard()->setText(Item->text(1));
    }));

    /* Setup the menu for the Log list */
    MenuLog.addAction(QString("Copy"), this, [this]() {  
        on_CopyLogToClipboard();
    });

    MenuLog.addAction(QString("Clear"), this, [this]() {  
        ui.LstLog->clear(); 
    });
}

QtExpoMon::~QtExpoMon()
{

}

void QtExpoMon::showEvent(QShowEvent* Event)
{
    static bool ScaledColSize = false;

    if (!ScaledColSize)
    {
        int Width = ui.TreeExpAccessed->size().width();

        std::vector<QTreeWidget*> TreeWidgets = {
            ui.TreeExpAccessed,
            ui.TreeExpHijacked
        };

        for (auto& TreeWidget : TreeWidgets)
        {
            TreeWidget->header()->resizeSection(0, Width * 10/100);
            TreeWidget->header()->resizeSection(1, Width * 20/100);
            TreeWidget->header()->resizeSection(2, Width * 20/100);
            TreeWidget->header()->resizeSection(3, Width * 15/100);
            TreeWidget->header()->resizeSection(4, Width * 15/100);
        }

        ScaledColSize = true;
    }

    /* Call the base class' implemenation */
    QMainWindow::showEvent(Event);
}

QAction* QtExpoMon::CreateCustomAction(const QString& Text, const std::function<void(QTreeWidget*)>& Func)
{
    QAction* Action = new QAction(Text, this);

    Action->setData(QVariant::fromValue(QCustomAction{Func}));

    return Action;
}

void QtExpoMon::on_BtnStartStop_clicked()
{
    if (!ExpoMon::IsDebugging())
    {
        QMessageBox::critical(this, "Error", "Not debugging anything!");
        return;
    }

    if (ExpoMon::IsRunning() && !ExpoMon::IsStarted)
    {
        QMessageBox::critical(this, "Error", "The debugger must be in a paused state!");
        return;
    }

    /* Do not allow any stopping/freeing: the program might still have the addresses in memory and 
        might use them at some point, causing unhandled exceptions if the data has been freed 
    
        ui.BtnStartStop->setEnabled(false);
    */

    ExpoMon::Start();
}

void QtExpoMon::on_BtnDisEnableMonitor_clicked()
{
    if (ui.BtnDisEnableMonitor->text().contains("Disable"))
    {
        ExpoMon::MemBreakpointsDisable();
        ui.BtnDisEnableMonitor->setText("Enable Monitoring");
    }
    else
    {
        ExpoMon::MemBreakpointsEnable();
        ui.BtnDisEnableMonitor->setText("Disable Monitoring");
    }
}

void QtExpoMon::on_BtnReset_clicked()
{
    auto Reply = QMessageBox::question(this, "Reset", 
        "This action may lead to unhandled exceptions. \nDo you want to continue?", 
        QMessageBox::Yes | QMessageBox::No);

    if (Reply == QMessageBox::Yes)
    {
        ExpoMon::Stop();
        ExpoMon::IsInitialized = FALSE;
    }
}

void QtExpoMon::on_CbBreak_toggled()
{
    if (ui.CbBreak->isChecked())
    {
        ui.EditBreak->setEnabled(false);
        ui.EditBreakOnModule->setEnabled(false);
        ui.EditBreakOnFunction->setEnabled(false);

        /* Break for a given on condition on access and/or functions and modules */
        ExpoMon::SetBreakOnAccess(
            ui.EditBreakOnModule->toPlainText().toStdString(),
            ui.EditBreakOnFunction->toPlainText().toStdString());

        ExpoMon::SetBreakCondition(ui.EditBreak->toPlainText().toStdString());
        ExpoMon::DoBreakOnAccess = true;
    }
    else
    {
        ExpoMon::DoBreakOnAccess = false;
        ExpoMon::SetBreakCondition("0");

        ui.EditBreak->setEnabled(true);
        ui.EditBreakOnModule->setEnabled(true);
        ui.EditBreakOnFunction->setEnabled(true);
    }
}

void QtExpoMon::on_CbHijack_toggled()
{
    if (ui.CbHijack->isChecked())
    {
        ui.EditHijack->setEnabled(false);
        ui.EditHijackOnModule->setEnabled(false);
        ui.EditHijackOnFunction->setEnabled(false);
        
        /* Hijack exported function for the given conditions */
        ExpoMon::SetHijackConditions(
            ui.EditHijack->toPlainText().toStdString(),
            ui.EditHijackOnModule->toPlainText().toStdString(),
            ui.EditHijackOnFunction->toPlainText().toStdString());

        ExpoMon::DoHijackOnConditions = true;
    }
    else
    {
        ExpoMon::DoHijackOnConditions = false;
        ExpoMon::SetHijackConditions("0", "", "");

        ui.EditHijack->setEnabled(true);
        ui.EditHijackOnModule->setEnabled(true);
        ui.EditHijackOnFunction->setEnabled(true);
    }
}

void QtExpoMon::on_CbBreakHijack_toggled()
{
    if (ui.CbBreakHijack->isChecked())
    {
        ui.EditBreakHijack->setEnabled(false);
        ui.EditBreakHijackOnModule->setEnabled(false);
        ui.EditBreakHijackOnFunction->setEnabled(false);
        
        /* Hijack exported function for the given conditions */
        ExpoMon::SetBreakOnHijackCalledConditions(
            ui.EditBreakHijack->toPlainText().toStdString(),
            ui.EditBreakHijackOnModule->toPlainText().toStdString(),
            ui.EditBreakHijackOnFunction->toPlainText().toStdString());

        ExpoMon::DoBreakOnCalledHijack = true;
    }
    else
    {
        ExpoMon::DoBreakOnCalledHijack = false;
        ExpoMon::SetBreakOnHijackCalledConditions("0", "", "");

        ui.EditBreakHijack->setEnabled(true);
        ui.EditBreakHijackOnModule->setEnabled(true);
        ui.EditBreakHijackOnFunction->setEnabled(true);
    }
}

void QtExpoMon::on_CbMonitorCond_toggled()
{
    if (ui.CbMonitorCond->isChecked())
    {
        ui.EditMonitorModules->setEnabled(false);
        
        /* Set monitored modules */
        ExpoMon::SetMonitoredModules(
            ui.EditMonitorModules->toPlainText().toStdString());
    }
    else
    {
        ui.EditMonitorModules->setEnabled(true);

        /* Monitor all the modules */
        ExpoMon::SetMonitoredModules("");
    }
}

void QtExpoMon::on_CustomContextMenuRequested(const QPoint &Pos)
{
    QMenu* Menu = nullptr;
    QTreeWidget* TreeWidget = reinterpret_cast<QTreeWidget*>(sender());
    QTreeWidgetItem* Item = TreeWidget->itemAt(Pos);

    /* Translate the widget coordinate pos to global screen coordinates */
    QPoint ScreenPos = TreeWidget->viewport()->mapToGlobal(Pos);

    if (Item == nullptr)
        return;

    switch (Item->type())
    {
        case Menu_Type_Root:
            Menu = &Menus.RootExpAccess;
            break;

        case Menu_Type_Regs:
            Menu = &Menus.Regs;
            break;

        case Menu_Type_Callstack:
            Menu = &Menus.Callstack;
            break;

        default:
            break;
    }

    if (Menu != nullptr)
    {
        Menu->setProperty("ParentSender", QVariant::fromValue(sender()));
        Menu->exec(ScreenPos);
    }
}

void QtExpoMon::on_LstLog_customContextMenuRequested(const QPoint &Pos)
{
    MenuLog.exec(ui.LstLog->viewport()->mapToGlobal(Pos));
}

void QtExpoMon::LogMessage(QString msg)
{
    ui.LstLog->addItem(new QListWidgetItem(QString("[%1] %2")
        .arg(QDateTime::currentDateTime().toString("HH:mm:ss.zzz"))
        .arg(msg)));
}

void QtExpoMon::on_CopyLogToClipboard()
{
    QStringList StringList;

    auto Items = ui.LstLog->selectedItems();

    if (Items.count() < 1)
        return;

    for (int i = 0; i < Items.count(); i++)
        StringList.append(Items.value(i)->text());

    /* Join the list elements and copy the output to the clipboard */
    QApplication::clipboard()->setText(StringList.join("\r\n"));
}

void QtExpoMon::on_ClickContextMenuItem(QAction* Action)
{
    auto Data = Action->data();

    if (!Data.isNull() && Data.isValid() && Data.canConvert<QCustomAction>())
    {
        QTreeWidget* TreeWidget = reinterpret_cast<QTreeWidget*>(
            sender()->property("ParentSender").value<QObject*>());

        Data.value<QCustomAction>().Func(TreeWidget);
    }
}

void QtExpoMon::ResetFilter(QTreeWidget* TreeWidget)
{
    for(int i = 0; i < TreeWidget->topLevelItemCount(); i++)
        TreeWidget->topLevelItem(i)->setHidden(false);

    TreeWidget->update();
}

void QtExpoMon::ApplyFilter(QTreeWidget* TreeWidget, QString& Filters, std::vector<int> Columns)
{
    QList<QTreeWidgetItem*> Items;

    for(int i = 0; i < TreeWidget->topLevelItemCount(); i++)
        TreeWidget->topLevelItem(i)->setHidden(true);

    std::vector<std::string> Tokens = ExpoMon::Tokenize(Filters.toStdString());

    for (auto& Token : Tokens)
    {
        /* For every column of interest, look for a token match */
        for (auto i : Columns)
        {
            Items.append(TreeWidget->findItems(Token.c_str(), Qt::MatchContains, i));
        }
    }

    /* Show all the items that matched the filter(s) */
    for (auto& Item : Items)
        Item->setHidden(false);

    TreeWidget->update();
}

void QtExpoMon::on_BtnAccessFilter_clicked()
{
    QString Filters = ui.EditAccessFilter->text();

    if (Filters.length() == 0)
    {
        ResetFilter(ui.TreeExpAccessed);
    }
    else
    {
        ApplyFilter(ui.TreeExpAccessed, Filters, { 1, 2, 3, 4 });
    }
}

void QtExpoMon::on_BtnHijackFilter_clicked()
{
    QString Filters = ui.EditHijackFilter->text();

    if (Filters.length() == 0)
    {
        ResetFilter(ui.TreeExpHijacked);
    }
    else
    {
        ApplyFilter(ui.TreeExpHijacked, Filters, { 1, 2, 3, 4 });
    }
}
