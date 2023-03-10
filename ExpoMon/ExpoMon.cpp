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
#include "QtExpoMonAbout.h"

/* Plugin logic */
#include "ExpoMon.h"
#include "Utils.h"
#include "WinInternals.h"

/***************************************************************************/

namespace ExpoMon
{
    /* Struct that contains several GUI handles (filled by plugsetup) */
    PLUG_SETUPSTRUCT Setup;

    /* Plugin handle */
    INT Handle = 0;

    /* Plugin module handle */
    HMODULE ModuleHandle = NULL;

    /* Sync objects */
    HANDLE HGuiInit = NULL;
    HANDLE HGuiDestroy = NULL;

    /* Qt objects */
    QtExpoMon* ObjExpoMon = nullptr;
    QtExpoMonAbout* ObjExpoMonAbout = nullptr;

    /* Plugin status */
    BOOL IsStarted = FALSE;
    BOOL IsEnabled = FALSE;
    BOOL IsInitialized = FALSE;
    BOOL DoBreakOnAccess = FALSE;
    BOOL DoBreakOnCalledHijack = FALSE;
    BOOL DoHijackOnConditions = FALSE;

    /* Thread synchronization */
    std::recursive_mutex Mutex;

    /* Misc variables */
    std::string BreakCondition;
    std::string HijackCondition;
    std::string HijackCalledBreakCondition;
    std::vector<std::string> MonitoredModules;
    std::vector<duint> BreakOnAddresses;
    std::vector<std::string> AccessBreakOnModules;
    std::vector<std::string> AccessBreakOnFunctions;
    std::vector<std::string> HijackBreakOnModules;
    std::vector<std::string> HijackBreakOnFunctions;
    std::vector<std::string> HijackOnModules;
    std::vector<std::string> HijackOnFunctions;

    /* How many bytes for each function will be copied when hijacked */
    const size_t BytesPerFunction = 32;

    /*
        Information about the hooked export, needed on memory breakpoint exceptions (on exec)
    */
    struct _PAGE_INFO;

    typedef struct _EXPORTS_HIJACK_PAGE_INFO
    {
        /* Original exported function RVA */
        DWORD FunctionRVA;

        /* Hijacked function RVA */
        DWORD HijackRVA;

        /* Exported function's address */
        duint FunctionAddress;

        /* Exported function's name */
        std::string FunctionName;

        /* Link to parent PAGE_INFO */
        _PAGE_INFO* PageInfo;

    } EXPORTS_HIJACK_PAGE_INFO;

    /*
        Information about the allocated pages

        .rdata usually contains the exports information
        .text usually contains the code. i.e. the exported functions
    */
    typedef struct _PAGE_INFO
    {
        _PAGE_INFO() 
        {
            IsExportsHijackPage = false;
            IsExportsPage = false;
        }

        BOOL IsExportsHijackPage : 1;
        BOOL IsExportsPage : 1;

        SIZE_T Size; /* Page size */
        duint Address; /* Page address */

        struct _MODULE_INFO
        {
            /* Base address */
            duint Base;

            /* Name */
            std::string Name;

            /* Backup of the original export directory */
            IMAGE_EXPORT_DIRECTORY ExportDirectory;

            /* Original export directory RVA */
            DWORD ExportDirectoryRVA;

        } ModuleInfo;

        /* Valid if IsExportsPage true */
        struct _EXPORTS_PAGE_INFO
        {
            /* Absolute virtual addresses */
            duint AddressOfFunctions_Start;
            duint AddressOfFunctions_End;

        } Exports;

        /* Valid if IsExportsHookPage true */
        std::vector< EXPORTS_HIJACK_PAGE_INFO > ExportsHijackInfo;

    } PAGE_INFO, *PPAGE_INFO;

    /* 
        Map containing information about the allocated pages
            Key: newly allocated page's base address 
    */
    std::unordered_map< duint, PAGE_INFO > AllocatedPages;

    /* 
        Map containing information about the hijacked functions
            Key: Module base address + Function RVA = Function's address 
    */
    std::unordered_map< duint, std::pair< duint, size_t > > HijackedFunctions;

    /* Qt functions */
    VOID AboutShow()
    {
        if (nullptr == ObjExpoMonAbout)
            return;

        ObjExpoMonAbout->move(QApplication::desktop()->screen()->rect().center() - 
            ObjExpoMonAbout->rect().center());

        /* ;-) */
        ObjExpoMonAbout->show();
        ObjExpoMonAbout->setFocus();
        ObjExpoMonAbout->PlaySoundtrack();
    }

    VOID GuiShow()
    {
        if (nullptr == ObjExpoMon)
            return;

        if (!ObjExpoMon->isVisible())
            GuiAddQWidgetTab(ObjExpoMon);

        GuiShowQWidgetTab(ObjExpoMon);
    }

    /* Callbacks */
    VOID GuiInit()
    {
        if (NULL == HGuiInit)
            HGuiInit = CreateEvent(NULL, TRUE, FALSE, NULL);

        /* Get the parent window handle */
        QWidget* Parent = QWidget::find((WId)Setup.hwndDlg);

        /* Create the About widget */
        ObjExpoMonAbout = new QtExpoMonAbout(Parent);

        /* Create the plugin's tab widget */
        ObjExpoMon = new QtExpoMon(Parent);

        GuiAddQWidgetTab(ObjExpoMon);

        /* Add the icon to the menu */
        QImage Image(":/ExpoMon/Resources/icon.png");

        QByteArray ImageRawData;
        QBuffer TmpBuffer(&ImageRawData);
        
        Image.save(&TmpBuffer, "PNG");

        ICONDATA IconData = {
            ImageRawData.data(),
            ImageRawData.size()
        };

        _plugin_menuseticon(Setup.hMenu, (const ICONDATA *)&IconData);

        /* Set the sync object */
        SetEvent(HGuiInit);
    }

    VOID GuiDestroy()
    {
        if (NULL == HGuiDestroy)
            HGuiDestroy = CreateEvent(NULL, TRUE, FALSE, NULL);

        GuiCloseQWidgetTab(ObjExpoMon);

        ObjExpoMon->close();
        ObjExpoMonAbout->close();

        delete ObjExpoMon;
        delete ObjExpoMonAbout;

        /* Set the sync object */
        SetEvent(HGuiDestroy);
    }

    /* Wait functions */
    VOID Wait_GuiInit()
    {
        WaitForSingleObject(HGuiInit, INFINITE);
    }

    VOID Wait_GuiDestroy()
    {
        WaitForSingleObject(HGuiDestroy, INFINITE);
    }

    /* Main logic */
    BOOL IsRunning()
    {
        return !::DbgIsRunLocked();
    }

    BOOL IsDebugging()
    {
        return ::DbgIsDebugging();
    }

    VOID LogMessage(std::string Msg)
    {
#if 0

        /* Acquire lock */
        std::lock_guard<std::recursive_mutex> lock(Mutex);

        const char* FilePath = "C:\\logfile.txt";

        std::ofstream LogFile(FilePath, std::ios_base::app | std::ios_base::out);

        if (LogFile.is_open())
        {
            char Timestamp[128];

            auto CurrTime = std::chrono::system_clock::to_time_t(
                std::chrono::system_clock::now());

            std::strftime(Timestamp, sizeof(Timestamp),
                "[%d/%m/%Y %H:%M:%S] ", std::localtime(&CurrTime));

            LogFile << Timestamp << Msg << std::endl;
        }

#else

        ObjExpoMon->LogMessage(QString(Msg.c_str()));

#endif
    }

    QString GetValueAtAddress(duint Address)
    {
        char Tmp[MAX_STRING_SIZE] = { 0 };

        /* Get the string at the address if valid */
        if (DbgGetStringAt(Address, Tmp))
        {
            return QString(Tmp);
        }
        
        /* Get the data at the address if valid (in hex format) */
        if (DbgMemIsValidReadPtr(Address))
        {
            BYTE Data[16] = { 0 };

            if (DbgMemoryRead((PVOID)Address, Data, sizeof(Data)))
            {
                QString Result = "";

                for (unsigned int i = 0; i < sizeof(Data); i++)
                {
                    Result += Utils::StringFormat("%02X ", Data[i]).c_str();
                }

                return Result;
            }
        }
        
        return QString("");
    }

    QString GetModuleAtAddress(duint Address)
    {
        char Tmp[MAX_STRING_SIZE] = { 0 };

        /* Get the module at the address if valid */
        if (DbgGetModuleAt(Address, Tmp))
        {
            return QString(Tmp);
        }
        
        return QString("");
    }

    QChildTreeWidgetItem* CreateRegistersItem(REGISTERCONTEXT* RegContext)
    {
        QChildTreeWidgetItem* RegItem = new QChildTreeWidgetItem(QStringList{"Registers"});

        if (RegItem != nullptr)
        {

            const char* RegName[] =
            {
                "rAX",
                "rCX",
                "rDX",
                "rBX",
                "rSP",
                "rBP",
                "rSI",
                "rDI",
#ifdef _WIN64
                "r8",
                "r9",
                "r10",
                "r11",
                "r12",
                "r13",
                "r14",
                "r15"
#endif
            };

            /* Add an empty row */
            RegItem->addChild(new QChildTreeWidgetItem());

            for (size_t i = 0; i < _countof(RegName); i++)
            {
                duint RegValue = *(&RegContext->cax + i);

                QChildTreeWidgetItem* Tmp = new QChildTreeWidgetItem(
                    QStringList{RegName[i], Utils::StringFormat("%p", RegValue).c_str(), 
                        GetValueAtAddress(RegValue), GetModuleAtAddress(RegValue)}, Menu_Type_Regs
                    );

                if (Tmp != nullptr)
                    RegItem->addChild(Tmp);
            }

            /* Add an empty row */
            RegItem->addChild(new QChildTreeWidgetItem());
        }

        return RegItem;
    }

    QChildTreeWidgetItem* CreateCallstackItem(DBGCALLSTACK* CallStack, unsigned int StartingIndex)
    {
        QChildTreeWidgetItem* CallStackItem = new QChildTreeWidgetItem(QStringList{"Call Stack"});

        if(CallStackItem != nullptr)
        {
            /* Add an empty row */
            CallStackItem->addChild(new QChildTreeWidgetItem());

            for (size_t i = StartingIndex; i < CallStack->total && i < 10; i++)
            {
                QChildTreeWidgetItem* Tmp = new QChildTreeWidgetItem(
                    QStringList{"", CallStack->entries[i].comment}, Menu_Type_Callstack
                );

                if (Tmp != nullptr)
                    CallStackItem->addChild(Tmp);
            }

            /* Add an empty row */
            CallStackItem->addChild(new QChildTreeWidgetItem());
        }

        return CallStackItem;
    }

    QChildTreeWidgetItem* CreateStackItem(const std::vector<duint>& Stack)
    {
        QChildTreeWidgetItem* StackItem = new QChildTreeWidgetItem(QStringList{"Stack"});

        if(StackItem != nullptr)
        {
            int i = 0;

            /* Add an empty row */
            StackItem->addChild(new QChildTreeWidgetItem());

            for (auto& Element : Stack)
            {
                QChildTreeWidgetItem* Tmp = new QChildTreeWidgetItem(
                    QStringList{
                        Utils::StringFormat("rSP + %02X", i).c_str(), 
                        Utils::StringFormat("%p", Element).c_str(), 
                        GetValueAtAddress(Element), GetModuleAtAddress(Element)}, Menu_Type_Regs
                );

                if (Tmp != nullptr)
                    StackItem->addChild(Tmp);

                i += sizeof(duint);
            }

            /* Add an empty row */
            StackItem->addChild(new QChildTreeWidgetItem());
        }

        return StackItem;
    }

    VOID PopulateRootItem(QTreeWidgetItem* Item, int CurrentItemCount, std::string ModName, 
        std::string FuncName, duint Address,
        std::string AddressModName, DWORD ThreadId, duint AccessOp)
    {
        Item->setText(0, Utils::StringFormat("%06d", CurrentItemCount).c_str());
        Item->setText(1, FuncName.c_str());
        Item->setText(2, ModName.c_str());
        Item->setText(3, Utils::StringFormat("%p", Address).c_str());
        Item->setText(4, AddressModName.c_str());
        Item->setText(5, Utils::StringFormat("%08X", ThreadId).c_str());

        /* ExceptionInformation[0] on EXCEPTION_ACCESS_VIOLATION */
        Item->setText(6, (AccessOp == 0 ? "READ" : 
            (AccessOp == 1 ? "WRITE" : 
            (AccessOp == 8 ? "EXECUTE" : "UNDEFINED"))));
    }

    VOID LogExportsAccess(std::string ModName, std::string FuncName, duint Address,
        std::string AddressModName, DWORD ThreadId, 
        REGISTERCONTEXT* RegContext, DBGCALLSTACK* CallStack, duint AccessOp, const std::vector<duint>& Stack)
    {
#if _PLUGIN_DEBUG

        /* Add message to the log list */
        LogMessage(Utils::StringFormat("Hit on %s!%s from %p", 
            ModName.c_str(), FuncName.c_str(), Address));

#endif

        /* Populate the QTreeWidget */
        QTreeWidgetItem* Item = new QTreeWidgetItem(ObjExpoMon->ui.TreeExpAccessed, 
            Menu_Type_Root);

        int CurrentItemCount = ObjExpoMon->ui.TreeExpAccessed->topLevelItemCount();

        PopulateRootItem(Item, CurrentItemCount, ModName, FuncName, 
            Address, AddressModName, ThreadId, AccessOp);

        /* Add the root entry */
        ObjExpoMon->ui.TreeExpAccessed->addTopLevelItem(Item);

        /* Add the register sub-entry */
        QChildTreeWidgetItem* RegItem = CreateRegistersItem(RegContext);

        if (RegItem != nullptr)
            Item->addChild(RegItem);
        
        /* Add the call stack sub-entry */
        QChildTreeWidgetItem* CallStackItem = CreateCallstackItem(CallStack, 0);

        if (CallStackItem != nullptr)
            Item->addChild(CallStackItem);

        /* Add the stack sub-entry */
        QChildTreeWidgetItem* StackItem = CreateStackItem(Stack);

        if (StackItem != nullptr)
            Item->addChild(StackItem);

#if 0

        QFont BoldFont(RegItem->font(0).family(), RegItem->font(0).pointSize(), QFont::Bold);

#endif

#if 0

        /* Resize the columns based on the content */
        for (int i = 0; i < ObjExpoMon->ui.TreeExpAccessed->columnCount(); i++)
            ObjExpoMon->ui.TreeExpAccessed->resizeColumnToContents(i);

#endif
    }

    VOID LogExportsHijacked(std::string ModName, std::string FuncName, duint Address,
        std::string AddressModName, DWORD ThreadId, 
        REGISTERCONTEXT* RegContext, DBGCALLSTACK* CallStack, duint AccessOp, const std::vector<duint>& Stack)
    {
        /* Populate the QTreeWidget */
        QTreeWidgetItem* Item = new QTreeWidgetItem(ObjExpoMon->ui.TreeExpHijacked, 
            Menu_Type_Root);

        int CurrentItemCount = ObjExpoMon->ui.TreeExpHijacked->topLevelItemCount();

        PopulateRootItem(Item, CurrentItemCount, ModName, FuncName, 
            Address, AddressModName, ThreadId, AccessOp);

        /* Add the root entry */
        ObjExpoMon->ui.TreeExpHijacked->addTopLevelItem(Item);

        /* Add the register sub-entry */
        QChildTreeWidgetItem* RegItem = CreateRegistersItem(RegContext);

        if (RegItem != nullptr)
            Item->addChild(RegItem);

        /* Add the call stack sub-entry, skip the first entry (hijack address) */
        QChildTreeWidgetItem* CallStackItem = CreateCallstackItem(CallStack, 1);

        if (CallStackItem != nullptr)
            Item->addChild(CallStackItem);

        /* Add the stack sub-entry */
        QChildTreeWidgetItem* StackItem = CreateStackItem(Stack);

        if (StackItem != nullptr)
            Item->addChild(StackItem);
    }

    template<typename ... Args>
    bool ExecCmdSync(const std::string& fmt, Args ... args)
    {
        return DbgCmdExecDirect(Utils::StringFormat(fmt, args ...).c_str());
    }

    template<typename ... Args>
    bool ExecCmdAsync(const std::string& fmt, Args ... args)
    {
        return DbgCmdExec(Utils::StringFormat(fmt, args ...).c_str());
    }

    PIMAGE_OPTIONAL_HEADER
    PEGetOptionalHeader(PVOID ModBase)
    {
        PIMAGE_NT_HEADERS Nt;
        PIMAGE_DOS_HEADER Dos;

        Dos = (PIMAGE_DOS_HEADER)ModBase;
        Nt = (PIMAGE_NT_HEADERS)((BYTE *)Dos + Dos->e_lfanew);

        return &Nt->OptionalHeader;
    }

    duint GetPebAddress()
    {
#if 1

        return DbgGetPebAddress(DbgGetProcessId());

#else

        /* alternative, but requires TitanEngine */
        return (duint)GetPEBLocation(DbgGetProcessHandle());

#endif
    }

    BOOL DbgMemoryRead(PVOID BaseAddr, PVOID Dst, SIZE_T Size)
    {
        SIZE_T BytesRead;

        return MemoryReadSafe(DbgGetProcessHandle(), BaseAddr, Dst, Size, &BytesRead);
    }

    BOOL DbgMemoryWrite(PVOID BaseAddr, PVOID Src, SIZE_T Size)
    {
        SIZE_T BytesWritten = 0;

        return MemoryWriteSafe(DbgGetProcessHandle(),
            (void*)BaseAddr, (void*)Src, Size, &BytesWritten);
    }

    bool DbgMemoryCopy(PVOID Src, PVOID Dst, SIZE_T Size)
    {
        std::unique_ptr<BYTE[]> Tmp(new BYTE[Size]);

        if (DbgMemoryRead(Src, Tmp.get(), Size))
            if (DbgMemoryWrite(Dst, Tmp.get(), Size))
                return true;

        return false;
    }

    duint GetAvailablePageAfterAddress(duint Address, size_t DesiredSize)
    {
        MEMORY_BASIC_INFORMATION MemBasicInfo = { 0 };
        SYSTEM_INFO SysInfo = { 0 };

        SIZE_T MemBasicInfoSize = 0;
        duint PageBaseAddress = 0;
        duint AllocPageAddress = 0;

#if _PLUGIN_DEBUG

        LogMessage(Utils::StringFormat("[%s] Search after: %p, size: %08X",
            __FUNCTION__, Address, DesiredSize));

#endif

        /* allocation granularity */
        GetSystemInfo(&SysInfo);

        while(true)
        {
            MemBasicInfoSize = VirtualQueryEx(DbgGetProcessHandle(), 
                (LPVOID)PageBaseAddress, &MemBasicInfo, sizeof(MemBasicInfo));

            if (MemBasicInfoSize == 0)
                break;

            /* only process available memory */
            if (MemBasicInfo.State == MEM_FREE)
            {
                if ((duint)MemBasicInfo.BaseAddress > Address && MemBasicInfo.RegionSize > DesiredSize)
                {
                    /* page must be aligned or else allocation fails */
                    AllocPageAddress = Utils::AlignUp((duint)MemBasicInfo.BaseAddress, 
                        (duint)SysInfo.dwAllocationGranularity);

                    break;
                }
            }

            PageBaseAddress = Utils::AlignUp((duint)MemBasicInfo.BaseAddress + MemBasicInfo.RegionSize, 
                (duint)SysInfo.dwAllocationGranularity);
        }

        return AllocPageAddress;
    }

    bool ModuleGetFunctionByIndex(duint ModBase, PIMAGE_EXPORT_DIRECTORY ModExpDir, 
        WORD Index, std::string& FuncName)
    {
        size_t NumberOfNames = ModExpDir->NumberOfNames;

        /* Check if the module exports only by ordinals */
        if (NumberOfNames == 0)
        {
            FuncName = Utils::StringFormat("#%d", Index + ModExpDir->Base);

            return true;
        }

        std::unique_ptr<DWORD[]> NameTable(new DWORD[NumberOfNames]);
        std::unique_ptr<WORD[]> OrdTable(new WORD[NumberOfNames]);

        /* Read the AddressOfNames array (RVA to ASCII string) */
        if (!DbgMemRead(ModBase + ModExpDir->AddressOfNames,
            NameTable.get(), NumberOfNames * sizeof(DWORD)))
        {
            return false;
        }

        /* Read the AddressOfNameOrdinals array (WORD indexes to AddressOfFunctions) */
        if (!DbgMemRead(ModBase + ModExpDir->AddressOfNameOrdinals, 
            OrdTable.get(), NumberOfNames * sizeof(WORD)))
        {
            return false;
        }

        /* Find the export function name by index */
        for (unsigned int i = 0; i < ModExpDir->NumberOfNames; i++)
        {
            if (OrdTable[i] == Index)
            {
                char tmp[128] = { 0 };

                if (DbgMemRead(ModBase + NameTable[i], tmp, sizeof(tmp)))
                {
                    FuncName = tmp;                 
                }

                return true;
            }
        }

        /* Exported by ordinal */
        FuncName = Utils::StringFormat("#%d", Index + ModExpDir->Base);

        return true;
    }

    void MemBreakpointsDisable()
    {
        /* Acquire lock */
        std::lock_guard<std::recursive_mutex> lock(Mutex);

        /* Disable all memory breakpoints */
        for (const auto& Page : AllocatedPages)
        {
#if _PLUGIN_DEBUG

            LogMessage(Utils::StringFormat("[%s,%08X] Disabling memory breakpoint @ %p (%s)",
                __FUNCTION__, DbgGetThreadId(), Page.first, Page.second.ModuleInfo.Name.c_str()));

#endif
            ExecCmdSync("DisableMemoryBreakpoint %p", Page.first);

            LogMessage(Utils::StringFormat("Disabled memory breakpoint for %s at %p", 
                Page.second.ModuleInfo.Name.c_str(), Page.first));
        }
    }
 
    void MemBreakpointsEnable()
    {
        /* Acquire lock */
        std::lock_guard<std::recursive_mutex> lock(Mutex);

        /* Enable all memory breakpoints */
        for (const auto& Page : AllocatedPages)
        {
#if _PLUGIN_DEBUG

            LogMessage(Utils::StringFormat("[%s,%08X] Enabling memory breakpoint @ %p [%s]",
                __FUNCTION__, DbgGetThreadId(), Page.first, Page.second.ModuleInfo.Name.c_str()));

#endif
            ExecCmdSync("EnableMemoryBreakpoint %p", Page.first);

            LogMessage(Utils::StringFormat("Enabled memory breakpoint for %s at %p", 
                Page.second.ModuleInfo.Name.c_str(), Page.first));
        }
    }
 
    bool IsModuleExportDirectoryHijacked(duint ModBase)
    {
        for (const auto& Page : AllocatedPages)
        {
            if (Page.second.ModuleInfo.Base == ModBase &&
                Page.second.IsExportsPage)
            {
                return true;
            }
        }

        return false;
    }

    void ForceDebuggerBreak(duint BaseAddress)
    {
        /*  
            Force the debugger to break by temporarily disabling fast resume on the 
            memory breakpoint and adding to the break condition 
        */
        std::string Brk = GetBreakCondition();

        if (Brk.empty() || Brk == "0")
        {
            Brk = "1";
        }
        else
        {
            Brk += " && 1";
        }

        ExecCmdSync("SetMemoryBreakpointFastResume %p,0", BaseAddress);
        ExecCmdSync("SetMemoryBreakpointCondition %p,%s", BaseAddress, Brk.c_str());

        BreakOnAddresses.push_back(BaseAddress);
    }

    void RestoreDebuggerBreak()
    {
        /* Restore fast resume on the memory breakpoints */
        for (auto Address : BreakOnAddresses)
        {
            ExecCmdSync("SetMemoryBreakpointFastResume %p,1", Address);
            ExecCmdSync("SetMemoryBreakpointCondition %p,%s", Address, GetBreakCondition().c_str());
        }
    }

    bool HijackModuleExportDirectory(duint ModBase, std::string ModName, bool IsDisabled)
    {
        std::unique_ptr<BYTE[]> PeHdr(new BYTE[0x1000]);

        /* Acquire lock */
        std::lock_guard<std::recursive_mutex> lock(Mutex);

        /* Check if the module's export directory has already been hijacked */
        if (IsModuleExportDirectoryHijacked(ModBase))
        {
            LogMessage(Utils::StringFormat("Module %s export directory already hijacked", 
                ModName.c_str(), ModBase));

            return false;
        }

        /* Check if the module is to be monitored */
        if (!ShouldMonitorModule(ModName))
        {
            LogMessage(Utils::StringFormat("Module %s export directory will not be monitored", 
                ModName.c_str(), ModBase));

            return false;
        }

        /* Update memory map */
        DbgFunctions()->MemUpdateMap();

        /* Read the PE header */
        if (!DbgMemoryRead((void*)ModBase, PeHdr.get(), 0x1000))
        {
            LogMessage(Utils::StringFormat("Failed to read the PE header of %s [%p]", 
                ModName.c_str(), ModBase));

            return false;
        }

        IMAGE_DATA_DIRECTORY ExpDataDir = PEGetOptionalHeader(
            PeHdr.get())->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

        /* Check if there are any exported functions */
        if (ExpDataDir.VirtualAddress == 0 || ExpDataDir.Size == 0)
        {
            LogMessage("No export directory to process");

            return false;
        }

#if _PLUGIN_DEBUG

        LogMessage(Utils::StringFormat("Exports directory address: %p", ModBase + ExpDataDir.VirtualAddress));

#endif

        /* Get the page's base and size */
        duint PageSize = 0;
        duint PageBase = DbgMemFindBaseAddr(ModBase + ExpDataDir.VirtualAddress, &PageSize);
        duint DeltaPageBase = PageBase - ModBase;
        duint AvailablePage = GetAvailablePageAfterAddress(PageBase, PageSize);

        /* Allocate remote memory at the available page address */ 
        duint NewPageBase = (duint)VirtualAllocEx(DbgGetProcessHandle(), (PVOID)AvailablePage,
            (SIZE_T)PageSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

        if (NewPageBase == NULL)
        {
            LogMessage(Utils::StringFormat("Failed to allocate page at base: %p", AvailablePage));

            return false;
        }

        /* Check for dword overflow */
        if (NewPageBase - PageBase + PageSize > MAXDWORD)
        {
            LogMessage("Failed to find a suitable new page address: DWORD overflown");

            /* Release the allocated page */
            VirtualFreeEx(DbgGetProcessHandle(), (PVOID)NewPageBase, 0, MEM_RELEASE);

            return false;
        }

        /* Delta between new page and original page */
        DWORD DeltaPages = (DWORD)(NewPageBase - PageBase);
    
        std::unique_ptr<BYTE[]> Buffer(new BYTE[PageSize]);

        if (!DbgMemoryRead((void*)PageBase, Buffer.get(), PageSize))
        {
            LogMessage(Utils::StringFormat("Failed to read from %p [%08X]", PageBase, PageSize));

            /* Release the allocated page */
            VirtualFreeEx(DbgGetProcessHandle(), (PVOID)NewPageBase, 0, MEM_RELEASE);

            return false;
        }

        /* Read the export directory */
        IMAGE_EXPORT_DIRECTORY ExpDir;

        if (!DbgMemoryRead((void*)(ModBase + ExpDataDir.VirtualAddress), &ExpDir, sizeof(ExpDir)))
        {
            LogMessage("Failed to read the export directory");

            /* Release the allocated page */
            VirtualFreeEx(DbgGetProcessHandle(), (PVOID)NewPageBase, 0, MEM_RELEASE);

            return false;
        }

        if (!DbgMemoryWrite((void*)NewPageBase, Buffer.get(), PageSize))
        {
            LogMessage(Utils::StringFormat("Failed to write to %p [%08X]", NewPageBase, PageSize));

            /* Release the allocated page */
            VirtualFreeEx(DbgGetProcessHandle(), (PVOID)NewPageBase, 0, MEM_RELEASE);

            return false;
        }

        AllocatedPages[NewPageBase].IsExportsPage = true;
        AllocatedPages[NewPageBase].Address = NewPageBase;
        AllocatedPages[NewPageBase].Size = PageSize;
        AllocatedPages[NewPageBase].ModuleInfo.Base = ModBase;
        AllocatedPages[NewPageBase].ModuleInfo.Name = ModName;
        AllocatedPages[NewPageBase].ModuleInfo.ExportDirectoryRVA = ExpDataDir.VirtualAddress;
        AllocatedPages[NewPageBase].ModuleInfo.ExportDirectory = ExpDir;

        AllocatedPages[NewPageBase].Exports.AddressOfFunctions_Start = 
            ModBase + ExpDir.AddressOfFunctions + DeltaPages;

        AllocatedPages[NewPageBase].Exports.AddressOfFunctions_End = 
            AllocatedPages[NewPageBase].Exports.AddressOfFunctions_Start +
            ExpDir.NumberOfFunctions * sizeof(DWORD);

        /* 
            Set memory breakpoint on the page (PAGE_GUARD / PAGE_NOACCESS)

            - PAGE_GUARD has race condition issues, so PAGE_NOACCESS has to be used
            - In x64dbg.ini, [Engine], set the variable MembpAlt=1 (setting for TitanEngine)

            Note: As a performance boost, we set it to silent, fast resume and
            set the break condition to never, which is only possible because we handle 
            the memory related exceptions directly in the DebugEvent callback
        */
        ExecCmdSync(
            "SetMemoryBPX %p,1,r;"
            "SetMemoryBreakpointSilent %p;"
            "SetMemoryBreakpointFastResume %p,1;"
            "SetMemoryBreakpointCondition %p,%s;",
            NewPageBase, NewPageBase, NewPageBase, NewPageBase, GetBreakCondition().c_str());

        /* Disable the breakpoint after having created it */
        if(IsDisabled)
            ExecCmdSync("DisableMemoryBreakpoint %p", NewPageBase);

#if _PLUGIN_DEBUG

        LogMessage(Utils::StringFormat("Hijacking AddressOfFunctions %08X [%p] of module at base %p",
            ExpDir.AddressOfFunctions, ModBase + ExpDataDir.VirtualAddress, ModBase));

#endif

        /* Hook IMAGE_EXPORT_DIRECTORY.AddressOfFunctions */
        ExpDir.AddressOfFunctions += DeltaPages;
  
        if (!DbgMemoryWrite((void*)(ModBase + ExpDataDir.VirtualAddress), &ExpDir, sizeof(ExpDir)))
        {
            LogMessage("Failed to hook IMAGE_EXPORT_DIRECTORY.AddressOfFunctions");

            /* Remove the element from the map */
            AllocatedPages.erase(NewPageBase);

            /* Release the allocated page */
            VirtualFreeEx(DbgGetProcessHandle(), (PVOID)NewPageBase, 0, MEM_RELEASE);

            return false;
        }

        return true;
    }

    bool RestoreModuleExportDirectory(duint PageBase)
    {
        std::unique_ptr<BYTE[]> PeHdr(new BYTE[0x1000]);

        /* Acquire lock */
        std::lock_guard<std::recursive_mutex> lock(Mutex);

        duint ModBase = AllocatedPages[PageBase].ModuleInfo.Base;
        DWORD ExpDirRVA = AllocatedPages[PageBase].ModuleInfo.ExportDirectoryRVA;

        /* Read the PE header */
        if (!DbgMemoryRead((void*)ModBase, PeHdr.get(), 0x1000))
        {
            LogMessage(Utils::StringFormat("Failed to read the PE header of %s [%p]", 
                AllocatedPages[PageBase].ModuleInfo.Name.c_str(), ModBase));

            return false;
        }

        /* Resotre the original export directory relative virtual address */
        if (!DbgMemoryWrite((void*)(ModBase + ExpDirRVA), 
            &AllocatedPages[PageBase].ModuleInfo.ExportDirectory, sizeof(IMAGE_EXPORT_DIRECTORY)))
        {
            LogMessage("Failed to restore IMAGE_EXPORT_DIRECTORY.AddressOfFunctions");

            return false;
        }

        /* Remove the memory breakpoint */
        ExecCmdSync("DeleteMemoryBPX %p", PageBase);

        /* Release the allocated page */
        VirtualFreeEx(DbgGetProcessHandle(), (PVOID)PageBase, 0, MEM_RELEASE);

        /* Remove the entry from the map */
        AllocatedPages.erase(PageBase);

        return true;
    }

    void HijackLoadedModulesExportDirectory()
    {
        ListInfo ModList;

        /* Get all the currently loaded modules */
        if (Script::Module::GetList(&ModList))
        {
            auto ModInfo = (Script::Module::ModuleInfo*)ModList.data;

            for (int i = 0; i < ModList.count; i++)
            {
                if (ModInfo[i].base == Script::Module::GetMainModuleBase())
                    continue;

                LogMessage(Utils::StringFormat("Hijacking %s", ModInfo[i].name));

                HijackModuleExportDirectory(ModInfo[i].base, ModInfo[i].name, false);
            }

            BridgeFree(ModList.data);
        }
    }

    std::vector<duint> GetStack(size_t NumberOfElements = 10)
    {
        std::vector<duint> Tmp;

        for (size_t i = 0; i < NumberOfElements; i++)
            Tmp.push_back(Script::Stack::Peek(i));

        return Tmp;
    }

    std::string GetBreakCondition()
    {
        /* Acquire lock */
        std::lock_guard<std::recursive_mutex> lock(Mutex);

        return (BreakCondition.empty() ? "0" : BreakCondition);
    }

    std::string GetHijackCondition()
    {
        /* Acquire lock */
        std::lock_guard<std::recursive_mutex> lock(Mutex);

        return (HijackCondition.empty() ? "0" : HijackCondition);
    }

    std::string GetHijackCalledBreakCondition()
    {
        /* Acquire lock */
        std::lock_guard<std::recursive_mutex> lock(Mutex);

        return (HijackCalledBreakCondition.empty() ? "0" : HijackCalledBreakCondition);
    }

    VOID SetHijackConditions(std::string Condition, std::string Modules, std::string Functions)
    {
        /* Acquire lock */
        std::lock_guard<std::recursive_mutex> lock(Mutex);

        HijackCondition = Condition;
        HijackOnModules = Tokenize(Modules);
        HijackOnFunctions = Tokenize(Functions);
    }

    VOID SetBreakOnHijackCalledConditions(std::string Condition, std::string Modules, std::string Functions)
    {
        /* Acquire lock */
        std::lock_guard<std::recursive_mutex> lock(Mutex);

        HijackCalledBreakCondition = Condition;
        HijackBreakOnModules = Tokenize(Modules);
        HijackBreakOnFunctions = Tokenize(Functions);
    }

    VOID SetBreakCondition(std::string Condition)
    {
        /* Acquire lock */
        std::lock_guard<std::recursive_mutex> lock(Mutex);
        std::regex Exp("[\r\n]");

        BreakCondition = (Condition.empty() ? "0" : 
            std::regex_replace(Condition, Exp, " "));

        for (const auto& Page : AllocatedPages)
        {
            ExecCmdSync("SetMemoryBreakpointCondition %p,%s", 
                Page.first, BreakCondition.c_str());
        }
    }

    bool ShouldMonitorModule(std::string Module)
    {
        /* Acquire lock */
        std::lock_guard<std::recursive_mutex> lock(Mutex);

        if (MonitoredModules.size() == 0)
            return true;

        /* Convert the module name to lowercase */
        std::transform(Module.begin(), Module.end(), Module.begin(), [](unsigned char c) { 
            return std::tolower(c); 
        });

        for (auto& Tmp : MonitoredModules)
        {
            if (Module.find(Tmp) != std::string::npos)
                return true;
        }

        return false;
    }

    VOID SetMonitoredModules(std::string Modules)
    {
        /* Acquire lock */
        std::lock_guard<std::recursive_mutex> lock(Mutex);

        MonitoredModules = Tokenize(Modules);
    }

    VOID SetBreakOnAccess(std::string Modules, std::string Functions)
    {
        /* Acquire lock */
        std::lock_guard<std::recursive_mutex> lock(Mutex);

        AccessBreakOnModules = Tokenize(Modules);
        AccessBreakOnFunctions = Tokenize(Functions);
    }

    bool ContainsModuleOrFunction(const std::vector<std::string>& Modules, const std::vector<std::string>& Functions,
        std::string Module, std::string Function)
    {
        /* Acquire lock */
        std::lock_guard<std::recursive_mutex> lock(Mutex);

        /* 
            This function does _not_ take into account the default access break condition 
            of the memory breakpoint, which is set by SetBreakCondition. That's because 
            that case is already handled by the debugger's internal logic
        */

        /* Convert the module name to lowercase */
        std::transform(Module.begin(), Module.end(), Module.begin(), [](unsigned char c) { 
            return std::tolower(c); 
        });

        /* Convert the function name to lowercase */
        std::transform(Function.begin(), Function.end(), Function.begin(), [](unsigned char c) { 
            return std::tolower(c); 
        });

        for (auto& Tmp : Modules)
            if (Module.find(Tmp) != std::string::npos)
                return true;

        for (auto& Tmp : Functions)
            if (Function.find(Tmp) != std::string::npos)
                return true;

        return false;
    }

    std::vector<std::string> Tokenize(std::string Input)
    {
        /* Return an empty vector on an empty input */
        if (Input.length() == 0)
            return std::vector<std::string>();

        std::regex Exp("[\\s|,;\r\n]");
        std::sregex_token_iterator IterFirst(Input.begin(), Input.end(), Exp, -1);
        std::sregex_token_iterator IterLast;
        std::vector<std::string> Tokens(IterFirst, IterLast);

        /* Remove all the empty lines */
        Tokens.erase(std::remove_if(Tokens.begin(), Tokens.end(), [](std::string const& s) { 
            return s.length() == 0; 
        }), Tokens.end());

        for (auto& Token : Tokens)
        {
            /* Convert tokens to lowercase */
            std::transform(Token.begin(), Token.end(), Token.begin(), [](unsigned char c) { 
                return std::tolower(c); 
            });
        }

        return Tokens;
    }

    std::string GetStringAfterChr(std::string& Str, const char* Sep)
    {
        size_t Pos = Str.find_last_of(Sep);

        if(std::string::npos != Pos)
        {
            return Str.substr(Pos + 1, Str.length());
        }

        return Str;
    }

    std::string ReplaceChrInString(std::string& Str, const char* Chr, const char* Rep)
    {
        size_t Pos = Str.find_first_of(Chr);

        if(std::string::npos != Pos)
        {
            std::string Tmp(Str); Tmp[Pos] = *Rep;

            return Tmp;
        }

        return Str;
    }

    bool PrepareExportedFunctionHijack(DWORD FuncRVA, std::string const& FuncName, duint ModBase, std::string const& ModName, 
        PIMAGE_EXPORT_DIRECTORY ExpDir, DWORD& HijackRVA, bool IsDisabled)
    {
        PAGE_INFO* PageInfo = nullptr;

        /* Acquire lock */
        std::lock_guard<std::recursive_mutex> lock(Mutex);

        duint FuncAddress = FuncRVA + ModBase;

#if _PLUGIN_DEBUG

            LogMessage(Utils::StringFormat("Hijacking %s (%08X, %p, %p)", 
                FuncName.c_str(), FuncRVA, ModBase, FuncAddress));

#endif

        /* Check if the function has already been hijacked */
        if (HijackedFunctions.find(FuncAddress) != HijackedFunctions.end())
        {
            HijackRVA = AllocatedPages[HijackedFunctions[FuncAddress].first].
                ExportsHijackInfo[HijackedFunctions[FuncAddress].second].HijackRVA;
#if _PLUGIN_DEBUG

            LogMessage(Utils::StringFormat("HijackRVA for %p -> %08X", 
                FuncAddress, HijackRVA));

#endif
            return true;
        }

        /* Update memory map */
        DbgFunctions()->MemUpdateMap();

        /* Check if the FuncAddress points to an executable page */
        MEMORY_BASIC_INFORMATION MemBasicInfo = { 0 };

        if (VirtualQueryEx(DbgGetProcessHandle(), (LPVOID)DbgMemFindBaseAddr(FuncAddress, nullptr),
            &MemBasicInfo, sizeof(MemBasicInfo)) > 0)
        {
            if ((MemBasicInfo.Protect & PAGE_EXECUTE_READ) != PAGE_EXECUTE_READ &&
                (MemBasicInfo.Protect & PAGE_EXECUTE_READWRITE) != PAGE_EXECUTE_READWRITE &&
                (MemBasicInfo.Protect & PAGE_EXECUTE) != PAGE_EXECUTE)
            {
#if _PLUGIN_DEBUG

                LogMessage(Utils::StringFormat("Will not hijack %s!%s", 
                    ModName.c_str(), FuncName.c_str()));

#endif
                return false;
            }
        }

        /* Loop the pages and check if an entry for the module already exists */
        for (auto& Page : AllocatedPages)
        {
            if (Page.second.IsExportsHijackPage && Page.second.ModuleInfo.Base == ModBase)
            {
                PageInfo = &Page.second;
                break;
            }
        }

        /* Allocate the page if it doesn't exist */
        if (PageInfo == nullptr)
        {
            duint PageSize = Utils::AlignUp(BytesPerFunction * ExpDir->NumberOfFunctions, (duint)0x1000/*4KB*/);
            duint AvailablePage = GetAvailablePageAfterAddress(ModBase, PageSize);

            /* Allocate remote memory at the available page address */ 
            duint AllocPage = (duint)VirtualAllocEx(DbgGetProcessHandle(), (PVOID)AvailablePage,
                (SIZE_T)PageSize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

            if (AllocPage == NULL)
            {
                LogMessage(Utils::StringFormat("Failed to allocate page at base: %p", AvailablePage));

                return false;
            }

            /* Check for dword overflow */
            if (AllocPage - ModBase + PageSize > MAXDWORD)
            {
                LogMessage("Failed to find a suitable new page address: DWORD overflown");

                /* Release the allocated page */
                VirtualFreeEx(DbgGetProcessHandle(), (PVOID)AllocPage, 0, MEM_RELEASE);

                return false;
            }

            AllocatedPages[AllocPage].IsExportsHijackPage = true;
            AllocatedPages[AllocPage].Address = AllocPage;
            AllocatedPages[AllocPage].Size = PageSize;
            AllocatedPages[AllocPage].ModuleInfo.Base = ModBase;
            AllocatedPages[AllocPage].ModuleInfo.Name = ModName;
            AllocatedPages[AllocPage].ModuleInfo.ExportDirectory = *ExpDir;

            PageInfo = &AllocatedPages[AllocPage];
        }

        /* Copy the function's first bytes */
        duint CopyAddress = PageInfo->Address + PageInfo->ExportsHijackInfo.size() * BytesPerFunction;

        if (!DbgMemoryCopy((void *)(FuncAddress), (void *)CopyAddress, BytesPerFunction))
        {
            LogMessage(Utils::StringFormat("Failed to copy %s (%p) to %p", FuncName.c_str(), FuncAddress, CopyAddress));

            return false;
        }

        /* Set the hijacked RVA */
        HijackRVA = CopyAddress - ModBase;

        /* Store information about the hijacked exported function */
        PageInfo->ExportsHijackInfo.push_back({FuncRVA, HijackRVA, FuncAddress, FuncName, PageInfo});

        HijackedFunctions[FuncAddress] = std::make_pair(PageInfo->Address, 
            PageInfo->ExportsHijackInfo.size() - 1);

        /* 
            Set memory breakpoint on the page (PAGE_GUARD / PAGE_NOACCESS)

            - PAGE_GUARD has race condition issues, so PAGE_NOACCESS has to be used
            - In x64dbg.ini, [Engine], set the variable MembpAlt=1 (setting for TitanEngine)

            Note: As a performance boost, we set it to silent, fast resume and
            set the break condition to never, which is only possible because we handle 
            the memory related exceptions directly in the DebugEvent callback
        */
        ExecCmdSync(
            "SetMemoryBPX %p,1,a;"
            "SetMemoryBreakpointSilent %p;"
            "SetMemoryBreakpointFastResume %p,1;"
            "SetMemoryBreakpointCondition %p,0;",
            PageInfo->Address, PageInfo->Address, PageInfo->Address, PageInfo->Address);

        /* Disable the breakpoint after having created it */
        if(IsDisabled)
            ExecCmdSync("DisableMemoryBreakpoint %p", PageInfo->Address);

#if _PLUGIN_DEBUG

        LogMessage(Utils::StringFormat("Prepared function %s (%p) -> %p for hijacking", FuncName.c_str(), FuncAddress, CopyAddress));

#endif

        return true;
    }

    BOOL Initialize()
    {
        PEB Peb;
        PEB_LDR_DATA PebLdr;

        duint PebAddr = GetPebAddress();

        /* Read the PEB structure */
        if (!DbgMemIsValidReadPtr(PebAddr) || 
            !DbgMemRead(PebAddr, &Peb, sizeof(Peb)))
        {
            LogMessage("Failed to read PEB");

            return false;
        }

        /* Read the PEB_LDR_DATA structure */
        if (!DbgMemRead(reinterpret_cast<duint>(Peb.Ldr), &PebLdr, sizeof(PebLdr)))
        {
            LogMessage("Failed to read PEB_LDR_DATA");

            return false;
        }

        // LogMessage(Utils::StringFormat("PEB @ %p", PebAddr));
        // LogMessage(Utils::StringFormat("PEB_LDR_DATA @ %p", Peb.Ldr));

        /* Set GUI properties */
        ObjExpoMon->ui.TreeExpAccessed->clear();
        ObjExpoMon->ui.TreeExpHijacked->clear();
        ObjExpoMon->ui.LstLog->clear();

        /* Successfully initialized */
        LogMessage("Initialized");

        return (IsInitialized = true);
    }

    BOOL Start()
    {
        if (!IsInitialized && !Initialize())
            return false;

        /* Set GUI properties */
        ObjExpoMon->ui.BtnDisEnableMonitor->setEnabled(true);

        /* Hijack the export directory of all the currently loaded modules */
        HijackLoadedModulesExportDirectory();
        HijackedFunctions.clear();
        BreakOnAddresses.clear();

        return (IsStarted = true);
    }

    VOID Stop()
    {
        if (!IsInitialized || !IsStarted)
            return;

        /* Set GUI properties */
        ObjExpoMon->ui.BtnStartStop->setEnabled(true);
        ObjExpoMon->ui.BtnDisEnableMonitor->setText("Disable Monitoring");
        ObjExpoMon->ui.BtnDisEnableMonitor->setEnabled(false);

        /* Backup the map since elements will get removed in RestoreModuleExportDirectory */
        auto TmpPages = AllocatedPages;

        for (const auto& Page : TmpPages)
        {
            LogMessage(Utils::StringFormat("Cleanup: %s (%p) - %s",
                Page.second.ModuleInfo.Name.c_str(), Page.first,
                (Page.second.IsExportsPage ? "IsExportsPage" : "IsExportsHijackPage")));

            /* Remove the memory breakpoint */
            ExecCmdSync("DeleteMemoryBPX %p", Page.first);

            /* Memory is not freed and modules are not unhooked 
            since the process is going to be terminated */
        }

        AllocatedPages.clear();
        HijackedFunctions.clear();

        IsStarted = false;
    }

    VOID OnLoadDll(duint ModBase, std::string ModName)
    {
        if (!IsInitialized || !IsStarted)
            return;

        /* If ModName is in full file path format, extract just the file name */
        ModName = GetStringAfterChr(ModName, "/\\");

        /* Convert it to lower case */
        std::transform(ModName.begin(), ModName.end(), ModName.begin(),
            [](unsigned char c) { 
                return std::tolower(c);
        });
    
        LogMessage(Utils::StringFormat("[%s,%08X] Hijacking %s",
            __FUNCTION__, DbgGetThreadId(), ModName.c_str()));

        /* Hook the export directory of the newly loaded module */
        HijackModuleExportDirectory(ModBase, ModName, false);
    }

    VOID OnBreakpoint(BRIDGEBP* BpInfo)
    {
        /*
            Since we handle the page guard exceptions in the DebugEvent callback and
            since the memory breakpoints are set to fast resume and to never break,
            the code here does not handle such events
        */
        if (bp_memory == BpInfo->type && IsStarted)
        {
            /* Acquire lock */
            std::lock_guard<std::recursive_mutex> lock(Mutex);

            if (AllocatedPages.find(BpInfo->addr) != AllocatedPages.end())
            {
                LogMessage(Utils::StringFormat("Break at %p", BpInfo->addr));

                /* Show the main cpu/disassembly window */
                GuiShowCpu();
            }
        }
    }

    VOID OnPause()
    {
        /* ... */
    }

    VOID OnDebugEvent(DEBUG_EVENT* DbgEvent)
    {
        /* Information needed to restore the hijacked address */
        static duint HijackedAddress = 0;
        static DWORD HijackedAddressRVA = 0;

        /* Thread id, which generated the exception */
        DWORD ThreadId = DbgEvent->dwThreadId;

        if (DbgEvent->dwDebugEventCode == EXCEPTION_DEBUG_EVENT)
        {
            EXCEPTION_RECORD ExcRecord = DbgEvent->u.Exception.ExceptionRecord;

            duint AccessOperation = ExcRecord.ExceptionInformation[0];
            duint AccessedAddress = ExcRecord.ExceptionInformation[1];

            /* Restore fast resume flags on memory breakpoints */
            RestoreDebuggerBreak();

#if _PLUGIN_DEBUG

            LogMessage(Utils::StringFormat("[%08X] ExCode: %08X, ExAddress: %p", 
                ThreadId, ExcRecord.ExceptionCode, ExcRecord.ExceptionAddress));

#endif

            /*
                PAGE_NOACCESS   -> STATUS_ACCESS_VIOLATION
                PAGE_GUARD      -> STATUS_GUARD_PAGE_VIOLATION
            */
            if (ExcRecord.ExceptionCode == EXCEPTION_ACCESS_VIOLATION)
            {
                duint PageSize = 0;
                duint PageBase = DbgMemFindBaseAddr(AccessedAddress, &PageSize);

                /* Acquire lock */
                std::lock_guard<std::recursive_mutex> lock(Mutex);

#if _PLUGIN_DEBUG

                LogMessage(Utils::StringFormat("[%08X,MEMBP] ExceptionAddress: %p, "
                    "AccessedAddress: %p, PageBase: %p", ThreadId, ExcRecord.ExceptionAddress, AccessedAddress, PageBase));

#endif

                /* Check if the accessed address is inside one of the copied pages */
                if (AllocatedPages.find(PageBase) != AllocatedPages.end())
                {
                    /* Get the registers */
                    REGDUMP RegDump = { 0 }; 
                    DbgGetRegDumpEx(&RegDump, sizeof(RegDump));

                    /* Get the callstack (no cache) */
                    DBGCALLSTACK CallStack = { 0 };
                    DbgFunctions()->GetCallStackEx(&CallStack, false);

#if _PLUGIN_DEBUG

                    LogMessage(Utils::StringFormat("[%08X,MEMBP] Hit inside page (%p)", ThreadId, PageBase));

#endif
                    if (AllocatedPages[PageBase].IsExportsHijackPage)
                    {
                        duint OrigAddress = 0;

                        unsigned int Index = Utils::AlignUp(AccessedAddress - PageBase, (duint)BytesPerFunction) /
                            BytesPerFunction;

                        auto HookInfo = AllocatedPages[PageBase].ExportsHijackInfo[Index];

                        /* Exception triggered on exec, get return address and module name (if possible) */
                        if (AccessOperation == 8)
                        {
                            duint rSP = RegDump.regcontext.csp;

                            if(!DbgMemoryRead((PVOID)rSP, &OrigAddress, sizeof(OrigAddress)))
                                OrigAddress = (duint)ExcRecord.ExceptionAddress;
                        }
                        else
                        {
                            OrigAddress = (duint)ExcRecord.ExceptionAddress;
                        }

                        /* Get the module name at the access origin address */
                        char OrigModName[MAX_MODULE_SIZE] = "<unknown>";

                        if (DbgMemIsValidReadPtr(OrigAddress))
                            DbgGetModuleAt(OrigAddress, OrigModName);

                        /* Log the access to the hijacked function */
                        LogExportsHijacked(AllocatedPages[PageBase].ModuleInfo.Name, 
                            HookInfo.FunctionName, OrigAddress, OrigModName,
                            ThreadId, &RegDump.regcontext, &CallStack, AccessOperation, GetStack());

                        /* If the exception was triggered on exec, redirect rIP */
                        if (AccessOperation == 8)
                            SetContextDataEx(DbgGetThreadHandle(), UE_CIP, HookInfo.FunctionAddress);

#if _PLUGIN_DEBUG

                        LogMessage(Utils::StringFormat("[%08X,MEMBP] Setting rIP to %p [AcsAddr: %p | ExcAddr: %p]", 
                            ThreadId, HookInfo.FunctionAddress, AccessedAddress, (duint)ExcRecord.ExceptionAddress));

#endif
                        bool EvalStatus;

                        if (DoBreakOnCalledHijack &&
                            ((DbgEval(GetHijackCalledBreakCondition().c_str(), &EvalStatus) && EvalStatus) ||
                            ContainsModuleOrFunction(HijackBreakOnModules, HijackBreakOnFunctions,
                            AllocatedPages[PageBase].ModuleInfo.Name, HookInfo.FunctionName)))
                        {
                            ForceDebuggerBreak(PageBase);
                        }
                    }
                    else if (AllocatedPages[PageBase].IsExportsPage &&
                        AccessedAddress >= AllocatedPages[PageBase].Exports.AddressOfFunctions_Start &&
                        AccessedAddress < AllocatedPages[PageBase].Exports.AddressOfFunctions_End )
                    {
                        /* 
                            Check that the page contains exports and that the accessed address is 
                            within the AddressOfFunctions boundary 
                        */

                        std::string FunctionName;

                        /* Calculate the function index based on the accessed address */
                        DWORD FunctionIndex = (DWORD)(AccessedAddress - 
                            AllocatedPages[PageBase].Exports.AddressOfFunctions_Start) / sizeof(DWORD);

                        /* Get the module name at the access origin address */
                        char AccessOriginModName[MAX_MODULE_SIZE] = "<unknown>";

                        if (DbgMemIsValidReadPtr((duint)ExcRecord.ExceptionAddress))
                            DbgGetModuleAt((duint)ExcRecord.ExceptionAddress, AccessOriginModName);
            
                        /* Get the function name based on the calculated index */
                        if (ModuleGetFunctionByIndex(AllocatedPages[PageBase].ModuleInfo.Base,
                            &AllocatedPages[PageBase].ModuleInfo.ExportDirectory, FunctionIndex, FunctionName))
                        {
                            /* Log the access to the exported function's RVA */
                            LogExportsAccess(AllocatedPages[PageBase].ModuleInfo.Name, 
                                FunctionName, (duint)ExcRecord.ExceptionAddress, AccessOriginModName,
                                ThreadId, &RegDump.regcontext, &CallStack, AccessOperation, GetStack());

                            /* Force a debugger break if the module's or function's name match the list */
                            if (DoBreakOnAccess && ContainsModuleOrFunction(AccessBreakOnModules, AccessBreakOnFunctions,
                                AllocatedPages[PageBase].ModuleInfo.Name, FunctionName))
                            {
                                ForceDebuggerBreak(PageBase);
                            }

                            bool EvalStatus;

                            if (DoHijackOnConditions && 
                                ((DbgEval(GetHijackCondition().c_str(), &EvalStatus) && EvalStatus) ||
                                ContainsModuleOrFunction(HijackOnModules, HijackOnFunctions, 
                                    AllocatedPages[PageBase].ModuleInfo.Name, FunctionName)))
                            {
                                if (HijackedAddress == 0 && HijackedAddressRVA == 0)
                                {
                                    DWORD HijackRVA = 0;

                                    /* Read the function's RVA */
                                    DWORD FunctionRVA = 0;

                                    if (DbgMemoryRead((PVOID)AccessedAddress, &FunctionRVA, sizeof(DWORD)))
                                    {
                                        if (PrepareExportedFunctionHijack(FunctionRVA, FunctionName,
                                            AllocatedPages[PageBase].ModuleInfo.Base,
                                            AllocatedPages[PageBase].ModuleInfo.Name,
                                            &AllocatedPages[PageBase].ModuleInfo.ExportDirectory, HijackRVA, false))
                                        {
                                            /* Hijack the function */
                                            if (DbgMemoryWrite((void *)AccessedAddress, &HijackRVA, sizeof(DWORD)))
                                            {
                                                HijackedAddress = AccessedAddress;
                                                HijackedAddressRVA = FunctionRVA;
#if _PLUGIN_DEBUG

                                                LogMessage(Utils::StringFormat("[%08X,MEMBP] Hijacked at address %p -> [%08X -> %08X]", 
                                                    ThreadId, AccessedAddress, HijackedAddressRVA, HijackRVA));

#endif
                                            }
                                            else
                                            {
                                                LogMessage(Utils::StringFormat("Failed to hijack %s (%p)",
                                                    FunctionName.c_str(), AccessedAddress));
                                            }
                                        }
                                    }
                                    else
                                    {
                                        LogMessage(Utils::StringFormat("Failed to read the RVA of function %s (%p)",
                                            FunctionName.c_str(), AccessedAddress));
                                    }
                                }
                            }
                        }
                        else
                        {
                            LogMessage(Utils::StringFormat("Failed to get function name by index (%i)", 
                                FunctionIndex));
                        }
                    }
                }
            }
            else if (ExcRecord.ExceptionCode == EXCEPTION_SINGLE_STEP)
            {
                /* Note: TitanEngine handles single stepping after a PAGE_GUARD / PAGE_NOACCESS exception */
                if (HijackedAddress != 0 && HijackedAddressRVA != 0)
                {
                    /* Restore the RVA in the table */
                    DbgMemoryWrite((void *)HijackedAddress, &HijackedAddressRVA, sizeof(DWORD));
#if _PLUGIN_DEBUG

                    LogMessage(Utils::StringFormat("[%08X,EXCEPTION_SINGLE_STEP] Restoring original RVA at address %p -> %08X", 
                        ThreadId, HijackedAddress, HijackedAddressRVA));

#endif
                    HijackedAddress = 0;
                    HijackedAddressRVA = 0;
                }
            }
        }
        else if (DbgEvent->dwDebugEventCode == CREATE_PROCESS_DEBUG_EVENT)
        {
            /* Nothing... */
        }
        else if (DbgEvent->dwDebugEventCode == LOAD_DLL_DEBUG_EVENT)
        {
            /* Nothing... */
        }
    }
}