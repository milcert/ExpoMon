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

#ifndef _ExpoMon_H_
#define _ExpoMon_H_

/***************************************************************************/

#include <windows.h>
#include <stdint.h>
#include <inttypes.h>
#include <stdbool.h> 
#include <stdio.h>
#include <stdlib.h>
#include <psapi.h>
#include <string.h>

#include <iostream>
#include <vector>
#include <memory>
#include <mutex>
#include <utility>
#include <regex>
#include <locale>
#include <cctype>
#include <clocale>

/***************************************************************************/

#define ExpoMon_VERSION_INT 100
#define ExpoMon_VERSION_STR "1.0.0"
#define ExpoMon_PLUGIN_NAME_SHORT "ExpoMon"
#define ExpoMon_PLUGIN_NAME_LONG "Exports Monitor"

/***************************************************************************/

#ifndef DLL_EXPORT
    #define DLL_EXPORT __declspec(dllexport)
#endif

#ifndef EXTERN_C
    #define EXTERN_C extern "C"
#endif

#include "PluginSdk/bridgemain.h"
#include "PluginSdk/_plugins.h"

#include "PluginSdk/_scriptapi_argument.h"
#include "PluginSdk/_scriptapi_assembler.h"
#include "PluginSdk/_scriptapi_bookmark.h"
#include "PluginSdk/_scriptapi_comment.h"
#include "PluginSdk/_scriptapi_debug.h"
#include "PluginSdk/_scriptapi_flag.h"
#include "PluginSdk/_scriptapi_function.h"
#include "PluginSdk/_scriptapi_gui.h"
#include "PluginSdk/_scriptapi_label.h"
#include "PluginSdk/_scriptapi_memory.h"
#include "PluginSdk/_scriptapi_misc.h"
#include "PluginSdk/_scriptapi_module.h"
#include "PluginSdk/_scriptapi_pattern.h"
#include "PluginSdk/_scriptapi_register.h"
#include "PluginSdk/_scriptapi_stack.h"
#include "PluginSdk/_scriptapi_symbol.h"

#include "PluginSdk/TitanEngine/TitanEngine.h"

/***************************************************************************/

#ifdef _WIN64
    #pragma comment(lib, ".\\PluginSdk\\x64dbg.lib")
    #pragma comment(lib, ".\\PluginSdk\\x64bridge.lib")
    #pragma comment(lib, ".\\PluginSdk\\TitanEngine\\TitanEngine_x64.lib")
#else
    #pragma comment(lib, ".\\PluginSdk\\x32dbg.lib")
    #pragma comment(lib, ".\\PluginSdk\\x32bridge.lib")
    #pragma comment(lib, ".\\PluginSdk\\TitanEngine\\TitanEngine_x86.lib")
#endif

/***************************************************************************/

namespace ExpoMon
{
    /* Struct that contains several GUI handles (filled by plugsetup) */
    extern PLUG_SETUPSTRUCT Setup;

    /* Plugin handle */
    extern INT Handle;

    /* Plugin module handle */
    extern HMODULE ModuleHandle;

    /* Main logic */
    extern BOOL IsEnabled;
    extern BOOL IsStarted;
    extern BOOL IsInitialized;
    extern BOOL DoBreakOnAccess;
    extern BOOL DoHijackOnConditions;
    extern BOOL DoBreakOnCalledHijack;

    /* Qt functions */
    VOID GuiShow();
    VOID AboutShow();

    /* Callbacks */
    VOID GuiInit();
    VOID GuiDestroy();

    /* Wait functions */
    VOID Wait_GuiInit();
    VOID Wait_GuiDestroy();

    /* Utility functions */
    BOOL DbgMemoryRead(PVOID BaseAddr, PVOID Dst, SIZE_T Size);
    BOOL DbgMemoryWrite(PVOID BaseAddr, PVOID Src, SIZE_T Size);
    std::string GetStringAfterChr(std::string& Str, const char* Sep);
    std::string ReplaceChrInString(std::string& Str, const char* Chr, const char* Rep);
    std::string GetBreakCondition();
    bool ShouldMonitorModule(std::string Module);
    std::vector<std::string> Tokenize(std::string Input);
    VOID SetBreakCondition(std::string Condition);
    VOID SetHijackConditions(std::string Condition, std::string Modules, std::string Functions);
    VOID SetBreakOnHijackCalledConditions(std::string Condition, std::string Modules, std::string Functions);
    VOID SetMonitoredModules(std::string Modules);
    VOID SetBreakOnAccess(std::string Modules, std::string Functions);
    void MemBreakpointsDisable();
    void MemBreakpointsEnable();

    /* Main logic */
    BOOL IsRunning();
    BOOL IsDebugging();
    BOOL Initialize();
    BOOL Start();
    VOID Stop();
    VOID OnLoadDll(duint ModBase, std::string ModName);
    VOID OnBreakpoint(BRIDGEBP* BpInfo);
    VOID OnDebugEvent(DEBUG_EVENT* DbgEvent);
    VOID OnPause();
}

/***************************************************************************/

#endif // _ExpoMon_H_