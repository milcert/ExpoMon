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

/***************************************************************************/

enum PluginMenuItem
{
    ABOUT,
    SHOW
};

/***************************************************************************/

CBTYPE RegisteredCallbacks[] = 
{
    CB_INITDEBUG,
    CB_MENUENTRY,
    CB_DEBUGEVENT,
    CB_BREAKPOINT,
    CB_EXCEPTION,
    CB_STEPPED,
    CB_STOPDEBUG,
    CB_STOPPINGDEBUG,
    CB_PAUSEDEBUG,
    CB_CREATETHREAD,
    CB_LOADDLL,
    CB_DETACH
};

/***************************************************************************/

static
void plugcb(CBTYPE Type, void* CallbackInfo)
{
    switch (Type)
    {
        case CB_MENUENTRY:
        {
            /* Called by x64dbg pluginmenucall() */

            PLUG_CB_MENUENTRY* MenuEntry =
                reinterpret_cast<PLUG_CB_MENUENTRY*>(CallbackInfo);

            if (MenuEntry == nullptr)
                break;

            switch (MenuEntry->hEntry)
            {
                case PluginMenuItem::ABOUT:
                {
                    ExpoMon::AboutShow();
                    break;
                }
                case PluginMenuItem::SHOW:
                {
                    ExpoMon::GuiShow();
                    break;
                }
                default: 
                    break;
            }

            break;
        }
        case CB_DEBUGEVENT:
        {
            /* Called on any debug event */

            PLUG_CB_DEBUGEVENT* DbgEvent =
                reinterpret_cast<PLUG_CB_DEBUGEVENT*>(CallbackInfo);

            if (DbgEvent == nullptr || DbgEvent->DebugEvent == nullptr)
                break;

#if _PLUGIN_DEBUG

            _plugin_logprintf("[DebugEvent,%08X] Address: %p, Code: %08X, NumberParameters: %i, ExcInfo[0]: %p, ExcInfo[1]: %p\n",
                DbgEvent->DebugEvent->dwThreadId,
                DbgEvent->DebugEvent->u.Exception.ExceptionRecord.ExceptionAddress,
                DbgEvent->DebugEvent->u.Exception.ExceptionRecord.ExceptionCode,
                DbgEvent->DebugEvent->u.Exception.ExceptionRecord.NumberParameters,
                DbgEvent->DebugEvent->u.Exception.ExceptionRecord.ExceptionInformation[0],
                DbgEvent->DebugEvent->u.Exception.ExceptionRecord.ExceptionInformation[1]);

#endif

            ExpoMon::OnDebugEvent(DbgEvent->DebugEvent);

            break;
        }
        case CB_BREAKPOINT:
        {
            /* Called on breakpoint event (bp set by the debugger) */

            PLUG_CB_BREAKPOINT* BreakpointInfo =
                reinterpret_cast<PLUG_CB_BREAKPOINT*>(CallbackInfo);

            if (BreakpointInfo == nullptr)
                break;

#if _PLUGIN_DEBUG

            _plugin_logprintf("[CB_BREAKPOINT,%08X] Address: %p, Type: %i\n",
                DbgGetThreadId(),
                BreakpointInfo->breakpoint->addr,
                BreakpointInfo->breakpoint->type);

#endif

            ExpoMon::OnBreakpoint(BreakpointInfo->breakpoint);

            break;
        }
        case CB_STEPPED:
        {
            /* Called on StepIn / StepOver */

            PLUG_CB_STEPPED* StepInfo =
                reinterpret_cast<PLUG_CB_STEPPED*>(CallbackInfo);

            if (StepInfo == nullptr)
                break;

#if _PLUGIN_DEBUG

            _plugin_logprintf("[CB_STEPPED,%08X]\n", DbgGetThreadId());

#endif

            break;
        }
        case CB_EXCEPTION:
        {
            /* Called on DBG_EXCEPTION_NOT_HANDLED */

            PLUG_CB_EXCEPTION* ExceptionInfo =
                reinterpret_cast<PLUG_CB_EXCEPTION*>(CallbackInfo);

            if (ExceptionInfo == nullptr)
                break;

#if _PLUGIN_DEBUG

            _plugin_logprintf("[CB_EXCEPTION,%08X] Address: %p, Code: %08X\n",
                DbgGetThreadId(),
                ExceptionInfo->Exception->ExceptionRecord.ExceptionAddress,
                ExceptionInfo->Exception->ExceptionRecord.ExceptionCode);

#endif

            break;
        }
        case CB_PAUSEDEBUG:
        {
            /* Called on debugger pause. It's generated by the debugger on several occasions */
            ExpoMon::OnPause();

            break;
        }
        case CB_LOADDLL:
        {
            /* Called on LOAD_DLL_DEBUG_EVENT */

            PLUG_CB_LOADDLL* DllInfo =
                reinterpret_cast<PLUG_CB_LOADDLL*>(CallbackInfo);

            if (DllInfo == nullptr || DllInfo->modInfo == nullptr)
                break;

            ExpoMon::OnLoadDll(DllInfo->modInfo->BaseOfImage, 
                DllInfo->modInfo->ImageName);

            break;
        }
        case CB_CREATETHREAD:
        {
            /* Called on CREATE_THREAD_DEBUG_EVENT */
            break;
        }
        case CB_DETACH:
        {
            break;
        }
        case CB_INITDEBUG:
        {
            break;
        }
        case CB_STOPPINGDEBUG:
        {
            /* Disable the plugin before closing/stopping */
            ExpoMon::Stop();
            ExpoMon::IsInitialized = FALSE;

            break;
        }
        default:
        {
            break;
        }
    }
}

/***************************************************************************/

EXTERN_C DLL_EXPORT
VOID plugsetup(PLUG_SETUPSTRUCT* setup)
{
    /*
        This function is called when the plugin initialization was successful.
        Here you can register menus and other GUI-related things
    */
    ExpoMon::Setup = *setup;

    _plugin_menuaddentry(ExpoMon::Setup.hMenu, PluginMenuItem::SHOW, "&Show");
    _plugin_menuaddentry(ExpoMon::Setup.hMenu, PluginMenuItem::ABOUT, "&About");

    GuiExecuteOnGuiThread(ExpoMon::GuiInit);

    ExpoMon::Wait_GuiInit();
}

EXTERN_C DLL_EXPORT
BOOL pluginit(PLUG_INITSTRUCT* init)
{
    ExpoMon::Handle = init->pluginHandle;

    /* Set the required fields */
    init->sdkVersion = PLUG_SDKVERSION;
    init->pluginVersion = ExpoMon_VERSION_INT;

    strcpy_s(init->pluginName, sizeof(init->pluginName), 
        ExpoMon_PLUGIN_NAME_SHORT);

    /* Register callbacks */
    for (size_t i = 0; i < _countof(RegisteredCallbacks); i++)
        _plugin_registercallback(ExpoMon::Handle, RegisteredCallbacks[i], plugcb);

    return TRUE;
}

EXTERN_C DLL_EXPORT
BOOL plugstop()
{
    /*
        Called when the plugin is about to be unloaded. 
        Remove all registered commands and callbacks here (perform cleanup)
    */
    _plugin_menuclear(ExpoMon::Setup.hMenu);

    for (size_t i = 0; i < _countof(RegisteredCallbacks); i++)
        _plugin_unregistercallback(ExpoMon::Handle, RegisteredCallbacks[i]);

    /* Qt cleanup */
    GuiExecuteOnGuiThread(ExpoMon::GuiDestroy);

    ExpoMon::Wait_GuiDestroy();

    return TRUE;
}
