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

#ifndef _WININTERNALS_H_
#define _WININTERNALS_H_

/***************************************************************************/

#include <windows.h>
#include <winnt.h>
#include <stdint.h>
#include <stdbool.h> 

/***************************************************************************/

typedef struct _UNICODE_STRING 
{
    USHORT                          Length;
    USHORT                          MaximumLength;
    PWSTR                           Buffer;

} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _PEB_LDR_DATA
{
    ULONG                           Length;
    BOOLEAN                         Initialized;
    PVOID                           SsHandle;
    LIST_ENTRY                      InLoadOrderModuleList;
    LIST_ENTRY                      InMemoryOrderModuleList;
    LIST_ENTRY                      InInitializationOrderModuleList;
    PVOID                           EntryInProgress;

} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _LDR_DATA_TABLE_ENTRY
{
    LIST_ENTRY                      InLoadOrderLinks;
    LIST_ENTRY                      InMemoryOrderModuleList;
    LIST_ENTRY                      InInitializationOrderModuleList;
    PVOID                           DllBase;
    PVOID                           EntryPoint;
    ULONG                           SizeOfImage;
    UNICODE_STRING                  FullDllName;
    UNICODE_STRING                  BaseDllName;
    ULONG                           Flags;
    USHORT                          LoadCount;
    USHORT                          TlsIndex;

    union
    {
        LIST_ENTRY                  HashLinks;
        PVOID                       SectionPointer;
    };

    ULONG CheckSum;

    union
    {
        ULONG                       TimeDateStamp;
        PVOID                       LoadedImports;
    };

    PVOID                           EntryPointActivationContext;
    PVOID                           PatchInformation;

} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

typedef struct _PEB 
{
    BYTE                            Reserved1[2];
    BYTE                            BeingDebugged;
    BYTE                            Reserved2[1];
    PVOID                           Reserved3[2];
    PPEB_LDR_DATA                   Ldr;
    PVOID                           ProcessParameters;

} PEB, *PPEB;

#endif // _WININTERNALS_H_