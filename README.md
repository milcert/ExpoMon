# ExpoMon

ExpoMon is a plugin developed by milCERT.ch, the Swiss Military CERT, for [x64dbg](https://github.com/x64dbg/x64dbg) with the goal to assist a reverse engineer during dynamic analysis of malicious binaries when they resolve APIs, e.g. with functions such as `GetProcAddress`, `LdrGetProcedureAddress`, etc. or a custom implementation of those functions. In theory, the plugin monitors access to a module's `IMAGE_EXPORT_DIRECTORY.AddressOfFunctions` array, which is usually accessed when resolving an exported function's address via the Export Address Table (EAT); in practice, in favor of increased performance, the plugin monitors access to a cloned page of the memory page containing the module's EAT with `IMAGE_EXPORT_DIRECTORY.AddressOfFunctions` hijacked to point to it.

## Features

- Logs context information on access to the address containing the RVA of an exported function
- Hijacks the accessed exported functions (RVA hijack)

## Known limitations (by design)

- Cannot handle cases where pattern scanning is used to find the functions
- Cannot handle cases where hardcoded relative offsets are used to find the functions
- Cannot handle direct syscalls

# Install

- Download or compile the plugin
	- Compiled with
		- Visual Studio 2013 with Qt Visual Studio Tools version 2.3.2
		- Qt 5.6.3 (x64/x86 msvc2013)
		- Qt Creator 4.3.1 
- Copy the plugin to the `plugins` directory
	- `release\x64\plugins\ExpoMon.dp64`
	- `release\x32\plugins\ExpoMon.dp32`
- Set or add `MembpAlt=1` to the `[Engine]` section in `x64dbg.ini`
	- This configures memory breakpoints to use `PAGE_NOACCESS` instead of `PAGE_GUARD`

# Usage

- If it is not visiable in the tabs
	- `Plugins > ExpoMon > Show`
	
- To enable the exports monitoring: `Monitor Exports`
	- This will monitor the access to the exports of all the currently loaded modules
		- In the `Settings` tab it is possible to configure to only monitor specific modules
	- Modules that are loaded at a later stage are also automatically monitored (`CB_LOADDLL` / `LOAD_DLL_DEBUG_EVENT`)

- To temporarily disable any monitoring: `Disable Monitoring`
	- Internally executes the `DisableMemoryBreakpoint` command on every monitored memory page
	
- To completely remove and disable the monitoring: `Reset`
	- This may potentially lead to a crash / unhandled exceptions, due to the fact that there may still be pointers in use to the monitored pages, which will be freed, causing invalid memory access
	
- In the `Settings` tab it is possible to configure the conditions for breaking and hijacking
	- The conditions use the internal scripting engine (https://help.x64dbg.com/en/latest/introduction/index.html)
	- Module and function names can be separated by a `,` and `;` or a newline
		- The check performs an needle/substring search so that adding file extensions is not required
		
# Screenshots

![Accessed Exports](Assets/img01.png)

![Hijacked Exports](Assets/img02.png)

# License

MIT License
