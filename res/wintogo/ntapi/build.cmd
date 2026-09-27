@echo off
setlocal

rem Build a 32-bit object without the Microsoft C runtime.
cl /nologo /O2 /GS- /Zl /W4 /c ntapi.c
if errorlevel 1 exit /b 1

rem Link at the oldest version accepted by current link.exe.  The PE header is
rem changed to NT 4.0 immediately afterward.
link /nologo /DLL /NODEFAULTLIB /ENTRY:ShimDllMain@12 /MACHINE:X86 ^
 /SUBSYSTEM:WINDOWS,5.01 /DYNAMICBASE:NO /NXCOMPAT:NO /MANIFEST:NO ^
 /INCREMENTAL:NO /OPT:REF /OPT:ICF /OUT:ntapi.dll ^
 ntapi.obj /DEF:ntapi.def kernel32.lib advapi32.lib ole32.lib shell32.lib setupapi.lib mpr.lib ntdll.lib
if errorlevel 1 exit /b 1

rem Modern Microsoft linkers reject subsystem 4.0 even though NT 4 accepts it.
rem Patch Major/MinorOperatingSystemVersion and Major/MinorSubsystemVersion in
rem the PE32 optional header.  Windows 7 includes PowerShell 2.0.
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "$p=[IO.Path]::GetFullPath('ntapi.dll');$b=[IO.File]::ReadAllBytes($p);$pe=[BitConverter]::ToInt32($b,60);if($b[$pe] -ne 80 -or $b[$pe+1] -ne 69){throw 'Invalid PE signature'};$o=$pe+24;if([BitConverter]::ToUInt16($b,$o) -ne 267){throw 'ntapi.dll is not PE32'};[BitConverter]::GetBytes([UInt16]4).CopyTo($b,$o+40);[BitConverter]::GetBytes([UInt16]0).CopyTo($b,$o+42);[BitConverter]::GetBytes([UInt16]4).CopyTo($b,$o+48);[BitConverter]::GetBytes([UInt16]0).CopyTo($b,$o+50);[IO.File]::WriteAllBytes($p,$b)"
if errorlevel 1 exit /b 1

rem Display the final public surface so it can be captured with test results.
dumpbin /nologo /headers ntapi.dll | findstr /i /c:"operating system version" /c:"subsystem version" /c:"machine"
dumpbin /nologo /exports ntapi.dll
exit /b 0
