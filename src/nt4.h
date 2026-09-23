#pragma once

#include <windows.h>
#include <setupapi.h>
#include <cfgmgr32.h>
#include <shlobj.h>

#ifdef __cplusplus
extern "C" {
#endif

// Every wrapper resolves the real export first, so this header is harmless on W2k+
extern BOOL WINAPI NT4_SetFilePointerEx(HANDLE, LARGE_INTEGER, PLARGE_INTEGER, DWORD);
extern BOOL WINAPI NT4_GetFileSizeEx(HANDLE, PLARGE_INTEGER);
// Open whole-disk objects when the PhysicalDrive DOS alias is absent
extern HANDLE WINAPI NT4_CreateFileA(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
extern LANGID WINAPI NT4_GetUserDefaultUILanguage(void);
extern UINT WINAPI NT4_GetSystemWindowsDirectoryW(LPWSTR, UINT);
extern HWND WINAPI NT4_GetConsoleWindow(void);
extern ULONGLONG WINAPI NT4_VerSetConditionMask(ULONGLONG, DWORD, BYTE);
extern BOOL WINAPI NT4_EnumUILanguagesW(UILANGUAGE_ENUMPROCW, DWORD, LONG_PTR);
extern BOOL WINAPI NT4_GetVolumePathNameA(LPCSTR, LPSTR, DWORD);
extern HANDLE WINAPI NT4_FindFirstVolumeA(LPSTR, DWORD);
extern BOOL WINAPI NT4_FindNextVolumeA(HANDLE, LPSTR, DWORD);
extern BOOL WINAPI NT4_FindVolumeClose(HANDLE);
extern BOOL WINAPI NT4_GetVolumeNameForVolumeMountPointA(LPCSTR, LPSTR, DWORD);
extern BOOL WINAPI NT4_SetVolumeMountPointA(LPCSTR, LPCSTR);
extern BOOL WINAPI NT4_DeleteVolumeMountPointA(LPCSTR);
extern BOOL WINAPI NT4_CreateHardLinkW(LPCWSTR, LPCWSTR, LPSECURITY_ATTRIBUTES);
extern BOOL WINAPI NT4_SetProcessDefaultLayout(DWORD);
extern BOOL WINAPI NT4_FlashWindowEx(PFLASHWINFO);
extern DWORD WINAPI NT4_SetLayout(HDC, DWORD);
extern COLORREF WINAPI NT4_SetDCPenColor(HDC, COLORREF);
extern BOOL WINAPI NT4_ConvertStringSidToSidA(LPCSTR, PSID*);
extern BOOL WINAPI NT4_ConvertSidToStringSidA(PSID, LPSTR*);
extern BOOL WINAPI NT4_CheckTokenMembership(HANDLE, PSID, PBOOL);
extern HRESULT WINAPI NT4_SHGetFolderPathW(HWND, int, HANDLE, DWORD, LPWSTR);
extern BOOL WINAPI NT4_SHGetSpecialFolderPathW(HWND, LPWSTR, int, BOOL);
extern int WINAPI NT4_SHCreateDirectoryExA(HWND, LPCSTR, const SECURITY_ATTRIBUTES*);
extern int WINAPI NT4_SHCreateDirectoryExW(HWND, LPCWSTR, const SECURITY_ATTRIBUTES*);
extern HRESULT WINAPI NT4_SHBindToParent(PCIDLIST_ABSOLUTE, REFIID, void**, PCUITEMID_CHILD*);
extern HRESULT WINAPI NT4_CoWaitForMultipleHandles(DWORD, DWORD, ULONG, LPHANDLE, LPDWORD);
extern DWORD WINAPI NT4_WNetRestoreConnectionA(HWND, LPCSTR);
extern BOOL WINAPI NT4_ExpandEnvironmentStringsForUserW(HANDLE, LPCWSTR, LPWSTR, DWORD);
// Preserve callers that resolve post-NT4 Kernel32 exports dynamically
extern FARPROC WINAPI NT4_GetProcAddress(HMODULE, LPCSTR);
extern HMODULE WINAPI NT4_LoadLibraryExA(LPCSTR, HANDLE, DWORD);

extern CONFIGRET WINAPI NT4_CM_Get_Parent(PDEVINST, DEVINST, ULONG);
extern CONFIGRET WINAPI NT4_CM_Locate_DevNodeA(PDEVINST, DEVINSTID_A, ULONG);
extern CONFIGRET WINAPI NT4_CM_Get_Child(PDEVINST, DEVINST, ULONG);
extern CONFIGRET WINAPI NT4_CM_Get_Device_ID_List_SizeA(PULONG, PCSTR, ULONG);
extern CONFIGRET WINAPI NT4_CM_Get_Sibling(PDEVINST, DEVINST, ULONG);
extern CONFIGRET WINAPI NT4_CM_Get_DevNode_Registry_PropertyA(DEVINST, ULONG, PULONG, PVOID, PULONG, ULONG);
extern CONFIGRET WINAPI NT4_CM_Get_Device_IDA(DEVINST, PCHAR, ULONG, ULONG);
extern CONFIGRET WINAPI NT4_CM_Get_DevNode_Status(PULONG, PULONG, DEVINST, ULONG);
extern CONFIGRET WINAPI NT4_CM_Get_Device_ID_ListA(PCSTR, PCHAR, ULONG, ULONG);
extern BOOL WINAPI NT4_SetupDiEnumDeviceInterfaces(HDEVINFO, PSP_DEVINFO_DATA, const GUID*, DWORD, PSP_DEVICE_INTERFACE_DATA);
extern BOOL WINAPI NT4_SetupDiGetDeviceInterfaceDetailA(HDEVINFO, PSP_DEVICE_INTERFACE_DATA,
	PSP_DEVICE_INTERFACE_DETAIL_DATA_A, DWORD, PDWORD, PSP_DEVINFO_DATA);
// Virtualize the missing NT4 disk-interface subset without changing dev.c enumeration
extern HDEVINFO WINAPI NT4_SetupDiGetClassDevsA(const GUID*, PCSTR, HWND, DWORD);
extern BOOL WINAPI NT4_SetupDiEnumDeviceInfo(HDEVINFO, DWORD, PSP_DEVINFO_DATA);
extern BOOL WINAPI NT4_SetupDiGetDeviceRegistryPropertyA(HDEVINFO, PSP_DEVINFO_DATA,
	DWORD, PDWORD, PBYTE, DWORD, PDWORD);
extern BOOL WINAPI NT4_SetupDiGetDeviceRegistryPropertyW(HDEVINFO, PSP_DEVINFO_DATA,
	DWORD, PDWORD, PBYTE, DWORD, PDWORD);
extern BOOL WINAPI NT4_SetupDiGetDeviceInstanceIdA(HDEVINFO, PSP_DEVINFO_DATA, PSTR, DWORD, PDWORD);
extern BOOL WINAPI NT4_SetupDiDestroyDeviceInfoList(HDEVINFO);
extern int NT4_GetDriveNumberFromPath(const char*);
// NT4 diagnostics
extern BOOL NT4_SetDiskFunction(LPCSTR);
extern BOOL NT4_SetDiskStage(LPCSTR);
extern BOOL NT4_GetDiskDiagnostic(LPCSTR, LPSTR, DWORD);
extern BOOL NT4_ClearDiskDiagnostics(VOID);

#ifdef RUFUS_TARGET_NT4
#define SetFilePointerEx NT4_SetFilePointerEx
#define GetFileSizeEx NT4_GetFileSizeEx
#define CreateFileA NT4_CreateFileA
#define GetUserDefaultUILanguage NT4_GetUserDefaultUILanguage
#define GetSystemWindowsDirectoryW NT4_GetSystemWindowsDirectoryW
#define GetConsoleWindow NT4_GetConsoleWindow
#define VerSetConditionMask NT4_VerSetConditionMask
#define EnumUILanguagesW NT4_EnumUILanguagesW
#define GetVolumePathNameA NT4_GetVolumePathNameA
#define FindFirstVolumeA NT4_FindFirstVolumeA
#define FindNextVolumeA NT4_FindNextVolumeA
#define FindVolumeClose NT4_FindVolumeClose
#define GetVolumeNameForVolumeMountPointA NT4_GetVolumeNameForVolumeMountPointA
#define SetVolumeMountPointA NT4_SetVolumeMountPointA
#define DeleteVolumeMountPointA NT4_DeleteVolumeMountPointA
#define CreateHardLinkW NT4_CreateHardLinkW
#define SetProcessDefaultLayout NT4_SetProcessDefaultLayout
#define FlashWindowEx NT4_FlashWindowEx
#define SetLayout NT4_SetLayout
#define SetDCPenColor NT4_SetDCPenColor
#define ConvertStringSidToSidA NT4_ConvertStringSidToSidA
#define ConvertSidToStringSidA NT4_ConvertSidToStringSidA
#define CheckTokenMembership NT4_CheckTokenMembership
#define SHGetFolderPathW NT4_SHGetFolderPathW
#define SHGetSpecialFolderPathW NT4_SHGetSpecialFolderPathW
#define SHCreateDirectoryExA NT4_SHCreateDirectoryExA
#define SHCreateDirectoryExW NT4_SHCreateDirectoryExW
#define SHBindToParent NT4_SHBindToParent
#define CoWaitForMultipleHandles NT4_CoWaitForMultipleHandles
#define WNetRestoreConnectionA NT4_WNetRestoreConnectionA
#define ExpandEnvironmentStringsForUserW NT4_ExpandEnvironmentStringsForUserW
#define GetProcAddress NT4_GetProcAddress
#define LoadLibraryExA NT4_LoadLibraryExA
#define CM_Get_Parent NT4_CM_Get_Parent
#define CM_Locate_DevNodeA NT4_CM_Locate_DevNodeA
#define CM_Get_Child NT4_CM_Get_Child
#define CM_Get_Device_ID_List_SizeA NT4_CM_Get_Device_ID_List_SizeA
#define CM_Get_Sibling NT4_CM_Get_Sibling
#define CM_Get_DevNode_Registry_PropertyA NT4_CM_Get_DevNode_Registry_PropertyA
#define CM_Get_Device_IDA NT4_CM_Get_Device_IDA
#define CM_Get_DevNode_Status NT4_CM_Get_DevNode_Status
#define CM_Get_Device_ID_ListA NT4_CM_Get_Device_ID_ListA
#define SetupDiEnumDeviceInterfaces NT4_SetupDiEnumDeviceInterfaces
#define SetupDiGetDeviceInterfaceDetailA NT4_SetupDiGetDeviceInterfaceDetailA
#define SetupDiGetClassDevsA NT4_SetupDiGetClassDevsA
#define SetupDiEnumDeviceInfo NT4_SetupDiEnumDeviceInfo
#define SetupDiGetDeviceRegistryPropertyA NT4_SetupDiGetDeviceRegistryPropertyA
#define SetupDiGetDeviceRegistryPropertyW NT4_SetupDiGetDeviceRegistryPropertyW
#define SetupDiGetDeviceInstanceIdA NT4_SetupDiGetDeviceInstanceIdA
#define SetupDiDestroyDeviceInfoList NT4_SetupDiDestroyDeviceInfoList
#endif

#ifdef __cplusplus
}
#endif
