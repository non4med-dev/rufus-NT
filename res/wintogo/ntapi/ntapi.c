/*
 * ntapi.c - Windows NT 4.0 compatibility layer for the supplied wimgapi and
 * bcdboot import sets.
 *
 * Native NT4 exports are forwarded by ntapi.def.  This file implements only
 * APIs absent from NT4.  It is intentionally x86-only and has no C runtime
 * dependency.
 *
 * Build from an x86 Native Tools Command Prompt by running build-ntapi.cmd.
 * The build script also stamps the PE operating-system and subsystem versions
 * to 4.0, which current Microsoft linkers no longer accept directly.
 */

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0400
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#if !defined(_MSC_VER) || !defined(_M_IX86)
#error ntapi.dll must be built as x86 with Microsoft-compatible tools.
#endif

#ifndef ERROR_CALL_NOT_IMPLEMENTED
#define ERROR_CALL_NOT_IMPLEMENTED 120L
#endif
#ifndef ERROR_NO_MORE_ITEMS
#define ERROR_NO_MORE_ITEMS 259L
#endif
#ifndef ERROR_INVALID_SID
#define ERROR_INVALID_SID 1337L
#endif
#ifndef ERROR_INVALID_ACL
#define ERROR_INVALID_ACL 1336L
#endif
#ifndef LMEM_FIXED
#define LMEM_FIXED 0x0000
#endif
#ifndef LMEM_ZEROINIT
#define LMEM_ZEROINIT 0x0040
#endif
#ifndef ERROR_UNKNOWN_REVISION
#define ERROR_UNKNOWN_REVISION 1305L
#endif
#ifndef ERROR_NONE_MAPPED
#define ERROR_NONE_MAPPED 1332L
#endif
#ifndef ERROR_INVALID_NAME
#define ERROR_INVALID_NAME 123L
#endif
#ifndef ERROR_FILENAME_EXCED_RANGE
#define ERROR_FILENAME_EXCED_RANGE 206L
#endif
#ifndef COWAIT_WAITALL
#define COWAIT_WAITALL 0x00000001
#define COWAIT_ALERTABLE 0x00000002
#define COWAIT_INPUTAVAILABLE 0x00000004
#endif
#ifndef QS_ALLINPUT
#define QS_ALLINPUT 0x04FF
#endif
#ifndef PM_REMOVE
#define PM_REMOVE 0x0001
#endif
#ifndef RPC_S_CALLPENDING
#define RPC_S_CALLPENDING ((HRESULT)0x80010115L)
#endif
#ifndef RPC_E_NO_SYNC
#define RPC_E_NO_SYNC ((HRESULT)0x80010120L)
#endif
#ifndef E_INVALIDARG
#define E_INVALIDARG ((HRESULT)0x80070057L)
#endif
#ifndef E_POINTER
#define E_POINTER ((HRESULT)0x80004003L)
#endif
#ifndef COWAIT_DISPATCH_CALLS
#define COWAIT_DISPATCH_CALLS 0x00000008
#define COWAIT_DISPATCH_WINDOW_MESSAGES 0x00000010
#endif
#ifndef SDDL_REVISION_1
#define SDDL_REVISION_1 1
#endif
#ifndef WAIT_IO_COMPLETION
#define WAIT_IO_COMPLETION 0x000000C0L
#endif
#ifndef SE_DACL_AUTO_INHERIT_REQ
#define SE_DACL_AUTO_INHERIT_REQ 0x0100
#define SE_SACL_AUTO_INHERIT_REQ 0x0200
#define SE_DACL_AUTO_INHERITED 0x0400
#define SE_SACL_AUTO_INHERITED 0x0800
#define SE_DACL_PROTECTED 0x1000
#define SE_SACL_PROTECTED 0x2000
#define SE_SELF_RELATIVE 0x8000
#endif

#define SHIM_STATUS_SUCCESS ((LONG)0x00000000L)
#define SHIM_STATUS_INVALID_PARAMETER ((LONG)0xC000000DL)
#define SHIM_STATUS_NO_MEMORY ((LONG)0xC0000017L)
#define SHIM_STATUS_BUFFER_TOO_SMALL ((LONG)0xC0000023L)
#define SHIM_STATUS_INVALID_SID ((LONG)0xC0000078L)
#define SHIM_STATUS_INVALID_ACL ((LONG)0xC0000077L)
#define SHIM_HRESULT_FROM_WIN32(error) \
    ((HRESULT)(error) <= 0 ? (HRESULT)(error) : \
     (HRESULT)(((error) & 0xffff) | 0x80070000L))

#define SHIM_SD_OWNER 0x01
#define SHIM_SD_GROUP 0x02
#define SHIM_SD_DACL  0x04
#define SHIM_SD_SACL  0x08

#define SHIM_SID_MAX_SUB_AUTHORITIES 15
#define SHIM_SID_TEXT_CAPACITY 184

typedef struct _SHIM_UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
} SHIM_UNICODE_STRING, *PSHIM_UNICODE_STRING;

typedef struct _SHIM_RTL_OSVERSIONINFOW {
    ULONG dwOSVersionInfoSize;
    ULONG dwMajorVersion;
    ULONG dwMinorVersion;
    ULONG dwBuildNumber;
    ULONG dwPlatformId;
    WCHAR szCSDVersion[128];
} SHIM_RTL_OSVERSIONINFOW, *PSHIM_RTL_OSVERSIONINFOW;

typedef struct _SHIM_RTL_OSVERSIONINFOEXW {
    ULONG dwOSVersionInfoSize;
    ULONG dwMajorVersion;
    ULONG dwMinorVersion;
    ULONG dwBuildNumber;
    ULONG dwPlatformId;
    WCHAR szCSDVersion[128];
    USHORT wServicePackMajor;
    USHORT wServicePackMinor;
    USHORT wSuiteMask;
    BYTE wProductType;
    BYTE wReserved;
} SHIM_RTL_OSVERSIONINFOEXW;

typedef struct _SHIM_SECURITY_DESCRIPTOR_RELATIVE {
    BYTE Revision;
    BYTE Sbz1;
    SECURITY_DESCRIPTOR_CONTROL Control;
    DWORD Owner;
    DWORD Group;
    DWORD Sacl;
    DWORD Dacl;
} SHIM_SECURITY_DESCRIPTOR_RELATIVE;

typedef struct _SHIM_SID {
    BYTE Revision;
    BYTE SubAuthorityCount;
    SID_IDENTIFIER_AUTHORITY IdentifierAuthority;
    DWORD SubAuthority[1];
} SHIM_SID;

typedef LONG (WINAPI *PFN_RTL_ADD_ACE)(PACL, ULONG, ULONG, PVOID, ULONG);
typedef BOOLEAN (WINAPI *PFN_RTL_VALID_SID)(PSID);
typedef ULONG (WINAPI *PFN_RTL_LENGTH_SID)(PSID);
typedef ULONG (WINAPI *PFN_RTL_NTSTATUS_TO_DOS_ERROR)(LONG);
typedef LONG (WINAPI *PFN_RTL_CONVERT_SID_TO_UNICODE_STRING)(
    PSHIM_UNICODE_STRING, PSID, BOOLEAN);
typedef DWORD (WINAPI *PFN_WNET_RESTORE_CONNECTION_W)(HWND, LPCWSTR);
typedef DWORD (WINAPI *PFN_MSG_WAIT_FOR_MULTIPLE_OBJECTS)(DWORD,
    const HANDLE *, BOOL, DWORD, DWORD);
typedef BOOL (WINAPI *PFN_PEEK_MESSAGE_W)(LPMSG, HWND, UINT, UINT, UINT);
typedef BOOL (WINAPI *PFN_TRANSLATE_MESSAGE)(const MSG *);
typedef LRESULT (WINAPI *PFN_DISPATCH_MESSAGE_W)(const MSG *);
typedef DWORD (WINAPI *PFN_SLEEP_EX)(DWORD, BOOL);
typedef BOOL (WINAPI *PFN_EXPAND_ENVIRONMENT_STRINGS_FOR_USER_W)(
    HANDLE, LPCWSTR, LPWSTR, DWORD);
typedef BOOL (WINAPI *PFN_BIND_IO_COMPLETION_CALLBACK)(
    HANDLE, LPOVERLAPPED_COMPLETION_ROUTINE, ULONG);
typedef BOOL (WINAPI *PFN_GET_VOLUME_PATH_NAME_W)(LPCWSTR, LPWSTR, DWORD);
typedef LANGID (WINAPI *PFN_GET_UI_LANGUAGE)(VOID);
typedef DWORD (WINAPI *PFN_OPEN_ENCRYPTED_FILE_RAW_W)(
    LPCWSTR, ULONG, PVOID *);
typedef DWORD (WINAPI *PFN_ENCRYPTED_FILE_RAW)(PVOID, PVOID, PVOID);
typedef VOID (WINAPI *PFN_CLOSE_ENCRYPTED_FILE_RAW)(PVOID);
typedef BOOL (WINAPI *PFN_SETUP_DI_ENUM_DEVICE_INTERFACES)(
    PVOID, PVOID, const GUID *, DWORD, PVOID);
typedef LONG (WINAPI *PFN_RTL_GET_VERSION)(PSHIM_RTL_OSVERSIONINFOW);
typedef BOOL (WINAPI *PFN_CONVERT_STRING_SECURITY_DESCRIPTOR_W)(
    LPCWSTR, DWORD, PSECURITY_DESCRIPTOR *, PULONG);
typedef BOOL (WINAPI *PFN_CONVERT_SID_TO_STRING_SID_W)(PSID, LPWSTR *);
typedef HRESULT (WINAPI *PFN_CO_WAIT_FOR_MULTIPLE_HANDLES)(
    DWORD, DWORD, ULONG, const HANDLE *, LPDWORD);

typedef struct _SHIM_ITEMIDLIST {
    USHORT cb;
    BYTE data[1];
} SHIM_ITEMIDLIST;

typedef struct _SHIM_SHELL_FOLDER SHIM_SHELL_FOLDER;
typedef struct _SHIM_SHELL_FOLDER_VTBL {
    HRESULT (WINAPI *QueryInterface)(SHIM_SHELL_FOLDER *, const GUID *,
                                     PVOID *);
    ULONG (WINAPI *AddRef)(SHIM_SHELL_FOLDER *);
    ULONG (WINAPI *Release)(SHIM_SHELL_FOLDER *);
    HRESULT (WINAPI *ParseDisplayName)(SHIM_SHELL_FOLDER *, HWND, PVOID,
                                       LPWSTR, ULONG *, PVOID *, ULONG *);
    HRESULT (WINAPI *EnumObjects)(SHIM_SHELL_FOLDER *, HWND, DWORD, PVOID *);
    HRESULT (WINAPI *BindToObject)(SHIM_SHELL_FOLDER *,
                                   const SHIM_ITEMIDLIST *, PVOID,
                                   const GUID *, PVOID *);
} SHIM_SHELL_FOLDER_VTBL;

struct _SHIM_SHELL_FOLDER {
    const SHIM_SHELL_FOLDER_VTBL *lpVtbl;
};

typedef HRESULT (WINAPI *PFN_SH_GET_DESKTOP_FOLDER)(SHIM_SHELL_FOLDER **);
typedef HRESULT (WINAPI *PFN_SH_BIND_TO_PARENT)(
    const SHIM_ITEMIDLIST *, const GUID *, PVOID *,
    const SHIM_ITEMIDLIST **);

typedef struct _SHIM_SID_ALIAS {
    WCHAR first;
    WCHAR second;
    BYTE authority;
    BYTE count;
    DWORD sub_authority[2];
} SHIM_SID_ALIAS;

static HMODULE g_ntdll;
static HMODULE g_kernel32;
static HMODULE g_advapi32;
static HMODULE g_ole32;
static HMODULE g_setupapi;
static HMODULE g_mpr;
static HMODULE g_user32;
static HMODULE g_userenv;
static HMODULE g_shell32;
static HANDLE g_completion_port;
static LONG g_completion_worker_state;

static HMODULE
ShimModule(HMODULE *slot, LPCSTR name)
{
    HMODULE module;
    HMODULE previous;

    module = *slot;
    if (module != NULL)
        return module;
    /* Own a reference so the cached handle cannot become stale on unload. */
    module = LoadLibraryA(name);
    if (module == NULL)
        return NULL;
    previous = (HMODULE)InterlockedCompareExchange((LONG *)slot,
                                                   (LONG)module, 0);
    if (previous != NULL) {
        /* Another thread won the race; release this thread's reference. */
        FreeLibrary(module);
        module = previous;
    }
    return module;
}

static FARPROC
ShimProcedure(HMODULE *slot, LPCSTR module_name, LPCSTR procedure_name)
{
    HMODULE module;

    module = ShimModule(slot, module_name);
    if (module == NULL)
        return NULL;
    return GetProcAddress(module, procedure_name);
}

static ULONG
ShimAlign4(ULONG value)
{
    return (value + 3U) & ~3U;
}

static VOID
ShimCopyBytes(PVOID destination, const VOID *source, ULONG size)
{
    BYTE *output;
    const BYTE *input;

    output = (BYTE *)destination;
    input = (const BYTE *)source;
    while (size-- != 0)
        *output++ = *input++;
}

static VOID
ShimZeroBytes(PVOID destination, ULONG size)
{
    BYTE *output;

    output = (BYTE *)destination;
    while (size-- != 0)
        *output++ = 0;
}

BOOL WINAPI
ShimDllMain(HINSTANCE instance, DWORD reason, LPVOID reserved)
{
    if (reason == DLL_PROCESS_ATTACH)
        DisableThreadLibraryCalls(instance);
    (void)reserved;
    return TRUE;
}

BOOL WINAPI
ShimGetFileSizeEx(HANDLE file, PLARGE_INTEGER size)
{
    DWORD low;
    DWORD high;
    DWORD error;

    if (size == NULL) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    SetLastError(NO_ERROR);
    low = GetFileSize(file, &high);
    error = GetLastError();
    if (low == INVALID_FILE_SIZE && error != NO_ERROR)
        return FALSE;
    size->LowPart = low;
    size->HighPart = (LONG)high;
    SetLastError(error);
    return TRUE;
}

BOOL WINAPI
ShimSetFilePointerEx(HANDLE file, LARGE_INTEGER distance,
                     PLARGE_INTEGER new_position, DWORD move_method)
{
    LONG high;
    DWORD low;
    DWORD error;

    high = distance.HighPart;
    SetLastError(NO_ERROR);
    low = SetFilePointer(file, (LONG)distance.LowPart, &high, move_method);
    error = GetLastError();
    if (low == INVALID_SET_FILE_POINTER && error != NO_ERROR)
        return FALSE;
    if (new_position != NULL) {
        new_position->LowPart = low;
        new_position->HighPart = high;
    }
    SetLastError(error);
    return TRUE;
}

LANGID WINAPI
ShimGetUserDefaultUILanguage(VOID)
{
    PFN_GET_UI_LANGUAGE native_function;

    native_function = (PFN_GET_UI_LANGUAGE)
        ShimProcedure(&g_kernel32, "kernel32.dll",
                      "GetUserDefaultUILanguage");
    if (native_function != NULL)
        return native_function();
    return GetUserDefaultLangID();
}

LANGID WINAPI
ShimGetSystemDefaultUILanguage(VOID)
{
    PFN_GET_UI_LANGUAGE native_function;

    native_function = (PFN_GET_UI_LANGUAGE)
        ShimProcedure(&g_kernel32, "kernel32.dll",
                      "GetSystemDefaultUILanguage");
    if (native_function != NULL)
        return native_function();
    return GetSystemDefaultLangID();
}

DWORD WINAPI
ShimOpenEncryptedFileRawW(LPCWSTR file_name, ULONG flags, PVOID *context)
{
    PFN_OPEN_ENCRYPTED_FILE_RAW_W native_function;

    native_function = (PFN_OPEN_ENCRYPTED_FILE_RAW_W)
        ShimProcedure(&g_advapi32, "advapi32.dll", "OpenEncryptedFileRawW");
    if (native_function != NULL)
        return native_function(file_name, flags, context);
    (void)file_name;
    (void)flags;
    if (context != NULL)
        *context = NULL;
    return ERROR_CALL_NOT_IMPLEMENTED;
}

DWORD WINAPI
ShimReadEncryptedFileRaw(PVOID callback, PVOID callback_context,
                         PVOID context)
{
    PFN_ENCRYPTED_FILE_RAW native_function;

    native_function = (PFN_ENCRYPTED_FILE_RAW)
        ShimProcedure(&g_advapi32, "advapi32.dll", "ReadEncryptedFileRaw");
    if (native_function != NULL)
        return native_function(callback, callback_context, context);
    (void)callback;
    (void)callback_context;
    (void)context;
    return ERROR_CALL_NOT_IMPLEMENTED;
}

DWORD WINAPI
ShimWriteEncryptedFileRaw(PVOID callback, PVOID callback_context,
                          PVOID context)
{
    PFN_ENCRYPTED_FILE_RAW native_function;

    native_function = (PFN_ENCRYPTED_FILE_RAW)
        ShimProcedure(&g_advapi32, "advapi32.dll", "WriteEncryptedFileRaw");
    if (native_function != NULL)
        return native_function(callback, callback_context, context);
    (void)callback;
    (void)callback_context;
    (void)context;
    return ERROR_CALL_NOT_IMPLEMENTED;
}

VOID WINAPI
ShimCloseEncryptedFileRaw(PVOID context)
{
    PFN_CLOSE_ENCRYPTED_FILE_RAW native_function;

    native_function = (PFN_CLOSE_ENCRYPTED_FILE_RAW)
        ShimProcedure(&g_advapi32, "advapi32.dll", "CloseEncryptedFileRaw");
    if (native_function != NULL) {
        native_function(context);
        return;
    }
    (void)context;
}

BOOL WINAPI
ShimSetupDiEnumDeviceInterfaces(PVOID device_info_set,
                                PVOID device_info_data,
                                const GUID *interface_class_guid,
                                DWORD member_index,
                                PVOID device_interface_data)
{
    PFN_SETUP_DI_ENUM_DEVICE_INTERFACES native_function;

    native_function = (PFN_SETUP_DI_ENUM_DEVICE_INTERFACES)
        ShimProcedure(&g_setupapi, "setupapi.dll",
                      "SetupDiEnumDeviceInterfaces");
    if (native_function != NULL)
        return native_function(device_info_set, device_info_data,
                               interface_class_guid, member_index,
                               device_interface_data);
    (void)device_info_set;
    (void)device_info_data;
    (void)interface_class_guid;
    (void)member_index;
    (void)device_interface_data;
    SetLastError(ERROR_NO_MORE_ITEMS);
    return FALSE;
}

VOID WINAPI
ShimShellOrdinal526(VOID)
{
}

BOOL WINAPI
ShimGetVolumePathNameW(LPCWSTR file_name, LPWSTR volume_path,
                       DWORD buffer_length)
{
    PFN_GET_VOLUME_PATH_NAME_W native_function;
    WCHAR full_path[MAX_PATH];
    DWORD length;
    DWORD root_length;
    DWORD server_end;
    DWORD share_end;

    native_function = (PFN_GET_VOLUME_PATH_NAME_W)
        ShimProcedure(&g_kernel32, "kernel32.dll", "GetVolumePathNameW");
    if (native_function != NULL)
        return native_function(file_name, volume_path, buffer_length);
    if (file_name == NULL || volume_path == NULL || buffer_length == 0) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    length = GetFullPathNameW(file_name, MAX_PATH, full_path, NULL);
    if (length == 0 || length >= MAX_PATH)
        return FALSE;

    if (full_path[0] == L'\\' && full_path[1] == L'\\') {
        if ((full_path[2] == L'?' || full_path[2] == L'.') &&
            full_path[3] == L'\\' &&
            (full_path[4] == L'U' || full_path[4] == L'u') &&
            (full_path[5] == L'N' || full_path[5] == L'n') &&
            (full_path[6] == L'C' || full_path[6] == L'c') &&
            full_path[7] == L'\\')
            server_end = 8;
        else
            server_end = 2;
        length = server_end;
        while (full_path[server_end] != L'\0' &&
               full_path[server_end] != L'\\' &&
               full_path[server_end] != L'/')
            ++server_end;
        if (server_end == length || full_path[server_end] == L'\0') {
            SetLastError(ERROR_INVALID_NAME);
            return FALSE;
        }
        share_end = server_end + 1;
        while (full_path[share_end] != L'\0' &&
               full_path[share_end] != L'\\' &&
               full_path[share_end] != L'/')
            ++share_end;
        if (share_end == server_end + 1) {
            SetLastError(ERROR_INVALID_NAME);
            return FALSE;
        }
        root_length = share_end + 1;
    } else if (full_path[0] != L'\0' && full_path[1] == L':') {
        root_length = 3;
    } else {
        SetLastError(ERROR_INVALID_NAME);
        return FALSE;
    }
    if (root_length + 1 > buffer_length) {
        SetLastError(ERROR_FILENAME_EXCED_RANGE);
        return FALSE;
    }
    for (length = 0; length + 1 < root_length; ++length)
        volume_path[length] = full_path[length];
    volume_path[root_length - 1] = L'\\';
    volume_path[root_length] = L'\0';
    return TRUE;
}

DWORD WINAPI
ShimWNetRestoreConnectionA(HWND window, LPCSTR device)
{
    PFN_WNET_RESTORE_CONNECTION_W function;
    WCHAR stack_buffer[MAX_PATH];
    WCHAR *wide_device;
    int required;
    DWORD result;

    function = (PFN_WNET_RESTORE_CONNECTION_W)
        ShimProcedure(&g_mpr, "mpr.dll", "WNetRestoreConnectionW");
    if (function == NULL)
        return ERROR_CALL_NOT_IMPLEMENTED;
    if (device == NULL)
        return function(window, NULL);
    required = MultiByteToWideChar(CP_ACP, 0, device, -1, NULL, 0);
    if (required == 0)
        return GetLastError();
    wide_device = stack_buffer;
    if ((DWORD)required > MAX_PATH) {
        wide_device = (WCHAR *)HeapAlloc(GetProcessHeap(), 0,
                                        (SIZE_T)required * sizeof(WCHAR));
        if (wide_device == NULL)
            return ERROR_NOT_ENOUGH_MEMORY;
    }
    if (MultiByteToWideChar(CP_ACP, 0, device, -1, wide_device,
                            required) == 0) {
        result = GetLastError();
    } else {
        result = function(window, wide_device);
    }
    if (wide_device != stack_buffer)
        HeapFree(GetProcessHeap(), 0, wide_device);
    return result;
}

// Test
DWORD WINAPI
ShimWNetRestoreConnectionW(HWND window, LPCWSTR device)
{
    PFN_WNET_RESTORE_CONNECTION_W function;

    function = (PFN_WNET_RESTORE_CONNECTION_W)
        ShimProcedure(&g_mpr, "mpr.dll", "WNetRestoreConnectionW");
    if (function == NULL)
        return ERROR_CALL_NOT_IMPLEMENTED;

    return function(window, device);
}

LONG WINAPI
ShimRtlGetVersion(PSHIM_RTL_OSVERSIONINFOW information)
{
    PFN_RTL_GET_VERSION native_function;
    SHIM_RTL_OSVERSIONINFOEXW native_information;
    ULONG requested_size;
    ULONG returned_size;

    // Fix: Validate pointer FIRST to avoid crashing native_function
    if (information == NULL)
        return SHIM_STATUS_INVALID_PARAMETER;

    native_function = (PFN_RTL_GET_VERSION)
        ShimProcedure(&g_ntdll, "ntdll.dll", "RtlGetVersion");
    if (native_function != NULL)
        return native_function(information);

    requested_size = information->dwOSVersionInfoSize;
    if (requested_size != sizeof(SHIM_RTL_OSVERSIONINFOW) &&
        requested_size != sizeof(SHIM_RTL_OSVERSIONINFOEXW))
        return SHIM_STATUS_INVALID_PARAMETER;

    ShimZeroBytes(&native_information, sizeof(native_information));
    native_information.dwOSVersionInfoSize = requested_size;
    returned_size = requested_size;

    // Suppress MSVC C4996 deprecation warning
#pragma warning(push)
#pragma warning(disable: 4996)
    if (!GetVersionExW((OSVERSIONINFOW *)&native_information)) {
        ShimZeroBytes(&native_information, sizeof(native_information));
        native_information.dwOSVersionInfoSize =
            sizeof(SHIM_RTL_OSVERSIONINFOW);
        returned_size = sizeof(SHIM_RTL_OSVERSIONINFOW);
        if (!GetVersionExW((OSVERSIONINFOW *)&native_information)) {
            return SHIM_STATUS_INVALID_PARAMETER;
        }
    }
#pragma warning(pop)

    ShimZeroBytes(information, requested_size);
    ShimCopyBytes(information, &native_information, returned_size);
    information->dwOSVersionInfoSize = requested_size;
    return SHIM_STATUS_SUCCESS;
}

static int
ShimHexValue(WCHAR character)
{
    if (character >= L'0' && character <= L'9')
        return character - L'0';
    if (character >= L'a' && character <= L'f')
        return character - L'a' + 10;
    if (character >= L'A' && character <= L'F')
        return character - L'A' + 10;
    return -1;
}

static BOOL
ShimParseHex(LPCWSTR text, ULONG count, ULONG *value)
{
    ULONG result;
    ULONG index;
    int digit;

    result = 0;
    for (index = 0; index < count; ++index) {
        digit = ShimHexValue(text[index]);
        if (digit < 0)
            return FALSE;
        result = (result << 4) | (ULONG)digit;
    }
    *value = result;
    return TRUE;
}

LONG WINAPI
ShimRtlGUIDFromString(PSHIM_UNICODE_STRING string, GUID *guid)
{
    LPCWSTR text;
    ULONG value;
    ULONG index;

    if (string == NULL || guid == NULL || string->Buffer == NULL ||
        string->Length != 38 * sizeof(WCHAR))
        return SHIM_STATUS_INVALID_PARAMETER;
    text = string->Buffer;
    if (text[0] != L'{' || text[9] != L'-' || text[14] != L'-' ||
        text[19] != L'-' || text[24] != L'-' || text[37] != L'}')
        return SHIM_STATUS_INVALID_PARAMETER;
    if (!ShimParseHex(text + 1, 8, &value))
        return SHIM_STATUS_INVALID_PARAMETER;
    guid->Data1 = value;
    if (!ShimParseHex(text + 10, 4, &value))
        return SHIM_STATUS_INVALID_PARAMETER;
    guid->Data2 = (USHORT)value;
    if (!ShimParseHex(text + 15, 4, &value))
        return SHIM_STATUS_INVALID_PARAMETER;
    guid->Data3 = (USHORT)value;
    for (index = 0; index < 2; ++index) {
        if (!ShimParseHex(text + 20 + index * 2, 2, &value))
            return SHIM_STATUS_INVALID_PARAMETER;
        guid->Data4[index] = (BYTE)value;
    }
    for (index = 0; index < 6; ++index) {
        if (!ShimParseHex(text + 25 + index * 2, 2, &value))
            return SHIM_STATUS_INVALID_PARAMETER;
        guid->Data4[index + 2] = (BYTE)value;
    }
    return SHIM_STATUS_SUCCESS;
}

static WCHAR *
ShimWriteHex(WCHAR *output, ULONG value, ULONG digits)
{
    static const WCHAR hex[] = L"0123456789ABCDEF";
    ULONG shift;

    shift = digits * 4;
    while (shift != 0) {
        shift -= 4;
        *output++ = hex[(value >> shift) & 0x0f];
    }
    return output;
}

LONG WINAPI
ShimRtlStringFromGUID(const GUID *guid, PSHIM_UNICODE_STRING string)
{
    WCHAR *buffer;
    WCHAR *cursor;
    ULONG index;

    if (guid == NULL || string == NULL)
        return SHIM_STATUS_INVALID_PARAMETER;
    string->Length = 0;
    string->MaximumLength = 0;
    string->Buffer = NULL;
    buffer = (WCHAR *)HeapAlloc(GetProcessHeap(), 0, 39 * sizeof(WCHAR));
    if (buffer == NULL)
        return SHIM_STATUS_NO_MEMORY;
    cursor = buffer;
    *cursor++ = L'{';
    cursor = ShimWriteHex(cursor, guid->Data1, 8);
    *cursor++ = L'-';
    cursor = ShimWriteHex(cursor, guid->Data2, 4);
    *cursor++ = L'-';
    cursor = ShimWriteHex(cursor, guid->Data3, 4);
    *cursor++ = L'-';
    for (index = 0; index < 2; ++index)
        cursor = ShimWriteHex(cursor, guid->Data4[index], 2);
    *cursor++ = L'-';
    for (index = 2; index < 8; ++index)
        cursor = ShimWriteHex(cursor, guid->Data4[index], 2);
    *cursor++ = L'}';
    *cursor = L'\0';
    string->Buffer = buffer;
    string->Length = 38 * sizeof(WCHAR);
    string->MaximumLength = 39 * sizeof(WCHAR);
    return SHIM_STATUS_SUCCESS;
}

LONG WINAPI
ShimRtlAddAccessAllowedAceEx(PACL acl, ULONG revision, ULONG ace_flags,
                             ACCESS_MASK access_mask, PSID sid)
{
    PFN_RTL_ADD_ACE rtl_add_ace;
    PFN_RTL_VALID_SID rtl_valid_sid;
    PFN_RTL_LENGTH_SID rtl_length_sid;
    ACCESS_ALLOWED_ACE *ace;
    ULONG sid_length;
    ULONG ace_length;
    LONG status;

    rtl_add_ace = (PFN_RTL_ADD_ACE)
        ShimProcedure(&g_ntdll, "ntdll.dll", "RtlAddAce");
    rtl_valid_sid = (PFN_RTL_VALID_SID)
        ShimProcedure(&g_ntdll, "ntdll.dll", "RtlValidSid");
    rtl_length_sid = (PFN_RTL_LENGTH_SID)
        ShimProcedure(&g_ntdll, "ntdll.dll", "RtlLengthSid");
    if (acl == NULL || sid == NULL || rtl_add_ace == NULL ||
        rtl_valid_sid == NULL || rtl_length_sid == NULL)
        return SHIM_STATUS_INVALID_PARAMETER;
    if (!rtl_valid_sid(sid))
        return SHIM_STATUS_INVALID_SID;
    if ((ace_flags & ~0xffUL) != 0)
        return SHIM_STATUS_INVALID_PARAMETER;
    sid_length = rtl_length_sid(sid);
    ace_length = ShimAlign4(FIELD_OFFSET(ACCESS_ALLOWED_ACE, SidStart) +
                            sid_length);
    if (ace_length > 0xffff)
        return SHIM_STATUS_INVALID_PARAMETER;
    ace = (ACCESS_ALLOWED_ACE *)HeapAlloc(GetProcessHeap(), 0, ace_length);
    if (ace == NULL)
        return SHIM_STATUS_NO_MEMORY;
    ace->Header.AceType = ACCESS_ALLOWED_ACE_TYPE;
    ace->Header.AceFlags = (BYTE)ace_flags;
    ace->Header.AceSize = (USHORT)ace_length;
    ace->Mask = access_mask;
    ShimCopyBytes(&ace->SidStart, sid, sid_length);
    status = rtl_add_ace(acl, revision, MAXDWORD, ace, ace_length);
    HeapFree(GetProcessHeap(), 0, ace);
    return status;
}

BOOL WINAPI
ShimAddAccessAllowedAceEx(PACL acl, DWORD revision, DWORD ace_flags,
                          DWORD access_mask, PSID sid)
{
    PFN_RTL_NTSTATUS_TO_DOS_ERROR convert_status;
    LONG status;

    status = ShimRtlAddAccessAllowedAceEx(acl, revision, ace_flags,
                                          access_mask, sid);
    if (status == SHIM_STATUS_SUCCESS)
        return TRUE;
    convert_status = (PFN_RTL_NTSTATUS_TO_DOS_ERROR)
        ShimProcedure(&g_ntdll, "ntdll.dll", "RtlNtStatusToDosError");
    SetLastError(convert_status != NULL ? convert_status(status) :
                 ERROR_INVALID_PARAMETER);
    return FALSE;
}

static BOOL
ShimEqualToken(LPCWSTR start, LPCWSTR end, LPCWSTR value)
{
    while (start != end && *value != L'\0') {
        if (*start++ != *value++)
            return FALSE;
    }
    return start == end && *value == L'\0';
}

static VOID
ShimTrimToken(LPCWSTR *start, LPCWSTR *end)
{
    while (*start != *end && (**start == L' ' || **start == L'\t'))
        ++*start;
    while (*end != *start && ((*end)[-1] == L' ' || (*end)[-1] == L'\t'))
        --*end;
}

static BOOL
ShimParseUnsigned(LPCWSTR start, LPCWSTR end, DWORD *result)
{
    DWORD value;
    DWORD base;
    DWORD digit;

    ShimTrimToken(&start, &end);
    if (start == end)
        return FALSE;
    base = 10;
    if (end - start > 2 && start[0] == L'0' &&
        (start[1] == L'x' || start[1] == L'X')) {
        base = 16;
        start += 2;
        if (start == end)
            return FALSE;
    }
    value = 0;
    while (start != end) {
        if (*start >= L'0' && *start <= L'9')
            digit = (DWORD)(*start - L'0');
        else if (base == 16 && *start >= L'a' && *start <= L'f')
            digit = (DWORD)(*start - L'a' + 10);
        else if (base == 16 && *start >= L'A' && *start <= L'F')
            digit = (DWORD)(*start - L'A' + 10);
        else
            return FALSE;
        if (digit >= base || value > (MAXDWORD - digit) / base)
            return FALSE;
        value = value * base + digit;
        ++start;
    }
    *result = value;
    return TRUE;
}

static BOOL
ShimParseAuthority(LPCWSTR start, LPCWSTR end,
                   SID_IDENTIFIER_AUTHORITY *authority)
{
    BYTE bytes[6];
    DWORD index;
    DWORD digit;
    DWORD carry;
    int hex_digit;

    ShimTrimToken(&start, &end);
    for (index = 0; index < 6; ++index)
        bytes[index] = 0;
    if (end - start > 2 && start[0] == L'0' &&
        (start[1] == L'x' || start[1] == L'X')) {
        start += 2;
        if (start == end || end - start > 12)
            return FALSE;
        while (start != end) {
            hex_digit = ShimHexValue(*start++);
            if (hex_digit < 0)
                return FALSE;
            carry = (DWORD)hex_digit;
            for (index = 6; index != 0; --index) {
                digit = (DWORD)bytes[index - 1] * 16U + carry;
                bytes[index - 1] = (BYTE)digit;
                carry = digit >> 8;
            }
            if (carry != 0)
                return FALSE;
        }
    } else {
        if (start == end)
            return FALSE;
        while (start != end) {
            if (*start < L'0' || *start > L'9')
                return FALSE;
            carry = (DWORD)(*start++ - L'0');
            for (index = 6; index != 0; --index) {
                digit = (DWORD)bytes[index - 1] * 10U + carry;
                bytes[index - 1] = (BYTE)digit;
                carry = digit >> 8;
            }
            if (carry != 0)
                return FALSE;
        }
    }
    for (index = 0; index < 6; ++index)
        authority->Value[index] = bytes[index];
    return TRUE;
}

static const SHIM_SID_ALIAS g_sid_aliases[] = {
    {L'A', L'N', 5, 1, {7, 0}},
    {L'A', L'O', 5, 2, {32, 548}},
    {L'A', L'U', 5, 1, {11, 0}},
    {L'B', L'A', 5, 2, {32, 544}},
    {L'B', L'G', 5, 2, {32, 546}},
    {L'B', L'O', 5, 2, {32, 551}},
    {L'B', L'U', 5, 2, {32, 545}},
    {L'C', L'G', 3, 1, {1, 0}},
    {L'C', L'O', 3, 1, {0, 0}},
    {L'E', L'D', 5, 1, {9, 0}},
    {L'I', L'U', 5, 1, {4, 0}},
    {L'L', L'S', 5, 1, {19, 0}},
    {L'N', L'O', 5, 2, {32, 556}},
    {L'N', L'S', 5, 1, {20, 0}},
    {L'N', L'U', 5, 1, {2, 0}},
    {L'P', L'O', 5, 2, {32, 550}},
    {L'P', L'S', 5, 1, {10, 0}},
    {L'P', L'U', 5, 2, {32, 547}},
    {L'R', L'C', 5, 1, {12, 0}},
    {L'R', L'D', 5, 2, {32, 555}},
    {L'R', L'E', 5, 2, {32, 552}},
    {L'R', L'U', 5, 2, {32, 554}},
    {L'S', L'O', 5, 2, {32, 549}},
    {L'S', L'U', 5, 1, {6, 0}},
    {L'S', L'Y', 5, 1, {18, 0}},
    {L'W', L'D', 1, 1, {0, 0}}
};

static BOOL
ShimParseSidToken(LPCWSTR start, LPCWSTR end, PSID sid, ULONG *sid_length)
{
    SHIM_SID *output;
    SID_IDENTIFIER_AUTHORITY authority;
    DWORD sub_authorities[SHIM_SID_MAX_SUB_AUTHORITIES];
    DWORD revision;
    DWORD count;
    DWORD index;
    LPCWSTR token_end;
    const SHIM_SID_ALIAS *alias;

    ShimTrimToken(&start, &end);
    if (end - start == 2) {
        alias = NULL;
        for (index = 0; index < sizeof(g_sid_aliases) /
                                sizeof(g_sid_aliases[0]); ++index) {
            if (g_sid_aliases[index].first == start[0] &&
                g_sid_aliases[index].second == start[1]) {
                alias = &g_sid_aliases[index];
                break;
            }
        }
        if (alias == NULL) {
            SetLastError(ERROR_NONE_MAPPED);
            return FALSE;
        }
        for (index = 0; index < 6; ++index)
            authority.Value[index] = 0;
        authority.Value[5] = alias->authority;
        count = alias->count;
        for (index = 0; index < count; ++index)
            sub_authorities[index] = alias->sub_authority[index];
        revision = SID_REVISION;
    } else {
        if (end - start < 6 || start[0] != L'S' || start[1] != L'-')
            goto invalid_sid;
        start += 2;
        token_end = start;
        while (token_end != end && *token_end != L'-')
            ++token_end;
        if (token_end == end ||
            !ShimParseUnsigned(start, token_end, &revision) ||
            revision != SID_REVISION)
            goto invalid_sid;
        start = token_end + 1;
        token_end = start;
        while (token_end != end && *token_end != L'-')
            ++token_end;
        if (!ShimParseAuthority(start, token_end, &authority))
            goto invalid_sid;
        count = 0;
        start = token_end;
        while (start != end) {
            if (*start++ != L'-' ||
                count == SHIM_SID_MAX_SUB_AUTHORITIES)
                goto invalid_sid;
            token_end = start;
            while (token_end != end && *token_end != L'-')
                ++token_end;
            if (!ShimParseUnsigned(start, token_end,
                                   &sub_authorities[count]))
                goto invalid_sid;
            ++count;
            start = token_end;
        }
    }
    *sid_length = 8U + count * sizeof(DWORD);
    if (sid != NULL) {
        output = (SHIM_SID *)sid;
        output->Revision = (BYTE)revision;
        output->SubAuthorityCount = (BYTE)count;
        /* Copy explicitly so /NODEFAULTLIB can never acquire a memcpy import. */
        for (index = 0; index < 6; ++index)
            output->IdentifierAuthority.Value[index] = authority.Value[index];
        for (index = 0; index < count; ++index)
            output->SubAuthority[index] = sub_authorities[index];
    }
    return TRUE;

invalid_sid:
    SetLastError(ERROR_INVALID_SID);
    return FALSE;
}

static WCHAR *
ShimWriteDecimal(WCHAR *output, DWORD value)
{
    WCHAR digits[10];
    DWORD count;

    count = 0;
    do {
        digits[count++] = (WCHAR)(L'0' + value % 10U);
        value /= 10U;
    } while (value != 0);
    while (count != 0)
        *output++ = digits[--count];
    return output;
}

BOOL WINAPI
ShimConvertSidToStringSidW(PSID sid, LPWSTR *string_sid)
{
    PFN_CONVERT_SID_TO_STRING_SID_W native_function;
    PFN_RTL_VALID_SID rtl_valid_sid;
    SHIM_SID *input;
    WCHAR *buffer;
    WCHAR *cursor;
    DWORD authority;
    DWORD index;

    native_function = (PFN_CONVERT_SID_TO_STRING_SID_W)
        ShimProcedure(&g_advapi32, "advapi32.dll", "ConvertSidToStringSidW");
    if (native_function != NULL)
        return native_function(sid, string_sid);
    if (string_sid == NULL) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    *string_sid = NULL;
    rtl_valid_sid = (PFN_RTL_VALID_SID)
        ShimProcedure(&g_ntdll, "ntdll.dll", "RtlValidSid");
    if (sid == NULL || rtl_valid_sid == NULL || !rtl_valid_sid(sid)) {
        SetLastError(ERROR_INVALID_SID);
        return FALSE;
    }
    input = (SHIM_SID *)sid;
    buffer = (WCHAR *)LocalAlloc(LMEM_FIXED,
        SHIM_SID_TEXT_CAPACITY * sizeof(WCHAR));
    if (buffer == NULL) {
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        return FALSE;
    }
    cursor = buffer;
    *cursor++ = L'S';
    *cursor++ = L'-';
    cursor = ShimWriteDecimal(cursor, input->Revision);
    *cursor++ = L'-';
    if (input->IdentifierAuthority.Value[0] != 0 ||
        input->IdentifierAuthority.Value[1] != 0) {
        *cursor++ = L'0';
        *cursor++ = L'x';
        for (index = 0; index < 6; ++index)
            cursor = ShimWriteHex(cursor,
                input->IdentifierAuthority.Value[index], 2);
    } else {
        authority = ((DWORD)input->IdentifierAuthority.Value[2] << 24) |
                    ((DWORD)input->IdentifierAuthority.Value[3] << 16) |
                    ((DWORD)input->IdentifierAuthority.Value[4] << 8) |
                    (DWORD)input->IdentifierAuthority.Value[5];
        cursor = ShimWriteDecimal(cursor, authority);
    }
    for (index = 0; index < input->SubAuthorityCount; ++index) {
        *cursor++ = L'-';
        cursor = ShimWriteDecimal(cursor, input->SubAuthority[index]);
    }
    *cursor = L'\0';
    *string_sid = buffer;
    return TRUE;
}

typedef struct _SHIM_NAME_VALUE {
    WCHAR first;
    WCHAR second;
    DWORD value;
} SHIM_NAME_VALUE;

static const SHIM_NAME_VALUE g_ace_rights[] = {
    {L'C', L'C', 0x00000001UL},
    {L'D', L'C', 0x00000002UL},
    {L'L', L'C', 0x00000004UL},
    {L'S', L'W', 0x00000008UL},
    {L'R', L'P', 0x00000010UL},
    {L'W', L'P', 0x00000020UL},
    {L'D', L'T', 0x00000040UL},
    {L'L', L'O', 0x00000080UL},
    {L'C', L'R', 0x00000100UL},
    {L'S', L'D', 0x00010000UL},
    {L'R', L'C', 0x00020000UL},
    {L'W', L'D', 0x00040000UL},
    {L'W', L'O', 0x00080000UL},
    {L'G', L'A', 0x10000000UL},
    {L'G', L'X', 0x20000000UL},
    {L'G', L'W', 0x40000000UL},
    {L'G', L'R', 0x80000000UL},
    {L'F', L'A', 0x001f01ffUL},
    {L'F', L'R', 0x00120089UL},
    {L'F', L'W', 0x00120116UL},
    {L'F', L'X', 0x001200a0UL},
    {L'K', L'A', 0x000f003fUL},
    {L'K', L'R', 0x00020019UL},
    {L'K', L'W', 0x00020006UL},
    {L'K', L'X', 0x00020019UL}
};

static const SHIM_NAME_VALUE g_ace_flags[] = {
    {L'O', L'I', OBJECT_INHERIT_ACE},
    {L'C', L'I', CONTAINER_INHERIT_ACE},
    {L'N', L'P', NO_PROPAGATE_INHERIT_ACE},
    {L'I', L'O', INHERIT_ONLY_ACE},
    {L'I', L'D', INHERITED_ACE},
    {L'S', L'A', SUCCESSFUL_ACCESS_ACE_FLAG},
    {L'F', L'A', FAILED_ACCESS_ACE_FLAG}
};

static BOOL
ShimParseNameValues(LPCWSTR start, LPCWSTR end,
                    const SHIM_NAME_VALUE *values, ULONG value_count,
                    DWORD *result)
{
    DWORD output;
    ULONG index;
    BOOL found;

    output = 0;
    while (start != end) {
        if (end - start < 2)
            return FALSE;
        found = FALSE;
        for (index = 0; index < value_count; ++index) {
            if (values[index].first == start[0] &&
                values[index].second == start[1]) {
                output |= values[index].value;
                found = TRUE;
                break;
            }
        }
        if (!found)
            return FALSE;
        start += 2;
    }
    *result = output;
    return TRUE;
}

static BOOL
ShimParseAceRights(LPCWSTR start, LPCWSTR end, DWORD *rights)
{
    ShimTrimToken(&start, &end);
    if (start == end) {
        *rights = 0;
        return TRUE;
    }
    if (end - start > 2 && start[0] == L'0' &&
        (start[1] == L'x' || start[1] == L'X'))
        return ShimParseUnsigned(start, end, rights);
    return ShimParseNameValues(start, end, g_ace_rights,
        sizeof(g_ace_rights) / sizeof(g_ace_rights[0]), rights);
}

static BOOL
ShimParseAceFlags(LPCWSTR start, LPCWSTR end, BYTE *flags)
{
    DWORD value;

    ShimTrimToken(&start, &end);
    if (!ShimParseNameValues(start, end, g_ace_flags,
            sizeof(g_ace_flags) / sizeof(g_ace_flags[0]), &value) ||
        value > 0xffUL)
        return FALSE;
    *flags = (BYTE)value;
    return TRUE;
}

static BOOL
ShimParseAceType(LPCWSTR start, LPCWSTR end, BYTE *type)
{
    ShimTrimToken(&start, &end);
    if (end - start == 1 && start[0] == L'A')
        *type = ACCESS_ALLOWED_ACE_TYPE;
    else if (end - start == 1 && start[0] == L'D')
        *type = ACCESS_DENIED_ACE_TYPE;
    else if (end - start == 2 && start[0] == L'A' && start[1] == L'U')
        *type = SYSTEM_AUDIT_ACE_TYPE;
    else if (end - start == 2 && start[0] == L'A' && start[1] == L'L')
        *type = SYSTEM_ALARM_ACE_TYPE;
    else
        return FALSE;
    return TRUE;
}

static BOOL
ShimParseAclToken(LPCWSTR start, LPCWSTR end, BOOL system_acl,
                  PACL acl, ULONG *acl_length,
                  SECURITY_DESCRIPTOR_CONTROL *control,
                  BOOL *null_acl)
{
    LPCWSTR cursor;
    LPCWSTR close;
    LPCWSTR field_start[6];
    LPCWSTR field_end[6];
    ACCESS_ALLOWED_ACE *ace;
    ULONG length;
    ULONG ace_length;
    ULONG sid_length;
    ULONG field;
    USHORT ace_count;
    BYTE ace_type;
    BYTE ace_flags;
    DWORD rights;

    ShimTrimToken(&start, &end);
    cursor = start;
    *control = 0;
    *null_acl = FALSE;
    while (cursor != end && *cursor != L'(') {
        if (*cursor == L'P') {
            *control |= (SECURITY_DESCRIPTOR_CONTROL)
                (system_acl ? SE_SACL_PROTECTED : SE_DACL_PROTECTED);
            ++cursor;
        } else if (end - cursor >= 2 && cursor[0] == L'A' &&
                   cursor[1] == L'R') {
            *control |= (SECURITY_DESCRIPTOR_CONTROL)
                (system_acl ? SE_SACL_AUTO_INHERIT_REQ :
                              SE_DACL_AUTO_INHERIT_REQ);
            cursor += 2;
        } else if (end - cursor >= 2 && cursor[0] == L'A' &&
                   cursor[1] == L'I') {
            *control |= (SECURITY_DESCRIPTOR_CONTROL)
                (system_acl ? SE_SACL_AUTO_INHERITED :
                              SE_DACL_AUTO_INHERITED);
            cursor += 2;
        } else {
            break;
        }
    }
    if (ShimEqualToken(cursor, end, L"NO_ACCESS_CONTROL")) {
        *null_acl = TRUE;
        *acl_length = 0;
        return TRUE;
    }

    length = sizeof(ACL);
    ace_count = 0;
    if (acl != NULL)
        ace = (ACCESS_ALLOWED_ACE *)((BYTE *)acl + sizeof(ACL));
    else
        ace = NULL;
    while (cursor != end) {
        while (cursor != end && (*cursor == L' ' || *cursor == L'\t'))
            ++cursor;
        if (cursor == end)
            break;
        if (*cursor++ != L'(')
            goto invalid_acl;
        close = cursor;
        while (close != end && *close != L')')
            ++close;
        if (close == end)
            goto invalid_acl;
        field_start[0] = cursor;
        for (field = 0; field < 5; ++field) {
            while (cursor != close && *cursor != L';')
                ++cursor;
            if (cursor == close)
                goto invalid_acl;
            field_end[field] = cursor;
            field_start[field + 1] = ++cursor;
        }
        field_end[5] = close;
        while (cursor != close) {
            if (*cursor++ == L';')
                goto invalid_acl;
        }
        if (!ShimParseAceType(field_start[0], field_end[0], &ace_type) ||
            !ShimParseAceFlags(field_start[1], field_end[1], &ace_flags) ||
            !ShimParseAceRights(field_start[2], field_end[2], &rights))
            goto invalid_acl;
        ShimTrimToken(&field_start[3], &field_end[3]);
        ShimTrimToken(&field_start[4], &field_end[4]);
        if (field_start[3] != field_end[3] ||
            field_start[4] != field_end[4])
            goto invalid_acl;
        if (!ShimParseSidToken(field_start[5], field_end[5],
                ace != NULL ? (PSID)&ace->SidStart : NULL, &sid_length))
            return FALSE;
        ace_length = ShimAlign4(FIELD_OFFSET(ACCESS_ALLOWED_ACE, SidStart) +
                                sid_length);
        if (ace_length > 0xffffUL || length > 0xffffUL - ace_length)
            goto invalid_acl;
        if (ace != NULL) {
            ace->Header.AceType = ace_type;
            ace->Header.AceFlags = ace_flags;
            ace->Header.AceSize = (USHORT)ace_length;
            ace->Mask = rights;
            ace = (ACCESS_ALLOWED_ACE *)((BYTE *)ace + ace_length);
        }
        length += ace_length;
        if (ace_count == 0xffffU)
            goto invalid_acl;
        ++ace_count;
        cursor = close + 1;
    }
    if (cursor != end)
        goto invalid_acl;
    if (acl != NULL) {
        acl->AclRevision = ACL_REVISION;
        acl->Sbz1 = 0;
        acl->AclSize = (USHORT)length;
        acl->AceCount = ace_count;
        acl->Sbz2 = 0;
    }
    *acl_length = length;
    return TRUE;

invalid_acl:
    SetLastError(ERROR_INVALID_ACL);
    return FALSE;
}

static LPCWSTR
ShimFindDescriptorTokenEnd(LPCWSTR start, BOOL *valid)
{
    LPCWSTR cursor;
    LONG depth;

    depth = 0;
    cursor = start;
    while (*cursor != L'\0') {
        if (*cursor == L'(')
            ++depth;
        else if (*cursor == L')') {
            if (depth == 0) {
                *valid = FALSE;
                return cursor;
            }
            --depth;
        } else if (depth == 0 && cursor[1] == L':' &&
                   (*cursor == L'O' || *cursor == L'G' ||
                    *cursor == L'D' || *cursor == L'S')) {
            *valid = TRUE;
            return cursor;
        }
        ++cursor;
    }
    *valid = depth == 0;
    return cursor;
}

static BOOL
ShimParseSecurityDescriptor(LPCWSTR text,
                            SHIM_SECURITY_DESCRIPTOR_RELATIVE *descriptor,
                            ULONG *descriptor_length)
{
    LPCWSTR cursor;
    LPCWSTR token_start;
    LPCWSTR token_end;
    ULONG offset;
    ULONG part_length;
    ULONG seen;
    ULONG bit;
    WCHAR type;
    BOOL valid;
    BOOL null_acl;
    SECURITY_DESCRIPTOR_CONTROL acl_control;
    PACL acl;

    offset = sizeof(SHIM_SECURITY_DESCRIPTOR_RELATIVE);
    seen = 0;
    if (descriptor != NULL) {
        descriptor->Revision = SECURITY_DESCRIPTOR_REVISION;
        descriptor->Sbz1 = 0;
        descriptor->Control = SE_SELF_RELATIVE;
        descriptor->Owner = 0;
        descriptor->Group = 0;
        descriptor->Sacl = 0;
        descriptor->Dacl = 0;
    }
    cursor = text;
    while (*cursor != L'\0') {
        while (*cursor == L' ' || *cursor == L'\t')
            ++cursor;
        if (*cursor == L'\0')
            break;
        type = *cursor++;
        if (*cursor++ != L':' ||
            (type != L'O' && type != L'G' &&
             type != L'D' && type != L'S'))
            goto invalid_descriptor;
        token_start = cursor;
        token_end = ShimFindDescriptorTokenEnd(token_start, &valid);
        if (!valid)
            goto invalid_descriptor;
        cursor = token_end;
        if (type == L'O')
            bit = SHIM_SD_OWNER;
        else if (type == L'G')
            bit = SHIM_SD_GROUP;
        else if (type == L'D')
            bit = SHIM_SD_DACL;
        else
            bit = SHIM_SD_SACL;
        if ((seen & bit) != 0)
            goto invalid_descriptor;
        seen |= bit;
        if (type == L'O' || type == L'G') {
            if (!ShimParseSidToken(token_start, token_end,
                    descriptor != NULL ? (PSID)((BYTE *)descriptor + offset) :
                                         NULL,
                    &part_length))
                return FALSE;
            if (descriptor != NULL) {
                if (type == L'O')
                    descriptor->Owner = offset;
                else
                    descriptor->Group = offset;
            }
        } else {
            acl = descriptor != NULL ?
                (PACL)((BYTE *)descriptor + offset) : NULL;
            if (!ShimParseAclToken(token_start, token_end, type == L'S',
                    acl, &part_length, &acl_control, &null_acl))
                return FALSE;
            if (descriptor != NULL) {
                descriptor->Control |= acl_control;
                if (type == L'D') {
                    descriptor->Control |= SE_DACL_PRESENT;
                    descriptor->Dacl = null_acl ? 0 : offset;
                } else {
                    descriptor->Control |= SE_SACL_PRESENT;
                    descriptor->Sacl = null_acl ? 0 : offset;
                }
            }
        }
        if (offset > MAXDWORD - ShimAlign4(part_length))
            goto invalid_descriptor;
        offset += ShimAlign4(part_length);
    }
    *descriptor_length = offset;
    return TRUE;

invalid_descriptor:
    SetLastError(ERROR_INVALID_PARAMETER);
    return FALSE;
}

BOOL WINAPI
ShimConvertStringSecurityDescriptorToSecurityDescriptorW(
    LPCWSTR string_descriptor, DWORD revision,
    PSECURITY_DESCRIPTOR *security_descriptor,
    PULONG security_descriptor_size)
{
    PFN_CONVERT_STRING_SECURITY_DESCRIPTOR_W native_function;
    SHIM_SECURITY_DESCRIPTOR_RELATIVE *descriptor;
    ULONG length;

    native_function = (PFN_CONVERT_STRING_SECURITY_DESCRIPTOR_W)
        ShimProcedure(&g_advapi32, "advapi32.dll",
            "ConvertStringSecurityDescriptorToSecurityDescriptorW");
    if (native_function != NULL)
        return native_function(string_descriptor, revision,
                               security_descriptor,
                               security_descriptor_size);
    if (security_descriptor == NULL || string_descriptor == NULL) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    *security_descriptor = NULL;
    if (security_descriptor_size != NULL)
        *security_descriptor_size = 0;
    if (revision != SDDL_REVISION_1) {
        SetLastError(ERROR_UNKNOWN_REVISION);
        return FALSE;
    }
    if (!ShimParseSecurityDescriptor(string_descriptor, NULL, &length))
        return FALSE;
    descriptor = (SHIM_SECURITY_DESCRIPTOR_RELATIVE *)
        LocalAlloc(LMEM_FIXED | LMEM_ZEROINIT, length);
    if (descriptor == NULL) {
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        return FALSE;
    }
    if (!ShimParseSecurityDescriptor(string_descriptor, descriptor, &length)) {
        LocalFree(descriptor);
        return FALSE;
    }
    *security_descriptor = (PSECURITY_DESCRIPTOR)descriptor;
    if (security_descriptor_size != NULL)
        *security_descriptor_size = length;
    return TRUE;
}

BOOL WINAPI
ShimExpandEnvironmentStringsForUserW(HANDLE token, LPCWSTR source,
                                     LPWSTR destination, DWORD size)
{
    PFN_EXPAND_ENVIRONMENT_STRINGS_FOR_USER_W native_function;
    DWORD required;

    native_function = (PFN_EXPAND_ENVIRONMENT_STRINGS_FOR_USER_W)
        ShimProcedure(&g_userenv, "userenv.dll",
                      "ExpandEnvironmentStringsForUserW");
    if (native_function != NULL)
        return native_function(token, source, destination, size);
    if (source == NULL || destination == NULL || size == 0) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    required = ExpandEnvironmentStringsW(source, destination, size);
    if (required == 0)
        return FALSE;
    if (required > size) {
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return FALSE;
    }
    return TRUE;
}

HRESULT WINAPI
ShimSHBindToParent(const SHIM_ITEMIDLIST *pidl, const GUID *interface_id,
                   PVOID *object, const SHIM_ITEMIDLIST **last_id)
{
    PFN_SH_BIND_TO_PARENT native_function;
    PFN_SH_GET_DESKTOP_FOLDER get_desktop_folder;
    SHIM_SHELL_FOLDER *desktop;
    const SHIM_ITEMIDLIST *current;
    const SHIM_ITEMIDLIST *last;
    SHIM_ITEMIDLIST *parent;
    ULONG parent_length;
    ULONG total_length;
    HRESULT result;

    native_function = (PFN_SH_BIND_TO_PARENT)
        ShimProcedure(&g_shell32, "shell32.dll", "SHBindToParent");
    if (native_function != NULL)
        return native_function(pidl, interface_id, object, last_id);
    if (pidl == NULL || interface_id == NULL || object == NULL)
        return E_POINTER;
    *object = NULL;
    if (last_id != NULL)
        *last_id = NULL;
    current = pidl;
    last = NULL;
    total_length = 0;
    while (current->cb != 0) {
        if (current->cb < sizeof(USHORT) ||
            total_length > 0x00010000UL - current->cb)
            return E_INVALIDARG;
        last = current;
        total_length += current->cb;
        current = (const SHIM_ITEMIDLIST *)
            ((const BYTE *)current + current->cb);
    }
    if (last == NULL)
        return E_INVALIDARG;
    get_desktop_folder = (PFN_SH_GET_DESKTOP_FOLDER)
        ShimProcedure(&g_shell32, "shell32.dll", "SHGetDesktopFolder");
    if (get_desktop_folder == NULL)
        return SHIM_HRESULT_FROM_WIN32(ERROR_PROC_NOT_FOUND);
    desktop = NULL;
    result = get_desktop_folder(&desktop);
    if (result < 0)
        return result;
    if (last == pidl) {
        result = desktop->lpVtbl->QueryInterface(desktop, interface_id,
                                                 object);
    } else {
        parent_length = (ULONG)((const BYTE *)last - (const BYTE *)pidl) +
                        sizeof(USHORT);
        parent = (SHIM_ITEMIDLIST *)HeapAlloc(GetProcessHeap(), 0,
                                              parent_length);
        if (parent == NULL) {
            desktop->lpVtbl->Release(desktop);
            return SHIM_HRESULT_FROM_WIN32(ERROR_NOT_ENOUGH_MEMORY);
        }
        ShimCopyBytes(parent, pidl, parent_length - sizeof(USHORT));
        *(USHORT *)((BYTE *)parent + parent_length - sizeof(USHORT)) = 0;
        result = desktop->lpVtbl->BindToObject(desktop, parent, NULL,
                                               interface_id, object);
        HeapFree(GetProcessHeap(), 0, parent);
    }
    desktop->lpVtbl->Release(desktop);
    if (result >= 0 && last_id != NULL)
        *last_id = last;
    return result;
}

static DWORD WINAPI
ShimCompletionWorker(LPVOID parameter)
{
    HANDLE port;
    DWORD bytes_transferred;
    DWORD completion_key;
    LPOVERLAPPED overlapped;
    LPOVERLAPPED_COMPLETION_ROUTINE callback;
    DWORD error;
    BOOL success;

    port = (HANDLE)parameter;
    for (;;) {
        overlapped = NULL;
        completion_key = 0;
        bytes_transferred = 0;
        success = GetQueuedCompletionStatus(port, &bytes_transferred,
                                            &completion_key, &overlapped,
                                            INFINITE);
        if (overlapped == NULL) {
            if (!success && GetLastError() == ERROR_INVALID_HANDLE)
                break;
            continue;
        }
        error = success ? ERROR_SUCCESS : GetLastError();
        callback = (LPOVERLAPPED_COMPLETION_ROUTINE)completion_key;
        if (callback != NULL)
            callback(error, bytes_transferred, overlapped);
    }
    return 0;
}

static BOOL
ShimEnsureCompletionWorker(HANDLE port)
{
    HANDLE thread;
    LONG state;

    state = InterlockedCompareExchange(&g_completion_worker_state, 1, 0);
    if (state == 0) {
        thread = CreateThread(NULL, 0, ShimCompletionWorker, port, 0, NULL);
        if (thread == NULL) {
            InterlockedExchange(&g_completion_worker_state, 0);
            return FALSE;
        }
        CloseHandle(thread);
        InterlockedExchange(&g_completion_worker_state, 2);
        return TRUE;
    }
    while (state == 1) {
        Sleep(0);
        state = InterlockedCompareExchange(&g_completion_worker_state, 2, 2);
    }
    if (state != 2) {
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        return FALSE;
    }
    return TRUE;
}

BOOL WINAPI
ShimBindIoCompletionCallback(HANDLE file,
                             LPOVERLAPPED_COMPLETION_ROUTINE callback,
                             ULONG flags)
{
    PFN_BIND_IO_COMPLETION_CALLBACK native_function;
    HANDLE port;
    HANDLE existing;

    native_function = (PFN_BIND_IO_COMPLETION_CALLBACK)
        ShimProcedure(&g_kernel32, "kernel32.dll",
                      "BindIoCompletionCallback");
    if (native_function != NULL)
        return native_function(file, callback, flags);
    if (file == NULL || file == INVALID_HANDLE_VALUE || callback == NULL ||
        flags != 0) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    port = g_completion_port;
    if (port == NULL) {
        port = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);
        if (port == NULL)
            return FALSE;
        existing = (HANDLE)InterlockedCompareExchange(
            (LONG *)&g_completion_port, (LONG)port, 0);
        if (existing != NULL) {
            CloseHandle(port);
            port = existing;
        }
    }
    if (!ShimEnsureCompletionWorker(port))
        return FALSE;
    if (CreateIoCompletionPort(file, port, (DWORD)callback, 0) == NULL)
        return FALSE;
    return TRUE;
}

HRESULT WINAPI
ShimCoWaitForMultipleHandles(DWORD flags, DWORD timeout, ULONG handle_count,
                             const HANDLE *handles, LPDWORD index)
{
    PFN_CO_WAIT_FOR_MULTIPLE_HANDLES native_function;
    PFN_MSG_WAIT_FOR_MULTIPLE_OBJECTS message_wait;
    PFN_PEEK_MESSAGE_W peek_message;
    PFN_TRANSLATE_MESSAGE translate_message;
    PFN_DISPATCH_MESSAGE_W dispatch_message;
    PFN_SLEEP_EX sleep_ex;
    DWORD started;
    DWORD elapsed;
    DWORD remaining;
    DWORD result;
    DWORD error;
    MSG message;
    BOOL wait_all;

    native_function = (PFN_CO_WAIT_FOR_MULTIPLE_HANDLES)
        ShimProcedure(&g_ole32, "ole32.dll", "CoWaitForMultipleHandles");
    if (native_function != NULL)
        return native_function(flags, timeout, handle_count, handles, index);
    if (index == NULL || handle_count > MAXIMUM_WAIT_OBJECTS ||
        handles == NULL ||
        (flags & ~(COWAIT_WAITALL | COWAIT_ALERTABLE |
                   COWAIT_INPUTAVAILABLE | COWAIT_DISPATCH_CALLS |
                   COWAIT_DISPATCH_WINDOW_MESSAGES)) != 0)
        return E_INVALIDARG;
    if (handle_count == 0)
        return RPC_E_NO_SYNC;
    *index = 0;
    wait_all = (flags & COWAIT_WAITALL) != 0;
    message_wait = (PFN_MSG_WAIT_FOR_MULTIPLE_OBJECTS)
        ShimProcedure(&g_user32, "user32.dll", "MsgWaitForMultipleObjects");
    peek_message = (PFN_PEEK_MESSAGE_W)
        ShimProcedure(&g_user32, "user32.dll", "PeekMessageW");
    translate_message = (PFN_TRANSLATE_MESSAGE)
        ShimProcedure(&g_user32, "user32.dll", "TranslateMessage");
    dispatch_message = (PFN_DISPATCH_MESSAGE_W)
        ShimProcedure(&g_user32, "user32.dll", "DispatchMessageW");
    sleep_ex = (PFN_SLEEP_EX)GetProcAddress(
        GetModuleHandleA("kernel32.dll"), "SleepEx");
    started = GetTickCount();
    remaining = timeout;

    for (;;) {
        if (wait_all) {
            DWORD wait_slice;

            wait_slice = remaining;
            if (message_wait != NULL &&
                (wait_slice == INFINITE || wait_slice > 50))
                wait_slice = 50;
            result = WaitForMultipleObjects(handle_count, handles, TRUE,
                                            wait_slice);
            if (result == WAIT_OBJECT_0) {
                *index = 0;
                return S_OK;
            }
            if (result >= WAIT_ABANDONED_0 &&
                result < WAIT_ABANDONED_0 + handle_count) {
                *index = result;
                return S_OK;
            }
            if (result == WAIT_FAILED) {
                error = GetLastError();
                return SHIM_HRESULT_FROM_WIN32(error);
            }
            if (message_wait == NULL && result == WAIT_TIMEOUT)
                return RPC_S_CALLPENDING;
        }
        if ((flags & COWAIT_ALERTABLE) != 0 && sleep_ex != NULL &&
            sleep_ex(0, TRUE) == WAIT_IO_COMPLETION) {
            *index = WAIT_IO_COMPLETION;
            return S_OK;
        }
        if (wait_all) {
            result = message_wait(0, NULL, FALSE, 0, QS_ALLINPUT);
        } else if (message_wait != NULL) {
            result = message_wait(handle_count, handles, FALSE, remaining,
                                  QS_ALLINPUT);
        } else {
            result = WaitForMultipleObjects(handle_count, handles, FALSE,
                                            remaining);
        }
        if (!wait_all && result < WAIT_OBJECT_0 + handle_count) {
            *index = result - WAIT_OBJECT_0;
            return S_OK;
        } else if (!wait_all && result >= WAIT_ABANDONED_0 &&
                   result < WAIT_ABANDONED_0 + handle_count) {
            *index = result;
            return S_OK;
        } else if ((!wait_all && message_wait != NULL &&
                    result == WAIT_OBJECT_0 + handle_count) ||
                   (wait_all && result == WAIT_OBJECT_0)) {
            if (peek_message != NULL) {
                while (peek_message(&message, NULL, 0, 0, PM_REMOVE)) {
                    if (translate_message != NULL)
                        translate_message(&message);
                    if (dispatch_message != NULL)
                        dispatch_message(&message);
                }
            }
        } else if (!wait_all && result == WAIT_TIMEOUT) {
            return RPC_S_CALLPENDING;
        } else if (result == WAIT_FAILED) {
            error = GetLastError();
            return SHIM_HRESULT_FROM_WIN32(error);
        }
        if (timeout != INFINITE) {
            elapsed = GetTickCount() - started;
            if (elapsed >= timeout)
                return RPC_S_CALLPENDING;
            remaining = timeout - elapsed;
        }
    }
}

#pragma function(memset)
void * __cdecl memset(void *dest, int c, size_t count)
{
    char *bytes = (char *)dest;
    while (count--)
    {
        *bytes++ = (char)c;
    }
    return dest;
}