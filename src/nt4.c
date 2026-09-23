// Writing of this compatibility 'shim' took weeks, and has been assisted by AI and lots of trial and error
// Pretty much everything here is included for a reason
// It's confirmed to work with Dell's proprietary drivers inside VMWare 16

#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <setupapi.h>
#include <cfgmgr32.h>
#include <shlobj.h>
#include <objbase.h>
#include <winnetwk.h>
#include <userenv.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include "nt4.h"

// Keep this file independent of Rufus globals
#undef SetFilePointerEx
#undef GetFileSizeEx
#undef CreateFileA
#undef GetUserDefaultUILanguage
#undef GetSystemWindowsDirectoryW
#undef GetConsoleWindow
#undef VerSetConditionMask
#undef EnumUILanguagesW
#undef GetVolumePathNameA
#undef FindFirstVolumeA
#undef FindNextVolumeA
#undef FindVolumeClose
#undef GetVolumeNameForVolumeMountPointA
#undef SetVolumeMountPointA
#undef DeleteVolumeMountPointA
#undef CreateHardLinkW
#undef SetProcessDefaultLayout
#undef FlashWindowEx
#undef SetLayout
#undef SetDCPenColor
#undef ConvertStringSidToSidA
#undef ConvertSidToStringSidA
#undef CheckTokenMembership
#undef SHGetFolderPathW
#undef SHGetSpecialFolderPathW
#undef SHCreateDirectoryExA
#undef SHCreateDirectoryExW
#undef SHBindToParent
#undef CoWaitForMultipleHandles
#undef WNetRestoreConnectionA
#undef ExpandEnvironmentStringsForUserW
#undef GetProcAddress
#undef LoadLibraryExA
#undef CM_Get_Parent
#undef CM_Locate_DevNodeA
#undef CM_Get_Child
#undef CM_Get_Device_ID_List_SizeA
#undef CM_Get_Sibling
#undef CM_Get_DevNode_Registry_PropertyA
#undef CM_Get_Device_IDA
#undef CM_Get_DevNode_Status
#undef CM_Get_Device_ID_ListA
#undef SetupDiEnumDeviceInterfaces
#undef SetupDiGetDeviceInterfaceDetailA
#undef SetupDiGetClassDevsA
#undef SetupDiEnumDeviceInfo
#undef SetupDiGetDeviceRegistryPropertyA
#undef SetupDiGetDeviceRegistryPropertyW
#undef SetupDiGetDeviceInstanceIdA
#undef SetupDiDestroyDeviceInfoList

static FARPROC NT4_Proc(const char* module, const char* name)
{
	HMODULE h = GetModuleHandleA(module);
	if (h == NULL)
		h = LoadLibraryA(module);
	return (h == NULL) ? NULL : GetProcAddress(h, name);
}

static BOOL NT4_SetDiskDiagnostic(LPCSTR value_name, LPCSTR value)
{
	static const char key_path[] = "Software\\Rufus-NT";
	DWORD disposition, saved_error = GetLastError();
	HKEY key = NULL;
	LONG status;

	if (value == NULL)
		value = "(null)";
	status = RegCreateKeyExA(HKEY_CURRENT_USER, key_path, 0, NULL,
		REG_OPTION_NON_VOLATILE, KEY_SET_VALUE, NULL, &key, &disposition);
	if (status == ERROR_SUCCESS) {
		status = RegSetValueExA(key, value_name, 0, REG_SZ,
			(const BYTE*)value, (DWORD)strlen(value) + 1);
		if (status == ERROR_SUCCESS)
			status = RegFlushKey(key);
		RegCloseKey(key);
	}
	SetLastError(saved_error);
	return status == ERROR_SUCCESS;
}

BOOL NT4_SetDiskFunction(LPCSTR function)
{
	return NT4_SetDiskDiagnostic("LastDiskFunction", function);
}

BOOL NT4_SetDiskStage(LPCSTR stage)
{
	return NT4_SetDiskDiagnostic("LastDiskStage", stage);
}

BOOL NT4_GetDiskDiagnostic(LPCSTR value_name, LPSTR value, DWORD size)
{
	static const char key_path[] = "Software\\Rufus-NT";
	DWORD type = 0, value_size = size, saved_error = GetLastError();
	HKEY key = NULL;
	LONG status;
	BOOL result;

	if ((value_name == NULL) || (value == NULL) || (size == 0)) {
		SetLastError(saved_error);
		return FALSE;
	}
	value[0] = 0;
	status = RegOpenKeyExA(HKEY_CURRENT_USER, key_path, 0,
		KEY_QUERY_VALUE, &key);
	if (status == ERROR_SUCCESS) {
		status = RegQueryValueExA(key, value_name, NULL, &type, (BYTE*)value, &value_size);
		RegCloseKey(key);
	}
	value[size - 1] = 0;
	result = (status == ERROR_SUCCESS) && (type == REG_SZ);
	SetLastError(saved_error);
	return result;
}

BOOL NT4_ClearDiskDiagnostics(VOID)
{
	static const char key_path[] = "Software\\Rufus-NT";
	DWORD saved_error = GetLastError();
	HKEY key = NULL;
	LONG status;

	status = RegOpenKeyExA(HKEY_CURRENT_USER, key_path, 0, KEY_SET_VALUE, &key);
	if (status == ERROR_SUCCESS) {
		RegDeleteValueA(key, "LastDiskFunction");
		RegDeleteValueA(key, "LastDiskStage");
		status = RegFlushKey(key);
		RegCloseKey(key);
	}
	SetLastError(saved_error);
	return (status == ERROR_SUCCESS) || (status == ERROR_FILE_NOT_FOUND);
}

HANDLE WINAPI NT4_CreateFileA(LPCSTR name, DWORD access, DWORD share,
	LPSECURITY_ATTRIBUTES security, DWORD creation, DWORD flags, HANDLE template_file)
{
	static const char physical_prefix[] = "\\\\.\\PhysicalDrive";
	char *end;
	char alias[64], alias_path[68], target[64];
	DWORD original_error, open_error;
	unsigned long number;
	HANDLE handle;

	// Preserve the normal CreateFile path unless NT4 lacks a PhysicalDrive DOS alias
	handle = CreateFileA(name, access, share, security, creation, flags, template_file);
	if (handle != INVALID_HANDLE_VALUE)
		return handle;
	original_error = GetLastError();
	if ((name == NULL) || ((original_error != ERROR_FILE_NOT_FOUND) &&
		(original_error != ERROR_PATH_NOT_FOUND)) ||
		(_strnicmp(name, physical_prefix, sizeof(physical_prefix) - 1) != 0)) {
		SetLastError(original_error);
		return INVALID_HANDLE_VALUE;
	}

	number = strtoul(name + sizeof(physical_prefix) - 1, &end, 10);
	if ((*end != 0) || (end == name + sizeof(physical_prefix) - 1) ||
		(number >= 0x7fffffffUL)) {
		SetLastError(original_error);
		return INVALID_HANDLE_VALUE;
	}

	// NT4 exposes the whole disk as HarddiskN\\Partition0 but may publish no PhysicalDriveN alias
	wsprintfA(alias, "RufusPhysicalDrive%lu_%08lX", number, GetCurrentProcessId());
	wsprintfA(alias_path, "\\\\.\\%s", alias);
	wsprintfA(target, "\\Device\\Harddisk%lu\\Partition0", number);
	if (!DefineDosDeviceA(DDD_RAW_TARGET_PATH, alias, target))
		return INVALID_HANDLE_VALUE;

	handle = CreateFileA(alias_path, access, share, security, creation, flags, template_file);
	open_error = (handle == INVALID_HANDLE_VALUE) ? GetLastError() : ERROR_SUCCESS;
	DefineDosDeviceA(DDD_REMOVE_DEFINITION | DDD_RAW_TARGET_PATH, alias, target);
	SetLastError(open_error);
	return handle;
}

// Retry the one safe-search flag used by bundled code after NT4 rejects that newer flag
HMODULE WINAPI NT4_LoadLibraryExA(LPCSTR name, HANDLE file, DWORD flags)
{
	HMODULE module = LoadLibraryExA(name, file, flags);
	if ((module == NULL) && (file == NULL) && (flags == LOAD_LIBRARY_SEARCH_SYSTEM32)) {
		module = GetModuleHandleA(name);
		if (module == NULL)
			module = LoadLibraryA(name);
	}
	return module;
}

// Make dynamic lookups observe the same central GetVolumePathNameA shim as direct calls
FARPROC WINAPI NT4_GetProcAddress(HMODULE module, LPCSTR name)
{
	FARPROC proc = GetProcAddress(module, name);
	if ((proc == NULL) && ((ULONG_PTR)name > 0xFFFF) &&
		(module == GetModuleHandleA("kernel32.dll")) &&
		(strcmp(name, "GetVolumePathNameA") == 0))
		return (FARPROC)NT4_GetVolumePathNameA;
	return proc;
}

BOOL WINAPI NT4_SetFilePointerEx(HANDLE h, LARGE_INTEGER distance, PLARGE_INTEGER result, DWORD method)
{
	typedef BOOL (WINAPI *Fn)(HANDLE, LARGE_INTEGER, PLARGE_INTEGER, DWORD);
	Fn fn = (Fn)NT4_Proc("kernel32.dll", "SetFilePointerEx");
	LONG high = distance.HighPart;
	DWORD low;
	if (fn != NULL) return fn(h, distance, result, method);
	SetLastError(NO_ERROR);
	low = SetFilePointer(h, distance.LowPart, &high, method);
	if ((low == INVALID_SET_FILE_POINTER) && (GetLastError() != NO_ERROR)) return FALSE;
	if (result != NULL) { result->LowPart = low; result->HighPart = high; }
	return TRUE;
}

BOOL WINAPI NT4_GetFileSizeEx(HANDLE h, PLARGE_INTEGER size)
{
	typedef BOOL (WINAPI *Fn)(HANDLE, PLARGE_INTEGER);
	Fn fn = (Fn)NT4_Proc("kernel32.dll", "GetFileSizeEx");
	DWORD low, high = 0;
	if (fn != NULL) return fn(h, size);
	if (size == NULL) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
	SetLastError(NO_ERROR); low = GetFileSize(h, &high);
	if ((low == INVALID_FILE_SIZE) && (GetLastError() != NO_ERROR)) return FALSE;
	size->LowPart = low; size->HighPart = (LONG)high; return TRUE;
}

LANGID WINAPI NT4_GetUserDefaultUILanguage(void)
{
	typedef LANGID (WINAPI *Fn)(void); Fn fn = (Fn)NT4_Proc("kernel32.dll", "GetUserDefaultUILanguage");
	return (fn != NULL) ? fn() : GetUserDefaultLangID();
}

UINT WINAPI NT4_GetSystemWindowsDirectoryW(LPWSTR buffer, UINT size)
{
	typedef UINT (WINAPI *Fn)(LPWSTR, UINT); Fn fn = (Fn)NT4_Proc("kernel32.dll", "GetSystemWindowsDirectoryW");
	return (fn != NULL) ? fn(buffer, size) : GetWindowsDirectoryW(buffer, size);
}

HWND WINAPI NT4_GetConsoleWindow(void)
{
	typedef HWND (WINAPI *Fn)(void); Fn fn = (Fn)NT4_Proc("kernel32.dll", "GetConsoleWindow");
	char old_title[512], title[96]; HWND window;
	if (fn != NULL) return fn();
	if (!GetConsoleTitleA(old_title, sizeof(old_title))) old_title[0] = 0;
	wsprintfA(title, "Rufus-NT4-%08lX-%08lX", GetCurrentProcessId(), GetTickCount());
	SetConsoleTitleA(title); Sleep(40); window = FindWindowA(NULL, title); SetConsoleTitleA(old_title);
	return window;
}

ULONGLONG WINAPI NT4_VerSetConditionMask(ULONGLONG mask, DWORD type, BYTE condition)
{
	typedef ULONGLONG (WINAPI *Fn)(ULONGLONG, DWORD, BYTE); Fn fn = (Fn)NT4_Proc("kernel32.dll", "VerSetConditionMask");
	DWORD bit = 0, index;
	if (fn != NULL) return fn(mask, type, condition);
	for (index = 0; index < 8; index++) if (type & (1UL << index)) { bit = index; break; }
	return mask | ((ULONGLONG)(condition & 7) << (bit * 3));
}

BOOL WINAPI NT4_EnumUILanguagesW(UILANGUAGE_ENUMPROCW callback, DWORD flags, LONG_PTR param)
{
	typedef BOOL (WINAPI *Fn)(UILANGUAGE_ENUMPROCW, DWORD, LONG_PTR); Fn fn = (Fn)NT4_Proc("kernel32.dll", "EnumUILanguagesW");
	WCHAR lang[9]; UNREFERENCED_PARAMETER(flags);
	if (fn != NULL) return fn(callback, flags, param);
	if (callback == NULL) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
	wsprintfW(lang, L"%04x", GetUserDefaultLangID()); return callback(lang, param);
}

BOOL WINAPI NT4_GetVolumePathNameA(LPCSTR file, LPSTR root, DWORD size)
{
	typedef BOOL (WINAPI *Fn)(LPCSTR, LPSTR, DWORD); Fn fn = (Fn)NT4_Proc("kernel32.dll", "GetVolumePathNameA");
	if (fn != NULL) return fn(file, root, size);
	if ((file == NULL) || (root == NULL) || (size < 4) || (file[1] != ':')) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
	root[0] = file[0]; root[1] = ':'; root[2] = '\\'; root[3] = 0; return TRUE;
}

typedef struct { DWORD magic, index, mask; } NT4_VOLUME_ENUM;
#define NT4_VOLUME_MAGIC 0x344C4F56UL
static BOOL NT4_NextVolume(NT4_VOLUME_ENUM* e, LPSTR name, DWORD size)
{
	while (e->index < 26) {
		DWORD index = e->index++;
		if ((e->mask & (1UL << index)) == 0)
			continue;
		if (size < 8) { SetLastError(ERROR_FILENAME_EXCED_RANGE); return FALSE; }
		name[0] = '\\'; name[1] = '\\'; name[2] = '?'; name[3] = '\\';
		name[4] = (char)('A' + index); name[5] = ':'; name[6] = '\\'; name[7] = 0;
		return TRUE;
	}
	SetLastError(ERROR_NO_MORE_FILES); return FALSE;
}
HANDLE WINAPI NT4_FindFirstVolumeA(LPSTR name, DWORD size)
{
	typedef HANDLE (WINAPI *Fn)(LPSTR, DWORD); Fn fn = (Fn)NT4_Proc("kernel32.dll", "FindFirstVolumeA");
	NT4_VOLUME_ENUM* e;
	if (fn != NULL) return fn(name, size);
	e = (NT4_VOLUME_ENUM*)LocalAlloc(LPTR, sizeof(*e)); if (e == NULL) return INVALID_HANDLE_VALUE;
	e->magic = NT4_VOLUME_MAGIC; e->mask = GetLogicalDrives();
	if ((e->mask == 0) || !NT4_NextVolume(e, name, size)) { LocalFree(e); return INVALID_HANDLE_VALUE; }
	return (HANDLE)e;
}
BOOL WINAPI NT4_FindNextVolumeA(HANDLE handle, LPSTR name, DWORD size)
{
	typedef BOOL (WINAPI *Fn)(HANDLE, LPSTR, DWORD); Fn fn = (Fn)NT4_Proc("kernel32.dll", "FindNextVolumeA");
	NT4_VOLUME_ENUM* e = (NT4_VOLUME_ENUM*)handle;
	if (fn != NULL) return fn(handle, name, size);
	if ((e != NULL) && (e != (void*)INVALID_HANDLE_VALUE) && (e->magic == NT4_VOLUME_MAGIC)) return NT4_NextVolume(e, name, size);
	SetLastError(ERROR_INVALID_HANDLE); return FALSE;
}
BOOL WINAPI NT4_FindVolumeClose(HANDLE handle)
{
	typedef BOOL (WINAPI *Fn)(HANDLE); Fn fn = (Fn)NT4_Proc("kernel32.dll", "FindVolumeClose"); NT4_VOLUME_ENUM* e = (NT4_VOLUME_ENUM*)handle;
	if (fn != NULL) return fn(handle);
	if ((e != NULL) && (e != (void*)INVALID_HANDLE_VALUE) && (e->magic == NT4_VOLUME_MAGIC)) { e->magic = 0; LocalFree(e); return TRUE; }
	SetLastError(ERROR_INVALID_HANDLE); return FALSE;
}
BOOL WINAPI NT4_GetVolumeNameForVolumeMountPointA(LPCSTR root, LPSTR name, DWORD size)
{
	typedef BOOL (WINAPI *Fn)(LPCSTR, LPSTR, DWORD); Fn fn = (Fn)NT4_Proc("kernel32.dll", "GetVolumeNameForVolumeMountPointA");
	char dos[3], target[MAX_PATH]; DWORD n;
	if (fn != NULL) return fn(root, name, size);
	if ((root == NULL) || (name == NULL) || (root[1] != ':')) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
	dos[0] = root[0]; dos[1] = ':'; dos[2] = 0;
	if (QueryDosDeviceA(dos, target, sizeof(target)) == 0)
		return FALSE;
	n = (DWORD)strlen(target) + (DWORD)strlen("\\\\?\\GLOBALROOT") + 1;
	if (n > size) { SetLastError(ERROR_FILENAME_EXCED_RANGE); return FALSE; }
	lstrcpyA(name, "\\\\?\\GLOBALROOT"); lstrcatA(name, target); return TRUE;
}
BOOL WINAPI NT4_SetVolumeMountPointA(LPCSTR mount, LPCSTR volume)
{
	typedef BOOL(WINAPI*Fn)(LPCSTR,LPCSTR); Fn fn=(Fn)NT4_Proc("kernel32.dll","SetVolumeMountPointA"); char dos[3]; const char prefix[]="\\\\?\\GLOBALROOT";
	if(fn)return fn(mount,volume); if(!mount||!volume||mount[1]!=':'||_strnicmp(volume,prefix,sizeof(prefix)-1)){SetLastError(ERROR_INVALID_PARAMETER);return FALSE;}
	dos[0]=mount[0];dos[1]=':';dos[2]=0;return DefineDosDeviceA(DDD_RAW_TARGET_PATH|DDD_NO_BROADCAST_SYSTEM,dos,&volume[sizeof(prefix)-1]);
}
BOOL WINAPI NT4_DeleteVolumeMountPointA(LPCSTR mount)
{
	typedef BOOL(WINAPI*Fn)(LPCSTR); Fn fn=(Fn)NT4_Proc("kernel32.dll","DeleteVolumeMountPointA"); char dos[3];
	if(fn)return fn(mount); if(!mount||mount[1]!=':'){SetLastError(ERROR_INVALID_PARAMETER);return FALSE;}dos[0]=mount[0];dos[1]=':';dos[2]=0;
	if(DefineDosDeviceA(DDD_REMOVE_DEFINITION|DDD_NO_BROADCAST_SYSTEM,dos,NULL))return TRUE;return GetLastError()==ERROR_FILE_NOT_FOUND;
}
#define NT4_UNSUPPORTED_BOOL(name, module, args, callargs) BOOL WINAPI NT4_##name args { typedef BOOL (WINAPI *Fn) args; Fn fn=(Fn)NT4_Proc(module,#name); if(fn!=NULL)return fn callargs; SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return FALSE; }
NT4_UNSUPPORTED_BOOL(CreateHardLinkW, "kernel32.dll", (LPCWSTR a, LPCWSTR b, LPSECURITY_ATTRIBUTES c), (a,b,c))

BOOL WINAPI NT4_SetProcessDefaultLayout(DWORD layout) { typedef BOOL(WINAPI*Fn)(DWORD); Fn fn=(Fn)NT4_Proc("user32.dll","SetProcessDefaultLayout"); if(fn)return fn(layout); return layout==0; }
BOOL WINAPI NT4_FlashWindowEx(PFLASHWINFO info) { typedef BOOL(WINAPI*Fn)(PFLASHWINFO); Fn fn=(Fn)NT4_Proc("user32.dll","FlashWindowEx"); if(fn)return fn(info); return (info!=NULL)?FlashWindow(info->hwnd,TRUE):FALSE; }
DWORD WINAPI NT4_SetLayout(HDC dc, DWORD layout) { typedef DWORD(WINAPI*Fn)(HDC,DWORD); Fn fn=(Fn)NT4_Proc("gdi32.dll","SetLayout"); UNREFERENCED_PARAMETER(dc); return fn?fn(dc,layout):GDI_ERROR; }
COLORREF WINAPI NT4_SetDCPenColor(HDC dc, COLORREF color) { typedef COLORREF(WINAPI*Fn)(HDC,COLORREF); Fn fn=(Fn)NT4_Proc("gdi32.dll","SetDCPenColor"); UNREFERENCED_PARAMETER(dc); return fn?fn(dc,color):CLR_INVALID; }

BOOL WINAPI NT4_ConvertStringSidToSidA(LPCSTR text, PSID* sid)
{
	typedef BOOL(WINAPI*Fn)(LPCSTR,PSID*); Fn fn=(Fn)NT4_Proc("advapi32.dll","ConvertStringSidToSidA");
	char copy[256], *p, *end; DWORD auth, sub[SID_MAX_SUB_AUTHORITIES], count=0, i; SID_IDENTIFIER_AUTHORITY ia={{0}}; PSID out;
	if(fn)return fn(text,sid); if(!text||!sid||strncmp(text,"S-",2)){SetLastError(ERROR_INVALID_SID);return FALSE;}
	lstrcpynA(copy,text,sizeof(copy)); p=strchr(copy+2,'-'); if(!p){SetLastError(ERROR_INVALID_SID);return FALSE;} *p++=0;
	auth=strtoul(p,&end,0); if(end==p){SetLastError(ERROR_INVALID_SID);return FALSE;} p=(*end=='-')?end+1:end;
	while(*p&&count<SID_MAX_SUB_AUTHORITIES){sub[count++]=strtoul(p,&end,0);if(end==p)break;p=(*end=='-')?end+1:end;}
	ia.Value[2]=(BYTE)(auth>>24);ia.Value[3]=(BYTE)(auth>>16);ia.Value[4]=(BYTE)(auth>>8);ia.Value[5]=(BYTE)auth;
	out=LocalAlloc(LPTR,GetSidLengthRequired((UCHAR)count)); if(!out)return FALSE;
	if(!InitializeSid(out,&ia,(BYTE)count)){LocalFree(out);return FALSE;} for(i=0;i<count;i++)*GetSidSubAuthority(out,i)=sub[i]; *sid=out; return TRUE;
}
BOOL WINAPI NT4_ConvertSidToStringSidA(PSID sid, LPSTR* text)
{
	typedef BOOL(WINAPI*Fn)(PSID,LPSTR*); Fn fn=(Fn)NT4_Proc("advapi32.dll","ConvertSidToStringSidA"); char buffer[256]; DWORD i, used;
	SID_IDENTIFIER_AUTHORITY* ia; if(fn)return fn(sid,text); if(!IsValidSid(sid)||!text){SetLastError(ERROR_INVALID_SID);return FALSE;} ia=GetSidIdentifierAuthority(sid);
	used=(DWORD)wsprintfA(buffer,"S-%u-%lu",(UINT)((SID*)sid)->Revision,(DWORD)ia->Value[5]);
	for(i=0;i<*GetSidSubAuthorityCount(sid)&&used<sizeof(buffer);i++)used+=(DWORD)wsprintfA(buffer+used,"-%lu",*GetSidSubAuthority(sid,i));
	*text=(LPSTR)LocalAlloc(LMEM_FIXED,used+1); if(!*text)return FALSE; memcpy(*text,buffer,used+1); return TRUE;
}
BOOL WINAPI NT4_CheckTokenMembership(HANDLE token, PSID sid, PBOOL member)
{
	typedef BOOL(WINAPI*Fn)(HANDLE,PSID,PBOOL); Fn fn=(Fn)NT4_Proc("advapi32.dll","CheckTokenMembership"); HANDLE own=NULL; TOKEN_GROUPS* groups=NULL; DWORD size=0,i; BOOL ok=FALSE;
	if(fn)return fn(token,sid,member); if(!member||!sid){SetLastError(ERROR_INVALID_PARAMETER);return FALSE;} *member=FALSE;
	if(token==NULL){if(!OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&own))return FALSE;token=own;}
	GetTokenInformation(token,TokenGroups,NULL,0,&size); groups=(TOKEN_GROUPS*)LocalAlloc(LPTR,size);
	if(groups&&GetTokenInformation(token,TokenGroups,groups,size,&size)){for(i=0;i<groups->GroupCount;i++)if(EqualSid(sid,groups->Groups[i].Sid)){*member=TRUE;break;}ok=TRUE;}
	if(groups)LocalFree(groups);if(own)CloseHandle(own);return ok;
}

static int NT4_CreateDirsW(LPCWSTR path, const SECURITY_ATTRIBUTES* sa)
{
	WCHAR tmp[MAX_PATH]; WCHAR* p; DWORD attr; lstrcpynW(tmp,path,MAX_PATH); attr=GetFileAttributesW(tmp); if(attr!=INVALID_FILE_ATTRIBUTES&&(attr&FILE_ATTRIBUTE_DIRECTORY))return ERROR_ALREADY_EXISTS;
	for(p=tmp+3;*p;p++)if(*p==L'\\'){*p=0;CreateDirectoryW(tmp,(LPSECURITY_ATTRIBUTES)sa);*p=L'\\';}
	return CreateDirectoryW(tmp,(LPSECURITY_ATTRIBUTES)sa)?ERROR_SUCCESS:(int)GetLastError();
}
HRESULT WINAPI NT4_SHGetFolderPathW(HWND w,int c,HANDLE t,DWORD f,LPWSTR p){typedef HRESULT(WINAPI*Fn)(HWND,int,HANDLE,DWORD,LPWSTR);Fn fn=(Fn)NT4_Proc("shell32.dll","SHGetFolderPathW");if(fn)return fn(w,c,t,f,p);return NT4_SHGetSpecialFolderPathW(w,p,c,(f&CSIDL_FLAG_CREATE)!=0)?S_OK:E_FAIL;}
BOOL WINAPI NT4_SHGetSpecialFolderPathW(HWND w,LPWSTR p,int c,BOOL create){typedef BOOL(WINAPI*Fn)(HWND,LPWSTR,int,BOOL);Fn fn=(Fn)NT4_Proc("shell32.dll","SHGetSpecialFolderPathW");LPITEMIDLIST id=NULL;if(fn)return fn(w,p,c,create);if(FAILED(SHGetSpecialFolderLocation(w,c,&id))||!SHGetPathFromIDListW(id,p)){if(id)CoTaskMemFree(id);return FALSE;}CoTaskMemFree(id);if(create)NT4_CreateDirsW(p,NULL);return TRUE;}
int WINAPI NT4_SHCreateDirectoryExW(HWND w,LPCWSTR p,const SECURITY_ATTRIBUTES* sa){typedef int(WINAPI*Fn)(HWND,LPCWSTR,const SECURITY_ATTRIBUTES*);Fn fn=(Fn)NT4_Proc("shell32.dll","SHCreateDirectoryExW");UNREFERENCED_PARAMETER(w);return fn?fn(w,p,sa):NT4_CreateDirsW(p,sa);}
int WINAPI NT4_SHCreateDirectoryExA(HWND w,LPCSTR p,const SECURITY_ATTRIBUTES* sa){typedef int(WINAPI*Fn)(HWND,LPCSTR,const SECURITY_ATTRIBUTES*);Fn fn=(Fn)NT4_Proc("shell32.dll","SHCreateDirectoryExA");WCHAR wide[MAX_PATH];if(fn)return fn(w,p,sa);if(!MultiByteToWideChar(CP_ACP,0,p,-1,wide,MAX_PATH))return ERROR_INVALID_NAME;return NT4_CreateDirsW(wide,sa);}
HRESULT WINAPI NT4_SHBindToParent(PCIDLIST_ABSOLUTE pidl,REFIID riid,void** ppv,PCUITEMID_CHILD* child)
{
	typedef HRESULT(WINAPI*Fn)(PCIDLIST_ABSOLUTE,REFIID,void**,PCUITEMID_CHILD*);
	Fn fn=(Fn)NT4_Proc("shell32.dll","SHBindToParent"); IShellFolder* desktop=NULL; LPITEMIDLIST parent, cursor; ULONG total; HRESULT hr;
	if(fn)return fn(pidl,riid,ppv,child); if(!pidl||!ppv)return E_INVALIDARG; *ppv=NULL;
	cursor=(LPITEMIDLIST)pidl; while(cursor->mkid.cb&&((LPITEMIDLIST)((BYTE*)cursor+cursor->mkid.cb))->mkid.cb) cursor=(LPITEMIDLIST)((BYTE*)cursor+cursor->mkid.cb);
	if(child)*child=(PCUITEMID_CHILD)cursor; total=(ULONG)((BYTE*)cursor-(BYTE*)pidl)+sizeof(USHORT); parent=(LPITEMIDLIST)CoTaskMemAlloc(total); if(!parent)return E_OUTOFMEMORY; memcpy(parent,pidl,total); ((LPITEMIDLIST)((BYTE*)parent+((BYTE*)cursor-(BYTE*)pidl)))->mkid.cb=0;
	hr=SHGetDesktopFolder(&desktop); if(SUCCEEDED(hr)) {
		if(parent->mkid.cb==0) hr=IShellFolder_QueryInterface(desktop,riid,ppv);
		else hr=IShellFolder_BindToObject(desktop,parent,NULL,riid,ppv);
	}
	if(desktop)IShellFolder_Release(desktop); CoTaskMemFree(parent); return hr;
}

HRESULT WINAPI NT4_CoWaitForMultipleHandles(DWORD flags,DWORD timeout,ULONG count,LPHANDLE handles,LPDWORD index){typedef HRESULT(WINAPI*Fn)(DWORD,DWORD,ULONG,LPHANDLE,LPDWORD);Fn fn=(Fn)NT4_Proc("ole32.dll","CoWaitForMultipleHandles");DWORD r;if(fn)return fn(flags,timeout,count,handles,index);r=MsgWaitForMultipleObjects(count,handles,FALSE,timeout,QS_ALLINPUT);if(r>=WAIT_OBJECT_0&&r<WAIT_OBJECT_0+count){if(index)*index=r-WAIT_OBJECT_0;return S_OK;}return (r==WAIT_TIMEOUT)?RPC_S_CALLPENDING:E_FAIL;}
DWORD WINAPI NT4_WNetRestoreConnectionA(HWND w,LPCSTR d){typedef DWORD(WINAPI*Fn)(HWND,LPCSTR);Fn fn=(Fn)NT4_Proc("mpr.dll","WNetRestoreConnectionA");return fn?fn(w,d):ERROR_NOT_SUPPORTED;}
BOOL WINAPI NT4_ExpandEnvironmentStringsForUserW(HANDLE t,LPCWSTR s,LPWSTR d,DWORD n){typedef BOOL(WINAPI*Fn)(HANDLE,LPCWSTR,LPWSTR,DWORD);Fn fn=(Fn)NT4_Proc("userenv.dll","ExpandEnvironmentStringsForUserW");UNREFERENCED_PARAMETER(t);return fn?fn(t,s,d,n):(ExpandEnvironmentStringsW(s,d,n)!=0);}

// Prefer the Configuration Manager DLL when a backported stack provides it
static FARPROC NT4_CMProc(const char* name)
{
	FARPROC proc = NT4_Proc("cfgmgr32.dll", name);
	return (proc != NULL) ? proc : NT4_Proc("setupapi.dll", name);
}

#define NT4_CM_WRAP(name,args,callargs) CONFIGRET WINAPI NT4_##name args { typedef CONFIGRET(WINAPI*Fn) args; Fn fn=(Fn)NT4_CMProc(#name); return fn?fn callargs:CR_FAILURE; }
NT4_CM_WRAP(CM_Get_Parent,(PDEVINST a,DEVINST b,ULONG c),(a,b,c))
NT4_CM_WRAP(CM_Locate_DevNodeA,(PDEVINST a,DEVINSTID_A b,ULONG c),(a,b,c))
NT4_CM_WRAP(CM_Get_Child,(PDEVINST a,DEVINST b,ULONG c),(a,b,c))
NT4_CM_WRAP(CM_Get_Device_ID_List_SizeA,(PULONG a,PCSTR b,ULONG c),(a,b,c))
NT4_CM_WRAP(CM_Get_Sibling,(PDEVINST a,DEVINST b,ULONG c),(a,b,c))
NT4_CM_WRAP(CM_Get_DevNode_Registry_PropertyA,(DEVINST a,ULONG b,PULONG c,PVOID d,PULONG e,ULONG f),(a,b,c,d,e,f))
NT4_CM_WRAP(CM_Get_Device_IDA,(DEVINST a,PCHAR b,ULONG c,ULONG d),(a,b,c,d))
NT4_CM_WRAP(CM_Get_DevNode_Status,(PULONG a,PULONG b,DEVINST c,ULONG d),(a,b,c,d))
NT4_CM_WRAP(CM_Get_Device_ID_ListA,(PCSTR a,PCHAR b,ULONG c,ULONG d),(a,b,c,d))
// Represent mounted removable disks as a SetupAPI disk-interface set
typedef struct {
	DWORD number;
	char letter;
	char path[32];
	char instance[128];
	char friendly_name[128];
	char scsi_identifier[128];
	char serial[64];
} NT4_VIRTUAL_DISK;

typedef struct {
	DWORD magic;
	DWORD count;
	NT4_VIRTUAL_DISK disk[26];
} NT4_VIRTUAL_DEVINFO;

#define NT4_DEVINFO_MAGIC 0x4944344EUL
#define NT4_DEVINST_BASE  0x4E540000UL

static NT4_VIRTUAL_DEVINFO* nt4_virtual_disk_set;
// Keep the virtual disk set free of persistent per-PhysicalDrive identity caching
// A newly inserted device is correlated from its current DOS mapping and direct SCSI I/O each time
static const GUID nt4_disk_interface_guid =
	{ 0x53f56307, 0xb6bf, 0x11d0, { 0x94, 0xf2, 0x00, 0xa0, 0xc9, 0x1e, 0xfb, 0x8b } };

static BOOL NT4_IsDiskInterfaceGuid(const GUID* guid)
{
	return (guid != NULL) && (memcmp(guid, &nt4_disk_interface_guid, sizeof(GUID)) == 0);
}

static BOOL NT4_IsVirtualDeviceSet(HDEVINFO set)
{
	return (set != NULL) && (set == (HDEVINFO)nt4_virtual_disk_set) &&
		(nt4_virtual_disk_set->magic == NT4_DEVINFO_MAGIC);
}

// NT4 predates IOCTL_STORAGE_QUERY_PROPERTY.
// Use IOCTL_SCSI_GET_INQUIRY_DATA instead which is fine for this legacy stack.
#ifndef IOCTL_SCSI_BASE
#define IOCTL_SCSI_BASE FILE_DEVICE_CONTROLLER
#endif
#ifndef IOCTL_SCSI_GET_INQUIRY_DATA
#define IOCTL_SCSI_GET_INQUIRY_DATA CTL_CODE(IOCTL_SCSI_BASE, 0x0403, METHOD_BUFFERED, FILE_ANY_ACCESS)
#endif
#ifndef IOCTL_SCSI_GET_ADDRESS
#define IOCTL_SCSI_GET_ADDRESS CTL_CODE(IOCTL_SCSI_BASE, 0x0406, METHOD_BUFFERED, FILE_ANY_ACCESS)
#endif

typedef struct {
	ULONG Length;
	UCHAR PortNumber;
	UCHAR PathId;
	UCHAR TargetId;
	UCHAR Lun;
} NT4_SCSI_ADDRESS;

typedef struct {
	UCHAR NumberOfLogicalUnits;
	UCHAR InitiatorBusId;
	ULONG InquiryDataOffset;
} NT4_SCSI_BUS_DATA;

typedef struct {
	UCHAR NumberOfBuses;
	NT4_SCSI_BUS_DATA BusData[1];
} NT4_SCSI_ADAPTER_BUS_INFO;

typedef struct {
	UCHAR PathId;
	UCHAR TargetId;
	UCHAR Lun;
	UCHAR DeviceClaimed;
	ULONG InquiryDataLength;
	ULONG NextInquiryDataOffset;
	UCHAR InquiryData[1];
} NT4_SCSI_INQUIRY_DATA;

typedef struct {
	char vendor[9];
	char product[17];
	char revision[5];
	BOOL removable;
} NT4_SCSI_IDENTITY;

static void NT4_CopyInquiryText(char* dst, DWORD dst_size, const UCHAR* src, DWORD src_size)
{
	DWORD i, n;

	if ((dst == NULL) || (dst_size == 0))
		return;
	dst[0] = 0;
	if ((src == NULL) || (src_size == 0))
		return;
	n = min(src_size, dst_size - 1);
	for (i = 0; i < n; i++) {
		if ((src[i] >= 0x20) && (src[i] <= 0x7e))
			dst[i] = (char)src[i];
		else
			dst[i] = ' ';
	}
	dst[n] = 0;
	while ((n != 0) && ((dst[n - 1] == ' ') || (dst[n - 1] == '\t')))
		dst[--n] = 0;
	for (i = 0; (dst[i] == ' ') || (dst[i] == '\t'); i++);
	if (i != 0)
		memmove(dst, dst + i, strlen(dst + i) + 1);
}

// Extract only the standard, read-only 36-byte INQUIRY fields. 
// The standard page provides vendor, product, revision and removable-media state
// USB VID/PID and serial are deliberately not invented here
static BOOL NT4_ParseStandardInquiry(const UCHAR* data, DWORD length, NT4_SCSI_IDENTITY* identity)
{
	if ((data == NULL) || (identity == NULL) || (length < 36))
		return FALSE;
	memset(identity, 0, sizeof(*identity));
	identity->removable = ((data[1] & 0x80) != 0);
	NT4_CopyInquiryText(identity->vendor, sizeof(identity->vendor), data + 8, 8);
	NT4_CopyInquiryText(identity->product, sizeof(identity->product), data + 16, 16);
	NT4_CopyInquiryText(identity->revision, sizeof(identity->revision), data + 32, 4);
	return (identity->vendor[0] != 0) || (identity->product[0] != 0);
}

static BOOL NT4_QueryScsiAddress(DWORD disk_number, NT4_SCSI_ADDRESS* address)
{
	HANDLE disk;
	DWORD returned = 0;
	char path[32];
	BOOL result;

	if (address == NULL)
		return FALSE;
	memset(address, 0, sizeof(*address));
	wsprintfA(path, "\\\\.\\PhysicalDrive%lu", disk_number);
	disk = NT4_CreateFileA(path, 0, FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (disk != INVALID_HANDLE_VALUE) {
		result = DeviceIoControl(disk, IOCTL_SCSI_GET_ADDRESS, NULL, 0,
			address, sizeof(*address), &returned, NULL);
		CloseHandle(disk);
		if (result && ((returned >= sizeof(*address)) ||
			(address->Length >= sizeof(*address))))
			return TRUE;
	}

	returned = 0;
	memset(address, 0, sizeof(*address));
	disk = NT4_CreateFileA(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (disk == INVALID_HANDLE_VALUE)
		return FALSE;
	result = DeviceIoControl(disk, IOCTL_SCSI_GET_ADDRESS, NULL, 0,
		address, sizeof(*address), &returned, NULL);
	CloseHandle(disk);
	return result && ((returned >= sizeof(*address)) ||
		(address->Length >= sizeof(*address)));
}

// Query the SCSI port driver's cached INQUIRY table. This is the NT4-era
// Microsoft interface for obtaining device inquiry data and avoids issuing
// a custom CDB to the USB device. Every offset is bounds-checked because old
// third-party miniports are not assumed to return perfectly formed buffers.
static BOOL NT4_QueryAdapterInquiry(const NT4_SCSI_ADDRESS* address, NT4_SCSI_IDENTITY* identity)
{
	static const DWORD sizes[] = { 4096, 16384 };
	HANDLE adapter = INVALID_HANDLE_VALUE;
	BYTE* buffer = NULL;
	DWORD returned = 0, attempt, bus_count, bus_bytes, offset, next, seen;
	char path[32];
	BOOL result = FALSE;
	NT4_SCSI_ADAPTER_BUS_INFO* adapter_info;
	NT4_SCSI_BUS_DATA* bus;
	NT4_SCSI_INQUIRY_DATA* inquiry;
	DWORD adapter_header = FIELD_OFFSET(NT4_SCSI_ADAPTER_BUS_INFO, BusData);
	DWORD inquiry_header = FIELD_OFFSET(NT4_SCSI_INQUIRY_DATA, InquiryData);

	if ((address == NULL) || (identity == NULL))

		return FALSE;
	wsprintfA(path, "\\\\.\\Scsi%u:", address->PortNumber);
	adapter = NT4_CreateFileA(path, 0, FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (adapter == INVALID_HANDLE_VALUE)
		return FALSE;

	for (attempt = 0; attempt < ARRAYSIZE(sizes); attempt++) {
		buffer = (BYTE*)VirtualAlloc(NULL, sizes[attempt], MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		if (buffer == NULL)
			break;
		memset(buffer, 0, sizes[attempt]);
		returned = 0;
		if (DeviceIoControl(adapter, IOCTL_SCSI_GET_INQUIRY_DATA, NULL, 0,
			buffer, sizes[attempt], &returned, NULL))
			break;
		VirtualFree(buffer, 0, MEM_RELEASE);
		buffer = NULL;
	}
	CloseHandle(adapter);
	if ((buffer == NULL) || (returned < adapter_header))
		goto out;

	adapter_info = (NT4_SCSI_ADAPTER_BUS_INFO*)buffer;

	bus_count = adapter_info->NumberOfBuses;
	bus_bytes = FIELD_OFFSET(NT4_SCSI_ADAPTER_BUS_INFO, BusData) +
		bus_count * sizeof(NT4_SCSI_BUS_DATA);
	if ((bus_count == 0) || (bus_bytes > returned) || (address->PathId >= bus_count))
		goto out;
	if (returned < inquiry_header)
		goto out;
	bus = &adapter_info->BusData[address->PathId];
	offset = bus->InquiryDataOffset;
	seen = 0;
	while ((offset != 0) && (offset < returned) &&
		(seen++ < (DWORD)bus->NumberOfLogicalUnits + 8)) {
		if ((offset > returned - inquiry_header))
			break;
		inquiry = (NT4_SCSI_INQUIRY_DATA*)(buffer + offset);
		if ((inquiry->InquiryDataLength <= returned - offset - inquiry_header) &&
			(inquiry->PathId == address->PathId) &&
			(inquiry->TargetId == address->TargetId) &&
			(inquiry->Lun == address->Lun)) {
			result = NT4_ParseStandardInquiry(inquiry->InquiryData,
				inquiry->InquiryDataLength, identity);
			break;
		}
		next = inquiry->NextInquiryDataOffset;
		if ((next == 0) || (next <= offset) || (next >= returned))
			break;
		offset = next;
	}

out:
	if (buffer != NULL)
		VirtualFree(buffer, 0, MEM_RELEASE);
	return result;
}

static BOOL NT4_QueryDiskIoIdentity(DWORD disk_number, NT4_SCSI_ADDRESS* address,
	NT4_SCSI_IDENTITY* identity)
{
	if ((address == NULL) || (identity == NULL))
		return FALSE;
	memset(identity, 0, sizeof(*identity));
	if (!NT4_QueryScsiAddress(disk_number, address))
		return FALSE;
	return NT4_QueryAdapterInquiry(address, identity);
}

static void NT4_ApplyIoIdentity(NT4_VIRTUAL_DISK* virtual_disk)
{
	NT4_SCSI_ADDRESS address;
	NT4_SCSI_IDENTITY identity;

	if ((virtual_disk == NULL) ||
		!NT4_QueryDiskIoIdentity(virtual_disk->number, &address, &identity))
		return;
	if ((identity.vendor[0] != 0) && (identity.product[0] != 0))
		_snprintf(virtual_disk->friendly_name, sizeof(virtual_disk->friendly_name) - 1,
			"%s %s", identity.vendor, identity.product);
	else if (identity.product[0] != 0)
		lstrcpynA(virtual_disk->friendly_name, identity.product,
			sizeof(virtual_disk->friendly_name));
	else if (identity.vendor[0] != 0)
		lstrcpynA(virtual_disk->friendly_name, identity.vendor,
			sizeof(virtual_disk->friendly_name));
	virtual_disk->friendly_name[sizeof(virtual_disk->friendly_name) - 1] = 0;
	lstrcpynA(virtual_disk->scsi_identifier, virtual_disk->friendly_name,
		sizeof(virtual_disk->scsi_identifier));
	_snprintf(virtual_disk->instance, sizeof(virtual_disk->instance) - 1,
		"SCSI\\DISK\\PORT%u_PATH%u_TARGET%u_LUN%u",
		address.PortNumber, address.PathId, address.TargetId, address.Lun);
	virtual_disk->instance[sizeof(virtual_disk->instance) - 1] = 0;
}

static BOOL NT4_AddVirtualDisk(NT4_VIRTUAL_DEVINFO* set, DWORD number, char letter)
{
	DWORD i;

	for (i = 0; i < set->count; i++) {
		if (set->disk[i].number == number) {
			if ((set->disk[i].letter == 0) && (letter != 0)) {
				set->disk[i].letter = letter;
				NT4_ApplyIoIdentity(&set->disk[i]);
			}
			return TRUE;
		}
	}
	if (set->count >= (DWORD)(sizeof(set->disk) / sizeof(set->disk[0])))
		return FALSE;
	set->disk[set->count].number = number;
	set->disk[set->count].letter = letter;
	wsprintfA(set->disk[set->count].path, "\\\\.\\PhysicalDrive%lu", number);
	wsprintfA(set->disk[set->count].instance,
		"USBSTOR\\NT4_REMOVABLE_DISK\\PHYSICALDRIVE%lu", number);
	// Naming is opportunistic and never controls whether the disk is enumerated.
	NT4_ApplyIoIdentity(&set->disk[set->count]);
	set->count++;
	return TRUE;
}

int NT4_GetDriveNumberFromPath(const char* path)
{
	const char prefix[] = "\\\\.\\PhysicalDrive";
	char dos[3], target[MAX_PATH], *end, *marker;
	unsigned long number;

	if (path == NULL)
		return -1;
	if (_strnicmp(path, prefix, sizeof(prefix) - 1) == 0) {
		number = strtoul(path + sizeof(prefix) - 1, &end, 10);
		return ((*end == 0) && (number < 0x7fffffffUL)) ? (int)number : -1;
	}
	if ((strlen(path) >= 6) && (path[0] == '\\') && (path[1] == '\\') &&
		((path[2] == '.') || (path[2] == '?')) && (path[3] == '\\') && (path[5] == ':')) {
		dos[0] = path[4]; dos[1] = ':'; dos[2] = 0;
		if (QueryDosDeviceA(dos, target, sizeof(target)) == 0)
			return -1;
	} else {
		lstrcpynA(target, path, sizeof(target));
	}
	marker = strstr(target, "\\Harddisk");
	if (marker == NULL)
		return -1;
	number = strtoul(marker + 9, &end, 10);
	return ((end != marker + 9) && (number < 0x7fffffffUL)) ? (int)number : -1;
}

static HDEVINFO NT4_CreateVirtualDiskSet(void)
{
	NT4_VIRTUAL_DEVINFO* set;
	DWORD mask, i, j, size;
	char root[] = "A:\\", dos[] = "A:", target[MAX_PATH];

	set = (NT4_VIRTUAL_DEVINFO*)LocalAlloc(LPTR, sizeof(*set));
	if (set == NULL)
		return INVALID_HANDLE_VALUE;
	set->magic = NT4_DEVINFO_MAGIC;

	mask = GetLogicalDrives();
	for (i = 0; (i < 26) && (set->count < 26); i++) {
		char* marker;
		unsigned long number;
		UINT drive_type;

		if ((mask & (1UL << i)) == 0)
			continue;
		root[0] = dos[0] = (char)('A' + i);
		if (QueryDosDeviceA(dos, target, sizeof(target)) == 0)
			continue;
		marker = strstr(target, "\\Harddisk");
		if (marker == NULL)
			continue;
		number = strtoul(marker + 9, NULL, 10);
		drive_type = GetDriveTypeA(root);
		if (drive_type == DRIVE_REMOVABLE)
			NT4_AddVirtualDisk(set, (DWORD)number, root[0]);
	}

	for (i = 0; (i < 32) &&
		(set->count < (DWORD)(sizeof(set->disk) / sizeof(set->disk[0]))); i++) {
		DISK_GEOMETRY geometry;
		HANDLE disk;
		char path[32];

		for (j = 0; (j < set->count) && (set->disk[j].number != i); j++);
		if (j < set->count)
			continue;
		wsprintfA(path, "\\\\.\\PhysicalDrive%lu", i);
		disk = NT4_CreateFileA(path, 0, FILE_SHARE_READ | FILE_SHARE_WRITE,
			NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		if (disk == INVALID_HANDLE_VALUE)
			continue;
		memset(&geometry, 0, sizeof(geometry));
		if (DeviceIoControl(disk, IOCTL_DISK_GET_DRIVE_GEOMETRY, NULL, 0,
			&geometry, sizeof(geometry), &size, NULL) &&
			(geometry.MediaType == RemovableMedia))
			NT4_AddVirtualDisk(set, i, 0);
		CloseHandle(disk);
	}
	if (set->count == 0) {
		LocalFree(set);
		SetLastError(ERROR_NO_MORE_ITEMS);
		return INVALID_HANDLE_VALUE;
	}
	nt4_virtual_disk_set = set;
	return (HDEVINFO)set;
}

HDEVINFO WINAPI NT4_SetupDiGetClassDevsA(const GUID* guid, PCSTR enumerator, HWND parent, DWORD flags)
{
	typedef HDEVINFO (WINAPI *Fn)(const GUID*, PCSTR, HWND, DWORD);
	Fn fn = (Fn)NT4_Proc("setupapi.dll", "SetupDiGetClassDevsA");
	FARPROC enumInterfaces = NT4_Proc("setupapi.dll", "SetupDiEnumDeviceInterfaces");
	FARPROC interfaceDetail = NT4_Proc("setupapi.dll", "SetupDiGetDeviceInterfaceDetailA");
	HDEVINFO set;
	DWORD error = ERROR_CALL_NOT_IMPLEMENTED;
	BOOL diskInterfaceRequest = ((flags & DIGCF_DEVICEINTERFACE) != 0) &&
		NT4_IsDiskInterfaceGuid(guid);
	if ((fn != NULL) && (((flags & DIGCF_DEVICEINTERFACE) == 0) ||
		((enumInterfaces != NULL) && (interfaceDetail != NULL)))) {
		set = fn(guid, enumerator, parent, flags);
		if (set != INVALID_HANDLE_VALUE)
			return set;
		error = GetLastError();
		if (!diskInterfaceRequest) {
			SetLastError(error);
			return INVALID_HANDLE_VALUE;
		}
	}
	if (diskInterfaceRequest)
		return NT4_CreateVirtualDiskSet();
	if ((fn != NULL) && (error != ERROR_SUCCESS)) {
		SetLastError(error);
		return INVALID_HANDLE_VALUE;
	}
	SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
	return INVALID_HANDLE_VALUE;
}

BOOL WINAPI NT4_SetupDiEnumDeviceInfo(HDEVINFO set, DWORD index, PSP_DEVINFO_DATA data)
{
	typedef BOOL (WINAPI *Fn)(HDEVINFO, DWORD, PSP_DEVINFO_DATA);
	Fn fn;
	if (!NT4_IsVirtualDeviceSet(set)) {
		fn = (Fn)NT4_Proc("setupapi.dll", "SetupDiEnumDeviceInfo");
		return (fn != NULL) ? fn(set, index, data) : FALSE;
	}
	if ((data == NULL) || (index >= nt4_virtual_disk_set->count)) {
		SetLastError(ERROR_NO_MORE_ITEMS);
		return FALSE;
	}
	data->ClassGuid = nt4_disk_interface_guid;
	data->DevInst = NT4_DEVINST_BASE + index;
	data->Reserved = index + 1;
	return TRUE;
}

static int NT4_VirtualDiskIndex(HDEVINFO set, PSP_DEVINFO_DATA data)
{
	DWORD index;
	if (!NT4_IsVirtualDeviceSet(set) || (data == NULL) ||
		(data->DevInst < NT4_DEVINST_BASE))
		return -1;
	index = data->DevInst - NT4_DEVINST_BASE;
	return (index < nt4_virtual_disk_set->count) ? (int)index : -1;
}

static BOOL NT4_CopyPropertyA(int index, DWORD property, PDWORD type, PBYTE buffer,
	DWORD size, PDWORD required)
{
	const char* value = NULL;
	NT4_VIRTUAL_DISK* virtual_disk = NULL;
	DWORD valueSize, valueType = REG_SZ;
	DWORD removalPolicy = CM_REMOVAL_POLICY_EXPECT_SURPRISE_REMOVAL;
	if ((index >= 0) && ((DWORD)index < nt4_virtual_disk_set->count))
		virtual_disk = &nt4_virtual_disk_set->disk[index];

	switch (property) {
	case SPDRP_ENUMERATOR_NAME: value = "USBSTOR"; break;
	case SPDRP_HARDWAREID: value = "USBSTOR\\DiskNT4_Removable_Disk"; valueType = REG_MULTI_SZ; break;
	case SPDRP_FRIENDLYNAME:
	case SPDRP_DEVICEDESC:
		value = ((virtual_disk != NULL) && (virtual_disk->friendly_name[0] != 0)) ?
			virtual_disk->friendly_name : "NT4 USB Mass Storage Device";
		break;
	case SPDRP_REMOVAL_POLICY:
		valueSize = sizeof(removalPolicy);
		if (required != NULL) *required = valueSize;
		if (type != NULL) *type = REG_DWORD;
		if ((buffer == NULL) || (size < valueSize)) { SetLastError(ERROR_INSUFFICIENT_BUFFER); return FALSE; }
		memcpy(buffer, &removalPolicy, valueSize); return TRUE;
	default:
		SetLastError(ERROR_INVALID_DATA); return FALSE;
	}
	valueSize = (DWORD)strlen(value) + 1 + ((valueType == REG_MULTI_SZ) ? 1 : 0);
	if (required != NULL) *required = valueSize;
	if (type != NULL) *type = valueType;
	if ((buffer == NULL) || (size < valueSize)) { SetLastError(ERROR_INSUFFICIENT_BUFFER); return FALSE; }
	memcpy(buffer, value, valueSize - ((valueType == REG_MULTI_SZ) ? 1 : 0));
	if (valueType == REG_MULTI_SZ) buffer[valueSize - 1] = 0;
	return TRUE;
}

BOOL WINAPI NT4_SetupDiGetDeviceRegistryPropertyA(HDEVINFO set, PSP_DEVINFO_DATA data,
	DWORD property, PDWORD type, PBYTE buffer, DWORD size, PDWORD required)
{
	typedef BOOL (WINAPI *Fn)(HDEVINFO, PSP_DEVINFO_DATA, DWORD, PDWORD, PBYTE, DWORD, PDWORD);
	Fn fn;
	int index = NT4_VirtualDiskIndex(set, data);
	if (index >= 0)
		return NT4_CopyPropertyA(index, property, type, buffer, size, required);
	fn = (Fn)NT4_Proc("setupapi.dll", "SetupDiGetDeviceRegistryPropertyA");
	return (fn != NULL) ? fn(set, data, property, type, buffer, size, required) : FALSE;
}

BOOL WINAPI NT4_SetupDiGetDeviceRegistryPropertyW(HDEVINFO set, PSP_DEVINFO_DATA data,
	DWORD property, PDWORD type, PBYTE buffer, DWORD size, PDWORD required)
{
	typedef BOOL (WINAPI *Fn)(HDEVINFO, PSP_DEVINFO_DATA, DWORD, PDWORD, PBYTE, DWORD, PDWORD);
	Fn fn;
	BYTE ansi[MAX_PATH];
	DWORD ansiType, ansiSize, wideSize;
	if (NT4_VirtualDiskIndex(set, data) < 0) {
		fn = (Fn)NT4_Proc("setupapi.dll", "SetupDiGetDeviceRegistryPropertyW");
		return (fn != NULL) ? fn(set, data, property, type, buffer, size, required) : FALSE;
	}
	if (!NT4_CopyPropertyA(NT4_VirtualDiskIndex(set, data), property,
		&ansiType, ansi, sizeof(ansi), &ansiSize))
		return FALSE;
	if (ansiType == REG_DWORD) {
		if (required != NULL) *required = ansiSize;
		if (type != NULL) *type = ansiType;
		if ((buffer == NULL) || (size < ansiSize)) { SetLastError(ERROR_INSUFFICIENT_BUFFER); return FALSE; }
		memcpy(buffer, ansi, ansiSize); return TRUE;
	}
	wideSize = ((DWORD)MultiByteToWideChar(CP_ACP, 0, (LPCSTR)ansi, -1, NULL, 0) +
		((ansiType == REG_MULTI_SZ) ? 1 : 0)) * sizeof(WCHAR);
	if (required != NULL) *required = wideSize;
	if (type != NULL) *type = ansiType;
	if ((buffer == NULL) || (size < wideSize)) { SetLastError(ERROR_INSUFFICIENT_BUFFER); return FALSE; }
	MultiByteToWideChar(CP_ACP, 0, (LPCSTR)ansi, -1, (LPWSTR)buffer, (int)(size / sizeof(WCHAR)));
	if (ansiType == REG_MULTI_SZ) ((LPWSTR)buffer)[wideSize / sizeof(WCHAR) - 1] = 0;
	return TRUE;
}

BOOL WINAPI NT4_SetupDiGetDeviceInstanceIdA(HDEVINFO set, PSP_DEVINFO_DATA data,
	PSTR instance, DWORD size, PDWORD required)
{
	typedef BOOL (WINAPI *Fn)(HDEVINFO, PSP_DEVINFO_DATA, PSTR, DWORD, PDWORD);
	Fn fn;
	DWORD length;
	int index = NT4_VirtualDiskIndex(set, data);
	if (index < 0) {
		fn = (Fn)NT4_Proc("setupapi.dll", "SetupDiGetDeviceInstanceIdA");
		return (fn != NULL) ? fn(set, data, instance, size, required) : FALSE;
	}
	length = (DWORD)strlen(nt4_virtual_disk_set->disk[index].instance) + 1;
	if (required != NULL) *required = length;
	if ((instance == NULL) || (size < length)) { SetLastError(ERROR_INSUFFICIENT_BUFFER); return FALSE; }
	memcpy(instance, nt4_virtual_disk_set->disk[index].instance, length);
	return TRUE;
}

BOOL WINAPI NT4_SetupDiEnumDeviceInterfaces(HDEVINFO set, PSP_DEVINFO_DATA data,
	const GUID* guid, DWORD member, PSP_DEVICE_INTERFACE_DATA iface)
{
	typedef BOOL (WINAPI *Fn)(HDEVINFO, PSP_DEVINFO_DATA, const GUID*, DWORD, PSP_DEVICE_INTERFACE_DATA);
	Fn fn;
	int index = NT4_VirtualDiskIndex(set, data);
	if (index < 0) {
		fn = (Fn)NT4_Proc("setupapi.dll", "SetupDiEnumDeviceInterfaces");
		if (fn != NULL) return fn(set, data, guid, member, iface);
		SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return FALSE;
	}
	if ((member != 0) || !NT4_IsDiskInterfaceGuid(guid) || (iface == NULL)) {
		SetLastError(ERROR_NO_MORE_ITEMS); return FALSE;
	}
	iface->InterfaceClassGuid = nt4_disk_interface_guid;
	iface->Flags = SPINT_ACTIVE;
	iface->Reserved = index + 1;
	return TRUE;
}

BOOL WINAPI NT4_SetupDiGetDeviceInterfaceDetailA(HDEVINFO set, PSP_DEVICE_INTERFACE_DATA iface,
	PSP_DEVICE_INTERFACE_DETAIL_DATA_A detail, DWORD size, PDWORD required, PSP_DEVINFO_DATA data)
{
	typedef BOOL (WINAPI *Fn)(HDEVINFO, PSP_DEVICE_INTERFACE_DATA, PSP_DEVICE_INTERFACE_DETAIL_DATA_A, DWORD, PDWORD, PSP_DEVINFO_DATA);
	Fn fn;
	DWORD needed;
	int index;
	if (!NT4_IsVirtualDeviceSet(set)) {
		fn = (Fn)NT4_Proc("setupapi.dll", "SetupDiGetDeviceInterfaceDetailA");
		if (fn != NULL) return fn(set, iface, detail, size, required, data);
		SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return FALSE;
	}
	index = (iface == NULL || iface->Reserved == 0) ? -1 : (int)iface->Reserved - 1;
	if ((index < 0) || ((DWORD)index >= nt4_virtual_disk_set->count)) {
		SetLastError(ERROR_INVALID_DATA); return FALSE;
	}
	needed = FIELD_OFFSET(SP_DEVICE_INTERFACE_DETAIL_DATA_A, DevicePath) +
		(DWORD)strlen(nt4_virtual_disk_set->disk[index].path) + 1;
	if (required != NULL) *required = needed;
	if ((detail == NULL) || (size < needed)) { SetLastError(ERROR_INSUFFICIENT_BUFFER); return FALSE; }
	lstrcpyA(detail->DevicePath, nt4_virtual_disk_set->disk[index].path);
	if (data != NULL) {
		data->ClassGuid = nt4_disk_interface_guid;
		data->DevInst = NT4_DEVINST_BASE + index;
		data->Reserved = index + 1;
	}
	return TRUE;
}

BOOL WINAPI NT4_SetupDiDestroyDeviceInfoList(HDEVINFO set)
{
	typedef BOOL (WINAPI *Fn)(HDEVINFO);
	Fn fn;
	if (NT4_IsVirtualDeviceSet(set)) {
		nt4_virtual_disk_set->magic = 0;
		LocalFree(nt4_virtual_disk_set);
		nt4_virtual_disk_set = NULL;
		return TRUE;
	}
	fn = (Fn)NT4_Proc("setupapi.dll", "SetupDiDestroyDeviceInfoList");
	return (fn != NULL) ? fn(set) : FALSE;
}
