/*
 * Rufus: The Reliable USB Formatting Utility
 * Networking functionality (web file download, check for update, etc.)
 * Copyright © 2012-2025 Pete Batard <pete@akeo.ie>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

 /* Memory leaks detection - define _CRTDBG_MAP_ALLOC as preprocessor macro */
#ifdef _CRTDBG_MAP_ALLOC
#include <stdlib.h>
#include <crtdbg.h>
#endif

#include <windows.h>
// Temporary workaround for MinGW32 delay-loading
// See https://github.com/pbatard/rufus/pull/2513
#if defined(__MINGW32__)
#undef DECLSPEC_IMPORT
#define DECLSPEC_IMPORT __attribute__((visibility("hidden")))
#endif
#include <wininet.h>
#include <netlistmgr.h>
#include <stdio.h>
#include <errno.h>
#include <malloc.h>
#include <string.h>
#include <inttypes.h>
#include <assert.h>
#include <time.h>
#include <virtdisk.h>

#include "rufus.h"
#include "winxp.h"
#include "missing.h"
#include "resource.h"
#include "msapi_utf8.h"
#include "localization.h"
#include "bled/bled.h"
#include "dbx/dbx_info.h"

#include "settings.h"

// Maximum download chunk size
#define DOWNLOAD_BUFFER_SIZE    (10*KB)
// Default delay between update checks
#define DEFAULT_UPDATE_INTERVAL (24*3600)
#define WININET_TLS10_FLAG 0x00000080
#define WININET_TLS11_FLAG 0x00000200
#define WININET_TLS12_FLAG 0x00000800
#define WININET_TLS13_FLAG 0x00002000


static BOOL tls_restart_required;
static BOOL tls_startup_notice_logged;
static WORD vista_update_notice_langid = 0xffff;
static int vista_tls_update = -1;
static int internet_access = -1;
static ULONGLONG internet_probe_time;

static BOOL EnsureTLS12Enabled(HWND hWnd);
static DWORD GetConfiguredSecureProtocols(void);
static HINTERNET GetInternetSession(const char* user_agent, BOOL bRetry);

static BOOL ProbeInternetAccess(void)
{
	DWORD status = 0, status_size = sizeof(status);
	HINTERNET hSession, hRequest;

	hSession = GetInternetSession(NULL, FALSE);
	if (hSession == NULL)
		return FALSE;
	hRequest = InternetOpenUrlA(hSession, RUFUS_URL "/", NULL, 0,
		INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE | INTERNET_FLAG_NO_COOKIES |
		INTERNET_FLAG_NO_UI | INTERNET_FLAG_SECURE, 0);
	if (hRequest != NULL)
		IGNORE_RETVAL(HttpQueryInfoA(hRequest, HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER,
			&status, &status_size, NULL));
	if (hRequest != NULL)
		InternetCloseHandle(hRequest);
	InternetCloseHandle(hSession);
	return (status >= 200) && (status < 400);
}

// Important note for anyone reading the code:
// WinINet MUST get ONLY TLS 1.2 passed on.
// The moment the configurations are mixed, it fails with [0x00002F7D]

static BOOL WriteTlsDword(HKEY root, const char* path, const char* name, DWORD value)
{
	HKEY hKey;
	DWORD disposition;
	LONG status;

	status = RegCreateKeyExA(root, path, 0, NULL, 0, KEY_QUERY_VALUE | KEY_SET_VALUE,
		NULL, &hKey, &disposition);
	if (status != ERROR_SUCCESS)
		return FALSE;
	status = RegSetValueExA(hKey, name, 0, REG_DWORD, (const BYTE*)&value, sizeof(value));
	RegCloseKey(hKey);
	return status == ERROR_SUCCESS;
}

static BOOL ReadTlsDword(HKEY root, const char* path, const char* name, DWORD* value)
{
	HKEY hKey;
	DWORD type = 0, size = sizeof(*value);
	LONG status;

	status = RegOpenKeyExA(root, path, 0, KEY_READ, &hKey);
	if (status != ERROR_SUCCESS)
		return FALSE;

	status = RegQueryValueExA(hKey, name, NULL, &type, (LPBYTE)value, &size);
	RegCloseKey(hKey);

	return (status == ERROR_SUCCESS) &&
		(type == REG_DWORD) &&
		(size == sizeof(*value));
}

static BOOL DeleteTlsValue(HKEY root, const char* path, const char* name)
{
	HKEY hKey;
	LONG status;

	status = RegOpenKeyExA(root, path, 0, KEY_SET_VALUE, &hKey);
	if (status == ERROR_FILE_NOT_FOUND)
		return TRUE;
	if (status != ERROR_SUCCESS)
		return FALSE;
	status = RegDeleteValueA(hKey, name);
	RegCloseKey(hKey);
	return (status == ERROR_SUCCESS) || (status == ERROR_FILE_NOT_FOUND);
}

static BOOL HasRegistryValue(HKEY root, const char* path, const char* name, REGSAM view)
{
	HKEY hKey;
	LONG status;

	status = RegOpenKeyExA(root, path, 0, KEY_QUERY_VALUE | view, &hKey);
	if (status != ERROR_SUCCESS)
		return FALSE;
	status = RegQueryValueExA(hKey, name, NULL, NULL, NULL, NULL);
	RegCloseKey(hKey);
	return status == ERROR_SUCCESS;
}

static BOOL DeleteRegistryValue(HKEY root, const char* path, const char* name, REGSAM view)
{
	HKEY hKey;
	LONG status;

	status = RegOpenKeyExA(root, path, 0, KEY_SET_VALUE | view, &hKey);
	if (status == ERROR_FILE_NOT_FOUND)
		return TRUE;
	if (status != ERROR_SUCCESS)
		return FALSE;
	status = RegDeleteValueA(hKey, name);
	RegCloseKey(hKey);
	return (status == ERROR_SUCCESS) || (status == ERROR_FILE_NOT_FOUND);
}

static BOOL HasVistaTls12Update(void)
// This list contains all Server 2008 R1 updates which added
// proper and official TLS 1.2 support required for networking
// features on Windows Vista
// The previous list was incorrect and shittily formatted
{
	static const char* valid_kbs[] = {
		// 2018-05
		"KB4056564",
		// 2018-06
		"KB4093227", "KB4130956", "KB4230467", "KB4234459",
		"KB4294413",
		// 2018-07
		"KB4291391", "KB4293756", "KB4295656", "KB4339291",
		"KB4339503", "KB4339854", "KB4340583",
		// 2018-08
		"KB4338380", "KB4340937", "KB4340939", "KB4341832",
		"KB4343674", "KB4344104",
		// 2018-09
		"KB4458010", "KB4457984",
		// 2018-10
		"KB4463097", "KB4463104",
		// 2018-11
		"KB4467706", "KB4467700",
		// 2018-12
		"KB4471325", "KB4471319",
		// 2019-01
		"KB4480968", "KB4480957",
		// 2019-02
		"KB4487023", "KB4487019",
		// 2019-03
		"KB4489880", "KB4489876",
		// 2019-04
		"KB4493471", "KB4493458",
		// 2019-05
		"KB4499149", "KB4499180",
		// 2019-06
		"KB4503273", "KB4503287",
		// 2019-07
		"KB4507452", "KB4507461",
		// 2019-08
		"KB4512476", "KB4512491",
		// 2019-09
		"KB4516026", "KB4516051",
		// 2019-10
		"KB4520002", "KB4520009",
		// 2019-11
		"KB4525234", "KB4525239",
		// 2019-12
		"KB4530695", "KB4530719",
		// 2020-01
		"KB4534303", "KB4534312",
		// 2020-02
		"KB4537810", "KB4537822",
		// 2020-03
		"KB4541506", "KB4541504",
		// 2020-04
		"KB4550951", "KB4550957",
		// 2020-05
		"KB4556860", "KB4556854",
		// 2020-06
		"KB4561670", "KB4561645",
		// 2020-07
		"KB4565536", "KB4565529",
		// 2020-08
		"KB4571730", "KB4571746",
		// 2020-09
		"KB4577064", "KB4577070",
		// 2020-10
		"KB4580378", "KB4580385",
		// 2020-11
		"KB4586807", "KB4586817",
		// 2020-12
		"KB4592498", "KB4592504",
		// 2021-01
		"KB4598288", "KB4598287",
		// 2021-02
		"KB4601360", "KB4601366",
		// 2021-03
		"KB5000844", "KB5000856",
		// 2021-04
		"KB5001389", "KB5001332",
		// 2021-05
		"KB5003210", "KB5003225",
		// 2021-06
		"KB5003661", "KB5003695",
		// 2021-07
		"KB5004305", "KB5004299",
		// 2021-08
		"KB5005090", "KB5005095",
		// 2021-09
		"KB5005606", "KB5005618",
		// 2021-10
		"KB5006736", "KB5006715",
		// 2021-11
		"KB5007263", "KB5007246",
		// 2021-12
		"KB5008274", "KB5008271",
		// 2022-01
		"KB5009627", "KB5009601",
		// 2022-02
		"KB5010384", "KB5010403",
		// 2022-03
		"KB5011534", "KB5011525",
		// 2022-04
		"KB5012658", "KB5012632",
		// 2022-05
		"KB5014010", "KB5014006",
		// 2022-06
		"KB5014752", "KB5014743",
		// 2022-07
		"KB5015866", "KB5015870",
		// 2022-08
		"KB5016669", "KB5016686",
		// 2022-09
		"KB5017358", "KB5017371",
		// 2022-10
		"KB5018450", "KB5018446",
		// 2022-11
		"KB5020019", "KB5020005",
		// 2022-12
		"KB5021289", "KB5021293",
		// 2023-01 
		"KB5022340", "KB5022353",
	};
	static const REGSAM views[] = { KEY_WOW64_64KEY, KEY_WOW64_32KEY };
	const char* packages = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Component Based Servicing\\Packages";
	char hotfix_path[256], pkg_name[MAX_PATH];
	DWORD pkg_index, pkg_len;
	HKEY hKey;

	if (vista_tls_update >= 0)
		return vista_tls_update != 0;

	for (size_t view = 0; view < ARRAYSIZE(views); view++) {
		if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, packages, 0, KEY_READ | views[view], &hKey) != ERROR_SUCCESS)
			continue;
		pkg_index = 0;
		while (pkg_len = ARRAYSIZE(pkg_name),
			RegEnumKeyExA(hKey, pkg_index++, pkg_name, &pkg_len, NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
			for (size_t i = 0; i < ARRAYSIZE(valid_kbs); i++) {
				if (strstr(pkg_name, valid_kbs[i]) != NULL) {
					RegCloseKey(hKey);
					vista_tls_update = 1;
					return TRUE;
				}
			}
		}
		RegCloseKey(hKey);
	}

	for (size_t i = 0; i < ARRAYSIZE(valid_kbs); i++) {
		static_sprintf(hotfix_path, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Hotfix\\%s", valid_kbs[i]);
		if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, hotfix_path, 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
			RegCloseKey(hKey);
			vista_tls_update = 1;
			return TRUE;
		}
	}
	vista_tls_update = 0;
	return FALSE;
}

static BOOL HasVistaTlsOsVersionRestriction(void)
{
	static const char* paths[] = {
		"SOFTWARE\\Microsoft\\Internet Explorer\\AdvancedOptions\\CRYPTO\\TLS1.1",
		"SOFTWARE\\Microsoft\\Internet Explorer\\AdvancedOptions\\CRYPTO\\TLS1.2"
	};
	static const REGSAM views[] = { KEY_WOW64_64KEY, KEY_WOW64_32KEY };

	for (size_t view = 0; view < ARRAYSIZE(views); view++)
		for (size_t i = 0; i < ARRAYSIZE(paths); i++)
			if (HasRegistryValue(HKEY_LOCAL_MACHINE, paths[i], "OSVersion", views[view]))
				return TRUE;
	return FALSE;
}

static BOOL RemoveVistaTlsOsVersionRestrictions(void)
{
	static const char* paths[] = {
		"SOFTWARE\\Microsoft\\Internet Explorer\\AdvancedOptions\\CRYPTO\\TLS1.1",
		"SOFTWARE\\Microsoft\\Internet Explorer\\AdvancedOptions\\CRYPTO\\TLS1.2"
	};
	static const REGSAM views[] = { KEY_WOW64_64KEY, KEY_WOW64_32KEY };
	BOOL success = TRUE;

	for (size_t view = 0; view < ARRAYSIZE(views); view++)
		for (size_t i = 0; i < ARRAYSIZE(paths); i++)
			success = DeleteRegistryValue(HKEY_LOCAL_MACHINE, paths[i], "OSVersion", views[view]) && success;
	return success && !HasVistaTlsOsVersionRestriction();
}

static void LogVistaTlsUpdateWarning(void)
{
	if (vista_update_notice_langid == selected_langid)
		return;
	uprintf("%s", lmprintf(MSG_547));
	vista_update_notice_langid = selected_langid;
}

static BOOL EnsureVistaTlsPrerequisites(HWND hWnd, BOOL prompt)
{
	int response;
	DWORD protocols;

	if (!HasVistaTls12Update()) {
		LogVistaTlsUpdateWarning();
		if (prompt && !ReadRegistryKeyBool(REGKEY_HKCU, SETTING_TLS_UPDATES_CHECK)) {
			response = MessageBoxExU(hWnd, lmprintf(MSG_544), lmprintf(MSG_545),
				MB_YESNO | MB_ICONWARNING | MB_IS_RTL, selected_langid);
			IGNORE_RETVAL(WriteRegistryKeyBool(REGKEY_HKCU, SETTING_TLS_UPDATES_CHECK, TRUE));
			if (response == IDYES)
				ShellExecuteA(NULL, "open", "https://www.catalog.update.microsoft.com/Search.aspx?q=KB4056564",
					NULL, NULL, SW_SHOWNORMAL);
		}
		return FALSE;
	}

	protocols = GetConfiguredSecureProtocols();
	if (!prompt &&
		(!(protocols & WININET_TLS12_FLAG) || HasVistaTlsOsVersionRestriction()))
		return FALSE;
	return EnsureTLS12Enabled(hWnd);
}

static DWORD GetConfiguredSecureProtocols(void)
{
	BOOL has_disabled_by_default;
	DWORD protocols;
	DWORD value;
	const char* internet_settings =
		"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings";
	const char* policy_settings =
		"SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings";
	const char* tls12_client =
		"SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.2\\Client";

	/*
	 * Group Policy overrides the user's Internet Options.
	 */
	if (ReadTlsDword(HKEY_LOCAL_MACHINE, policy_settings,
		"SecureProtocols", &protocols)) {
	}
	else if (ReadTlsDword(HKEY_CURRENT_USER, internet_settings,
		"SecureProtocols", &protocols)) {
	}
	else if (ReadTlsDword(HKEY_LOCAL_MACHINE, internet_settings,
		"SecureProtocols", &protocols)) {
	}
	else {
		if (WindowsVersion.Version >= WINDOWS_8)
			protocols = WININET_TLS10_FLAG |
			WININET_TLS11_FLAG |
			WININET_TLS12_FLAG;
		else if (WindowsVersion.Version >= WINDOWS_VISTA)
			protocols = WININET_TLS10_FLAG;
		else
			protocols = WININET_TLS10_FLAG |
			WININET_TLS11_FLAG |
			WININET_TLS12_FLAG;
	}

	if (protocols & WININET_TLS12_FLAG) {
		if (ReadTlsDword(HKEY_LOCAL_MACHINE, tls12_client, "Enabled", &value) &&
			(value == 0))
			protocols &= ~WININET_TLS12_FLAG;
		has_disabled_by_default = ReadTlsDword(HKEY_LOCAL_MACHINE, tls12_client,
			"DisabledByDefault", &value);
		if (((WindowsVersion.Version == WINDOWS_7) && !has_disabled_by_default) ||
			(has_disabled_by_default && (value != 0)))
			protocols &= ~WININET_TLS12_FLAG;
	}

	return protocols;
}

BOOL NetworkStartupPreflight(BOOL log_tls_warning)
{
	DWORD flags = 0;
	DWORD protocols;
	ULONGLONG now;

	if (WindowsVersion.Version <= WINDOWS_VISTA)
		return FALSE;
	now = GetTickCount64();
	if ((WindowsVersion.Version == WINDOWS_VISTA) && !HasVistaTls12Update())
		LogVistaTlsUpdateWarning();
	if ((internet_access >= 0) && ((now - internet_probe_time) < 30000))
		return internet_access != 0;
	if (!InternetGetConnectedState(&flags, 0)) {
		internet_access = 0;
		internet_probe_time = now;
		return FALSE;
	}
	if ((WindowsVersion.Version == WINDOWS_VISTA) &&
		!EnsureVistaTlsPrerequisites(hMainDialog, log_tls_warning)) {
		internet_access = 0;
		internet_probe_time = now;
		return FALSE;
	}

	protocols = GetConfiguredSecureProtocols() &
		(WININET_TLS10_FLAG | WININET_TLS11_FLAG | WININET_TLS12_FLAG | WININET_TLS13_FLAG);
	if (!(protocols & WININET_TLS12_FLAG)) {
		if (log_tls_warning && !tls_startup_notice_logged) {
			uprintf("TLS 1.2 must be enabled for networking functionality");
			tls_startup_notice_logged = TRUE;
		}
		if (!log_tls_warning || !EnsureTLS12Enabled(hMainDialog)) {
			internet_access = 0;
			internet_probe_time = now;
			return FALSE;
		}
		protocols = GetConfiguredSecureProtocols() &
			(WININET_TLS10_FLAG | WININET_TLS11_FLAG | WININET_TLS12_FLAG | WININET_TLS13_FLAG);
		if (!(protocols & WININET_TLS12_FLAG)) {
			internet_access = 0;
			internet_probe_time = now;
			return FALSE;
		}
	}
	internet_access = ProbeInternetAccess() ? 1 : 0;
	internet_probe_time = GetTickCount64();
	if (!internet_access && log_tls_warning)
		uprintf("Internet connection detected, but Rufus cannot access the Internet");
	return internet_access != 0;
}

BOOL IsInternetAvailable(void)
{
	return NetworkStartupPreflight(FALSE);
}

static BOOL ApplyWin7FidoProtocols(DWORD* previous_protocols, BOOL* had_previous_protocols)
{
	const char* internet_settings =
		"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings";

	*had_previous_protocols = ReadTlsDword(HKEY_CURRENT_USER, internet_settings,
		"SecureProtocols", previous_protocols);
	if (!WriteTlsDword(HKEY_CURRENT_USER, internet_settings, "SecureProtocols",
		WININET_TLS12_FLAG))
		return FALSE;
	IGNORE_RETVAL(InternetSetOptionA(NULL, INTERNET_OPTION_SETTINGS_CHANGED, NULL, 0));
	uprintf("Temporarily forcing TLS 1.2 for WinINet");
	return TRUE;
}

static void RestoreWin7FidoProtocols(DWORD previous_protocols, BOOL had_previous_protocols)
{
	const char* internet_settings =
		"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings";

	if (had_previous_protocols)
		IGNORE_RETVAL(WriteTlsDword(HKEY_CURRENT_USER, internet_settings,
			"SecureProtocols", previous_protocols));
	else
		IGNORE_RETVAL(DeleteTlsValue(HKEY_CURRENT_USER, internet_settings, "SecureProtocols"));
	IGNORE_RETVAL(InternetSetOptionA(NULL, INTERNET_OPTION_SETTINGS_CHANGED, NULL, 0));
}

static BOOL EnsureTLS12Enabled(HWND hWnd)
{
	BOOL is_vista, tls_enabled, vista_restricted;
	DWORD value = 0, protocols;
	int response;
	const char* internet_settings =
		"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings";
	const char* wow64_internet_settings =
		"SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Internet Settings";
	const char* policy_settings =
		"SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings";
	const char* tls12_client =
		"SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.2\\Client";

	if (WindowsVersion.Version <= WINDOWS_VISTA)
		return FALSE;

	is_vista = WindowsVersion.Version == WINDOWS_VISTA;
	if (is_vista && !HasVistaTls12Update()) {
		LogVistaTlsUpdateWarning();
		return FALSE;
	}
	protocols = GetConfiguredSecureProtocols() &
		(WININET_TLS10_FLAG | WININET_TLS11_FLAG | WININET_TLS12_FLAG | WININET_TLS13_FLAG);
	tls_enabled = (protocols & WININET_TLS12_FLAG) != 0;
	vista_restricted = is_vista && HasVistaTlsOsVersionRestriction();
	if (tls_enabled && !vista_restricted)
		return TRUE;

	if (!tls_enabled &&
		ReadTlsDword(HKEY_LOCAL_MACHINE, policy_settings, "SecureProtocols", &value) &&
		!(value & WININET_TLS12_FLAG)) {
		uprintf("Group Policy prevents Rufus from enabling TLS 1.2");
		SetLastError(ERROR_INTERNET_SECURITY_CHANNEL_ERROR);
		return FALSE;
	}

	response = MessageBoxExU(hWnd, lmprintf(MSG_530), lmprintf(MSG_531),
		MB_YESNO | MB_ICONWARNING | MB_IS_RTL, selected_langid);
	if (response != IDYES)
		return FALSE;

	if (!tls_enabled) {
		value = WININET_TLS12_FLAG;
		if (ReadTlsDword(HKEY_CURRENT_USER, internet_settings, "SecureProtocols", &protocols))
			value = protocols | WININET_TLS12_FLAG;
		if (!WriteTlsDword(HKEY_CURRENT_USER, internet_settings, "SecureProtocols", value))
			goto error;

		value = WININET_TLS12_FLAG;
		if (ReadTlsDword(HKEY_LOCAL_MACHINE, internet_settings, "SecureProtocols", &protocols))
			value = protocols | WININET_TLS12_FLAG;
		if (!WriteTlsDword(HKEY_LOCAL_MACHINE, internet_settings, "SecureProtocols", value))
			goto error;

		value = WININET_TLS12_FLAG;
		if (ReadTlsDword(HKEY_LOCAL_MACHINE, wow64_internet_settings, "SecureProtocols", &protocols))
			value = protocols | WININET_TLS12_FLAG;
		if (!WriteTlsDword(HKEY_LOCAL_MACHINE, wow64_internet_settings, "SecureProtocols", value))
			goto error;

		if (!WriteTlsDword(HKEY_LOCAL_MACHINE, tls12_client, "Enabled", 1) ||
			!WriteTlsDword(HKEY_LOCAL_MACHINE, tls12_client, "DisabledByDefault", 0))
			goto error;
	}

	if (is_vista && !RemoveVistaTlsOsVersionRestrictions())
		goto error;

	if (!InternetSetOptionA(NULL, INTERNET_OPTION_SETTINGS_CHANGED, NULL, 0))
		uprintf("Could not notify WinINet of TLS settings change: %s", WindowsErrorString());

	protocols = GetConfiguredSecureProtocols() &
		(WININET_TLS10_FLAG | WININET_TLS11_FLAG | WININET_TLS12_FLAG | WININET_TLS13_FLAG);
	if (!(protocols & WININET_TLS12_FLAG) ||
		(is_vista && HasVistaTlsOsVersionRestriction())) {
		SetLastError(ERROR_INTERNET_SECURITY_CHANNEL_ERROR);
		goto error;
	}

	uprintf("Enabled TLS 1.2 for WinINet");
	return TRUE;

error:
	uprintf("Could not enable TLS 1.2: %s", WindowsErrorString());
	return FALSE;
}

// Fido support and checks for Windows 7 and (experimentally) Vista
// Vista is allowed to run fido under specific circumstances, AND...
// Support is purely based on me injecting myself with hopium that
// someone will bother looking into the SSL connection errors

static BOOL IsDotNet45OrNewerInstalled(void)
{
	HKEY hKey;
	DWORD dwRelease = 0, dwSize = sizeof(DWORD);
	BOOL bInstalled = FALSE;

	if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
		"SOFTWARE\\Microsoft\\NET Framework Setup\\NDP\\v4\\Full",
		0, KEY_READ, &hKey) == ERROR_SUCCESS)
	{
		if (RegQueryValueExA(hKey, "Release", NULL, NULL, (LPBYTE)&dwRelease, &dwSize) == ERROR_SUCCESS) {
			if (dwRelease >= 378389)
				bInstalled = TRUE;
		}
		RegCloseKey(hKey);
	}

	return bInstalled;
}

static BOOL IsWMF4OrNewerInstalled(void)
{
	HKEY hKey;
	char version_str[32] = { 0 };
	DWORD dwSize = sizeof(version_str);
	BOOL bInstalled = FALSE;

	if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
		"SOFTWARE\\Microsoft\\PowerShell\\3\\PowerShellEngine",
		0, KEY_READ, &hKey) == ERROR_SUCCESS)
	{
		if (RegQueryValueExA(hKey, "PowerShellVersion", NULL, NULL, (LPBYTE)version_str, &dwSize) == ERROR_SUCCESS) {
			int major_ver = atoi(version_str);
			if (major_ver >= 4)
				bInstalled = TRUE;
		}
		RegCloseKey(hKey);
	}

	return bInstalled;
}

DWORD DownloadStatus;
BYTE* fido_script = NULL;
HANDLE update_check_thread = NULL;

extern loc_cmd* selected_locale;
extern HANDLE dialog_handle;
extern BOOL is_x86_64;
extern USHORT NativeMachine;
static DWORD error_code, fido_len = 0;
static BOOL force_update_check = FALSE;
static const char* request_headers[2] = { "Accept-Encoding: none", "Accept-Encoding: gzip, deflate" };
extern const char* efi_archname[ARCH_MAX];

#if defined(__MINGW32__)
#define INetworkListManager_get_IsConnectedToInternet INetworkListManager_IsConnectedToInternet
#endif

static char* GetShortName(const char* url)
{
	static char short_name[128];
	char* p;
	size_t i, len = safe_strlen(url);
	if (len < 5)
		return NULL;

	for (i = len - 2; i > 0; i--) {
		if (url[i] == '/') {
			i++;
			break;
		}
	}
	memset(short_name, 0, sizeof(short_name));
	static_strcpy(short_name, &url[i]);
	p = strstr(short_name, "%3F");
	if (p != NULL)
		*p = 0;
	p = strstr(short_name, "%3f");
	if (p != NULL)
		*p = 0;
	for (i = 0; i < strlen(short_name); i++) {
		if ((short_name[i] == '?') || (short_name[i] == '#')) {
			short_name[i] = 0;
			break;
		}
	}
	return short_name;
}

static __inline BOOL is_WOW64(void)
{
	BOOL ret = FALSE;
	IsWow64Process(GetCurrentProcess(), &ret);
	return ret;
}

// Open an Internet session
// Lots of bullshit
// My testing shows that without TLS 1.2, networking fails
// But let's keep TLS 1.0 enabled, just to see how it goes
static HINTERNET GetInternetSession(const char* user_agent, BOOL bRetry)
{
	DWORD dwProtocols;
	int i;
	char default_agent[64];
	BOOL decodingSupport = TRUE;
	VARIANT_BOOL InternetConnection = VARIANT_FALSE;
	DWORD dwFlags, dwTimeout = NET_SESSION_TIMEOUT, dwProtocolSupport = HTTP_PROTOCOL_FLAG_HTTP2;
	HINTERNET hSession = NULL;
	HRESULT hr = S_FALSE;
	INetworkListManager* pNetworkListManager;
	// Disable networking on Windows Vista and older
	if (WindowsVersion.Version <= WINDOWS_VISTA) {
		SetLastError(ERROR_NOT_SUPPORTED);
		return NULL;
	}
	dwProtocols = GetConfiguredSecureProtocols() &
		(WININET_TLS10_FLAG | WININET_TLS11_FLAG | WININET_TLS12_FLAG | WININET_TLS13_FLAG);
	if (tls_restart_required ||
		((WindowsVersion.Version == WINDOWS_7) && !(dwProtocols & WININET_TLS12_FLAG)) ||
		((WindowsVersion.Version != WINDOWS_7) &&
			!(dwProtocols & (WININET_TLS10_FLAG | WININET_TLS12_FLAG)))) {
		SetLastError(ERROR_INTERNET_SECURITY_CHANNEL_ERROR);
		return NULL;
	}
	// Create a NetworkListManager Instance to check the network connection
	IGNORE_RETVAL(CoInitializeEx(NULL, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE));
	hr = CoCreateInstance(&CLSID_NetworkListManager, NULL, CLSCTX_ALL,
		&IID_INetworkListManager, (LPVOID*)&pNetworkListManager);
	if (hr == S_OK) {
		for (i = 0; i <= WRITE_RETRIES; i++) {
			hr = INetworkListManager_get_IsConnectedToInternet(pNetworkListManager, &InternetConnection);
			// INetworkListManager may fail with ERROR_SERVICE_DEPENDENCY_FAIL if the DHCP service
			// is not running, in which case we gotta fallback to using InternetGetConnectedState().
			// See https://github.com/pbatard/rufus/issues/1801.
			if (hr == HRESULT_FROM_WIN32(ERROR_SERVICE_DEPENDENCY_FAIL)) {
				InternetConnection = InternetGetConnectedState(&dwFlags, 0) ? VARIANT_TRUE : VARIANT_FALSE;
				break;
			}
			if (hr == S_OK || !bRetry)
				break;
			Sleep(1000);
		}
	}
	/* VPN Fix for Windows 7 */
	if (InternetConnection == VARIANT_FALSE) {
		if (!InternetGetConnectedState(&dwFlags, 0)) {
			// Ignore the disconnect check and attempt connection through active adapter
			uprintf("Network manager reported offline, attempting connection anyway...");
		}
	}
	static_sprintf(default_agent, APPLICATION_NAME "/%d.%d.%d (Windows NT %lu.%lu%s)",
		rufus_version[0], rufus_version[1], rufus_version[2],
		WindowsVersion.Major, WindowsVersion.Minor, is_WOW64() ? "; WOW64" : "");
	hSession = InternetOpenA((user_agent == NULL) ? default_agent : user_agent,
		INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
	if (hSession == NULL)
		return NULL;
	if (WindowsVersion.Version == WINDOWS_7)
		IGNORE_RETVAL(InternetSetOptionA(hSession, INTERNET_OPTION_REFRESH, NULL, 0));
	// Set the timeouts
	InternetSetOptionA(hSession, INTERNET_OPTION_CONNECT_TIMEOUT, (LPVOID)&dwTimeout, sizeof(dwTimeout));
	InternetSetOptionA(hSession, INTERNET_OPTION_SEND_TIMEOUT, (LPVOID)&dwTimeout, sizeof(dwTimeout));
	InternetSetOptionA(hSession, INTERNET_OPTION_RECEIVE_TIMEOUT, (LPVOID)&dwTimeout, sizeof(dwTimeout));
	// Enable gzip and deflate decoding schemes
	InternetSetOptionA(hSession, INTERNET_OPTION_HTTP_DECODING, (LPVOID)&decodingSupport, sizeof(decodingSupport));
	// Enable HTTP/2 protocol support
	InternetSetOptionA(hSession, INTERNET_OPTION_ENABLE_HTTP_PROTOCOL, (LPVOID)&dwProtocolSupport, sizeof(dwProtocolSupport));
	return hSession;
}

/*
 * Download a file or fill a buffer from an URL
 * Mostly taken from http://support.microsoft.com/kb/234913
 * If file is NULL, a buffer is allocated for the download (that needs to be freed by the caller)
 * If hProgressDialog is not NULL, this function will send INIT and EXIT messages
 * to the dialog in question, with WPARAM being set to nonzero for EXIT on success
 * and also attempt to indicate progress using an IDC_PROGRESS control
 * Note that when a buffer is used, the actual size of the buffer is two more than its reported
 * size (with the extra bytes set to 0) to accommodate for calls that need NUL-terminated data.
 */
uint64_t DownloadToFileOrBufferEx(const char* url, const char* file, const char* user_agent,
	BYTE** buffer, HWND hProgressDialog, BOOL bTaskBarProgress)
{
	const char* accept_types[] = { "*/*\0", NULL };
	const char* short_name;
	unsigned char buf[DOWNLOAD_BUFFER_SIZE];
	char hostname[64], urlpath[1024], strsize[32] = { 0 };
	BOOL r = FALSE, use_github_api, has_content_length = FALSE;
	DWORD dwSize, dwWritten, dwDownloaded, request_error;
	int send_attempt;
	BYTE* resized_buffer;
	HANDLE hFile = INVALID_HANDLE_VALUE;
	HINTERNET hSession = NULL, hConnection = NULL, hRequest = NULL;
	URL_COMPONENTSA UrlParts = { sizeof(URL_COMPONENTSA), NULL, 1, (INTERNET_SCHEME)0,
		hostname, sizeof(hostname), 0, NULL, 1, urlpath, sizeof(urlpath), NULL, 1 };
	uint64_t size = 0, total_size = 0;
	size_t buffer_capacity = 0, required_capacity, new_capacity;

	ErrorStatus = 0;
	DownloadStatus = 404;
	// Force-fail networking and use local dbx instead (port)
	if (WindowsVersion.Version <= WINDOWS_VISTA) {
		if (buffer != NULL)
			*buffer = NULL;
		SetLastError(ERROR_NOT_SUPPORTED);
		return 0;
	}
	if (hProgressDialog != NULL) {
		UpdateProgressWithInfoInit(hProgressDialog, FALSE);
		if ((hProgressDialog == hMainDialog) && !bTaskBarProgress)
			SetTaskbarProgressState(TASKBAR_NOPROGRESS);
	}

	assert(url != NULL);
	if (buffer != NULL)
		*buffer = NULL;

	short_name = (file != NULL) ? PathFindFileNameU(file) : PathFindFileNameU(url);

	if (hProgressDialog != NULL) {
		PrintInfo(5000, MSG_085, short_name);
		uprintf("Downloading %s", url);
	}

	if ((!InternetCrackUrlA(url, (DWORD)safe_strlen(url), 0, &UrlParts))
		|| (UrlParts.lpszHostName == NULL) || (UrlParts.lpszUrlPath == NULL)) {
		uprintf("Unable to decode URL: %s", WindowsErrorString());
		goto out;
	}
	hostname[sizeof(hostname) - 1] = 0;

	// If we are querying the GitHub API, we need to enable raw content and
	// set 'Accept-Encoding' to 'none' to get the data length.
	use_github_api = (strstr(url, "api.github.com") != NULL);
	for (send_attempt = 0; send_attempt < 2; send_attempt++) {
		hSession = GetInternetSession(user_agent, TRUE);
		if (hSession == NULL) {
			uprintf("Could not open Internet session: %s", WindowsErrorString());
			if (WindowsVersion.Version == WINDOWS_VISTA)
				uprintf("%s", lmprintf(MSG_547));
			if (WindowsVersion.Version >= WINDOWS_7)
				uprintf("Make sure TLS 1.2 is enabled in Internet Options.");
			goto out;
		}

		hConnection = InternetConnectA(hSession, UrlParts.lpszHostName, UrlParts.nPort,
			NULL, NULL, INTERNET_SERVICE_HTTP, 0, (DWORD_PTR)NULL);
		if (hConnection == NULL) {
			uprintf("Could not connect to server %s:%d: %s", UrlParts.lpszHostName,
				UrlParts.nPort, WindowsErrorString());
			goto out;
		}

		hRequest = HttpOpenRequestA(hConnection, "GET", UrlParts.lpszUrlPath, NULL, NULL, accept_types,
			INTERNET_FLAG_IGNORE_REDIRECT_TO_HTTP | INTERNET_FLAG_IGNORE_REDIRECT_TO_HTTPS |
			INTERNET_FLAG_NO_COOKIES | INTERNET_FLAG_NO_UI | INTERNET_FLAG_NO_CACHE_WRITE |
			INTERNET_FLAG_HYPERLINK | INTERNET_FLAG_RELOAD |
			((UrlParts.nScheme == INTERNET_SCHEME_HTTPS) ? INTERNET_FLAG_SECURE : 0), (DWORD_PTR)NULL);
		if (hRequest == NULL) {
			uprintf("Could not open URL %s: %s", url, WindowsErrorString());
			goto out;
		}

		if (use_github_api && !HttpAddRequestHeadersA(hRequest,
			"Accept: application/vnd.github.v3.raw", (DWORD)-1, HTTP_ADDREQ_FLAG_ADD)) {
			uprintf("Unable to enable raw content from GitHub API: %s", WindowsErrorString());
			goto out;
		}
		if (HttpSendRequestA(hRequest, request_headers[use_github_api ? 0 : 1], -1L, NULL, 0))
			break;

		request_error = GetLastError();
		if ((WindowsVersion.Version != WINDOWS_7) ||
			(request_error != ERROR_INTERNET_SECURITY_CHANNEL_ERROR) || (send_attempt != 0)) {
			SetLastError(request_error);
			uprintf("Unable to send request: %s", WindowsErrorString());
			goto out;
		}

		uprintf("Secure channel failed; retrying with a new WinINet session...");
		InternetCloseHandle(hRequest);
		InternetCloseHandle(hConnection);
		InternetCloseHandle(hSession);
		hRequest = NULL;
		hConnection = NULL;
		hSession = NULL;
		IGNORE_RETVAL(InternetSetOptionA(NULL, INTERNET_OPTION_SETTINGS_CHANGED, NULL, 0));
	}

	// Get the file size
	dwSize = sizeof(DownloadStatus);
	HttpQueryInfoA(hRequest, HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER, (LPVOID)&DownloadStatus, &dwSize, NULL);
	if (DownloadStatus != 200) {
		error_code = ERROR_INTERNET_ITEM_NOT_FOUND;
		SetLastError(RUFUS_ERROR(error_code));
		uprintf("%s '%s': %d", (DownloadStatus == 404) ? "File not found" : "Unable to access file", url, DownloadStatus);
		goto out;
	}
	dwSize = sizeof(strsize) - 1;
	has_content_length = HttpQueryInfoA(hRequest, HTTP_QUERY_CONTENT_LENGTH,
		(LPVOID)strsize, &dwSize, NULL);
	if (has_content_length) {
		strsize[dwSize] = 0;
		total_size = strtoull(strsize, NULL, 10);
	}

	if (hProgressDialog != NULL && has_content_length) {
		char msg[128];
		uprintf("File length: %s", SizeToHumanReadable(total_size, FALSE, FALSE));
		if (right_to_left_mode)
			static_sprintf(msg, "(%s) %s", SizeToHumanReadable(total_size, FALSE, FALSE), GetShortName(url));
		else
			static_sprintf(msg, "%s (%s)", GetShortName(url), SizeToHumanReadable(total_size, FALSE, FALSE));
		PrintStatus(5000, MSG_085, msg);
	}

	if (file != NULL) {
		hFile = CreateFileU(file, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
		if (hFile == INVALID_HANDLE_VALUE) {
			uprintf("Unable to create file '%s': %s", short_name, WindowsErrorString());
			goto out;
		}
	}
	else {
		if (buffer == NULL) {
			uprintf("No buffer pointer provided for download");
			goto out;
		}
		// Start off with a normal block if final response is unknown
		// Why do you gotta be like that sbat?
		if (has_content_length && total_size > (uint64_t)(SIZE_MAX - 2)) {
			uprintf("Download is too large for this process");
			goto out;
		}
		buffer_capacity = has_content_length ? (size_t)total_size + 2 : DOWNLOAD_BUFFER_SIZE + 2;
		*buffer = calloc(buffer_capacity, 1);
		if (*buffer == NULL) {
			uprintf("Could not allocate buffer for download");
			goto out;
		}
	}

	// Keep checking for data until there is nothing left.
	while (1) {
		// User may have cancelled the download
		if (IS_ERROR(ErrorStatus))
			goto out;
		if (!InternetReadFile(hRequest, buf, sizeof(buf), &dwDownloaded)) {
			uprintf("Error reading download: %s", WindowsErrorString());
			goto out;
		}
		if (dwDownloaded == 0)
			break;
		if (hProgressDialog != NULL && has_content_length)
			UpdateProgressWithInfo(bTaskBarProgress ? OP_NOOP_WITH_TASKBAR : OP_NOOP,
				MSG_241, size, total_size);
		if (file != NULL) {
			if (!WriteFile(hFile, buf, dwDownloaded, &dwWritten, NULL)) {
				uprintf("Error writing file '%s': %s", short_name, WindowsErrorString());
				goto out;
			}
			else if (dwDownloaded != dwWritten) {
				uprintf("Error writing file '%s': Only %d/%d bytes written", short_name, dwWritten, dwDownloaded);
				goto out;
			}
		}
		else {
			// Grow memory downloads as data arrives when the server uses chunked transfer encoding
			if (size > (uint64_t)(SIZE_MAX - dwDownloaded - 2)) {
				uprintf("Download is too large for this process");
				goto out;
			}
			required_capacity = (size_t)size + dwDownloaded + 2;
			if (required_capacity > buffer_capacity) {
				new_capacity = buffer_capacity;
				while (new_capacity < required_capacity && new_capacity <= SIZE_MAX / 2)
					new_capacity *= 2;
				if (new_capacity < required_capacity)
					new_capacity = required_capacity;
				resized_buffer = (BYTE*)realloc(*buffer, new_capacity);
				if (resized_buffer == NULL) {
					uprintf("Could not grow download buffer");
					goto out;
				}
				*buffer = resized_buffer;
				buffer_capacity = new_capacity;
			}
			memcpy(&(*buffer)[size], buf, dwDownloaded);
		}
		size += dwDownloaded;
	}

	if (buffer != NULL) {
		(*buffer)[size] = 0;
		(*buffer)[size + 1] = 0;
	}
	if (has_content_length && size != total_size) {
		uprintf("Could not download complete file - read: %lld bytes, expected: %lld bytes", size, total_size);
		ErrorStatus = RUFUS_ERROR(ERROR_WRITE_FAULT);
		goto out;
	}
	else {
		DownloadStatus = 200;
		r = TRUE;
		// No
		SetLastError(ERROR_SUCCESS);
		if (hProgressDialog != NULL) {
			if (has_content_length)
				UpdateProgressWithInfo(bTaskBarProgress ? OP_NOOP_WITH_TASKBAR : OP_NOOP,
					MSG_241, total_size, total_size);
			uprintf("Successfully downloaded '%s'", short_name);
		}
	}

out:
	error_code = GetLastError();
	if (hFile != INVALID_HANDLE_VALUE) {
		FlushFileBuffers(hFile);
		CloseHandle(hFile);
	}
	if (!r) {
		if (file != NULL)
			DeleteFileU(file);
		if (buffer != NULL)
			safe_free(*buffer);
	}
	if (hRequest)
		InternetCloseHandle(hRequest);
	if (hConnection)
		InternetCloseHandle(hConnection);
	if (hSession)
		InternetCloseHandle(hSession);
	if (hProgressDialog != NULL) {
		SendMessage(hProgressDialog, UM_PROGRESS_EXIT, (WPARAM)(r ? size : 0), 0);
		if (hProgressDialog == hMainDialog)
			SetTaskbarProgressState(TASKBAR_NOPROGRESS);
	}

	SetLastError(error_code);
	return r ? size : 0;
}

// Download and validate a signed file. The file must have a corresponding '.sig' on the server.
DWORD DownloadSignedFile(const char* url, const char* file, HWND hProgressDialog, BOOL bPromptOnError)
{
	char* url_sig = NULL;
	BYTE* buf = NULL, * sig = NULL;
	DWORD buf_len = 0, sig_len = 0;
	DWORD ret = 0;
	HANDLE hFile = INVALID_HANDLE_VALUE;

	if (WindowsVersion.Version <= WINDOWS_VISTA) {
		SetLastError(ERROR_NOT_SUPPORTED);
		return 0;
	}
	assert(url != NULL);

	url_sig = malloc(strlen(url) + 5);
	if (url_sig == NULL) {
		uprintf("Could not allocate signature URL");
		goto out;
	}
	strcpy(url_sig, url);
	strcat(url_sig, ".sig");

	buf_len = (DWORD)DownloadToFileOrBuffer(url, NULL, &buf, hProgressDialog, FALSE);
	if (buf_len == 0)
		goto out;
	sig_len = (DWORD)DownloadToFileOrBuffer(url_sig, NULL, &sig, NULL, FALSE);
	if ((sig_len != RSA_SIGNATURE_SIZE) || (!ValidateOpensslSignature(buf, buf_len, sig, sig_len))) {
		uprintf("FATAL: Download signature is invalid ✗");
		DownloadStatus = 403;	// Forbidden
		ErrorStatus = RUFUS_ERROR(APPERR(ERROR_BAD_SIGNATURE));
		SendMessage(GetDlgItem(hProgressDialog, IDC_PROGRESS), PBM_SETSTATE, (WPARAM)PBST_ERROR, 0);
		SetTaskbarProgressState(TASKBAR_ERROR);
		goto out;
	}

	uprintf("Download signature is valid ✓");
	DownloadStatus = 206;	// Partial content
	hFile = CreateFileU(file, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		uprintf("Unable to create file '%s': %s", PathFindFileNameU(file), WindowsErrorString());
		goto out;
	}
	if (!WriteFile(hFile, buf, buf_len, &ret, NULL)) {
		uprintf("Error writing file '%s': %s", PathFindFileNameU(file), WindowsErrorString());
		ret = 0;
		goto out;
	}
	else if (ret != buf_len) {
		uprintf("Error writing file '%s': Only %d/%d bytes written", PathFindFileNameU(file), ret, buf_len);
		ret = 0;
		goto out;
	}
	DownloadStatus = 200;	// Full content

out:
	if (hProgressDialog != NULL) {
		SendMessage(hProgressDialog, UM_PROGRESS_EXIT, (WPARAM)ret, 0);
		if (hProgressDialog == hMainDialog)
			SetTaskbarProgressState(TASKBAR_NOPROGRESS);
	}
	if ((bPromptOnError) && (DownloadStatus != 200)) {
		PrintInfo(0, MSG_242);
		SetLastError(error_code);
		MessageBoxExU(hMainDialog, IS_ERROR(ErrorStatus) ? StrError(ErrorStatus, FALSE) : WindowsErrorString(),
			lmprintf(MSG_044), MB_OK | MB_ICONERROR | MB_IS_RTL, selected_langid);
	}
	safe_closehandle(hFile);
	free(url_sig);
	free(buf);
	free(sig);
	return ret;
}

/* Threaded download */
typedef struct {
	const char* url;
	const char* file;
	HWND hProgressDialog;
	BOOL bPromptOnError;
} DownloadSignedFileThreadArgs;

static DWORD WINAPI DownloadSignedFileThread(LPVOID param)
{
	DownloadSignedFileThreadArgs* args = (DownloadSignedFileThreadArgs*)param;
	ExitThread(DownloadSignedFile(args->url, args->file, args->hProgressDialog, args->bPromptOnError));
}

HANDLE DownloadSignedFileThreaded(const char* url, const char* file, HWND hProgressDialog, BOOL bPromptOnError)
{
	static DownloadSignedFileThreadArgs args;
	if (WindowsVersion.Version <= WINDOWS_VISTA) {
		SetLastError(ERROR_NOT_SUPPORTED);
		return NULL;
	}
	args.url = url;
	args.file = file;
	args.hProgressDialog = hProgressDialog;
	args.bPromptOnError = bPromptOnError;
	return CreateThread(NULL, 0, DownloadSignedFileThread, &args, 0, NULL);
}

static __inline uint64_t to_uint64_t(uint16_t x[3]) {
	int i;
	uint64_t ret = 0;
	for (i = 0; i < 3; i++)
		ret = (ret << 16) + x[i];
	return ret;
}

BOOL UseLocalDbx(int arch)
{
	char reg_name[32], path[MAX_PATH];
	static_sprintf(path, "%s\\%s\\dbx_%s.bin", app_data_dir, FILES_DIR, efi_archname[arch]);
	if (_accessU(path, 0) == -1)
		return FALSE;
	if (WindowsVersion.Version <= WINDOWS_VISTA)
		return TRUE;
	static_sprintf(reg_name, "DBXTimestamp_%s", efi_archname[arch]);
	return (uint64_t)ReadSetting64(reg_name) > dbx_info[arch - 1].timestamp;
}

static void CheckForDBXUpdates(int verbose)
{
	int i, r;
	char reg_name[32], timestamp_url[256], path[MAX_PATH], directory[MAX_PATH];
	char* p, * c, * rep, * buf = NULL;
	struct tm t = { 0 };
	uint64_t size, timestamp;
	BOOL already_prompted = FALSE;

	for (i = 0; i < ARRAYSIZE(dbx_info); i++) {
		// Get the epoch of the last commit
		timestamp = 0;
		static_strcpy(timestamp_url, dbx_info[i].url);
		p = strstr(timestamp_url, "contents/");
		if (p == NULL)
			continue;
		*p = 0;
		rep = replace_char(&p[9], '/', "%2F");
		static_strcat(timestamp_url, "commits?path=");
		static_strcat(timestamp_url, rep);
		free(rep);
		static_strcat(timestamp_url, "&page=1&per_page=1");
		vuprintf("Querying %s for DBX update timestamp", timestamp_url);
		size = DownloadToFileOrBuffer(timestamp_url, NULL, (BYTE**)&buf, NULL, FALSE);
		if (size == 0)
			continue;
		// Assumes that the GitHub JSON commit dates are of the form:
		// "date":[ ]*"2025-02-24T20:20:22Z"
		p = strstr(buf, "\"date\":");
		if (p == NULL) {
			safe_free(buf);
			continue;
		}
		c = &p[7];
		while (*c == ' ' || *c == '"')
			c++;
		p = c;
		while (*c != '"' && *c != '\0')
			c++;
		*c = 0;
		// "Thank you, X3J11 ANSI committee, for introducing the well thought through 'struct tm'", said ABSOLUTELY NOONE ever!
		r = sscanf(p, "%d-%d-%dT%d:%d:%dZ", &t.tm_year, &t.tm_mon, &t.tm_mday, &t.tm_hour, &t.tm_min, &t.tm_sec);
		safe_free(buf);
		if (r != 6)
			continue;
		t.tm_year -= 1900;
		t.tm_mon -= 1;
		timestamp = _mktime64(&t);
		vuprintf("DBX update timestamp is %" PRId64, timestamp);
		static_sprintf(reg_name, "DBXTimestamp_%s", efi_archname[i + 1]);
		// Check if we have an external DBX that is newer than embedded/last downloaded
		if (timestamp <= dbx_info[i].timestamp)
			continue;
		static_sprintf(path, "%s\\%s\\dbx_%s.bin", app_data_dir, FILES_DIR, efi_archname[i + 1]);
		if (PathFileExistsU(path) && timestamp <= (uint64_t)ReadSetting64(reg_name))
			continue;
		if (!already_prompted) {
			r = MessageBoxExU(hMainDialog, lmprintf(MSG_354), lmprintf(MSG_353),
				MB_YESNO | MB_ICONWARNING | MB_IS_RTL, selected_langid);
			already_prompted = TRUE;
			if (r != IDYES)
				break;
			// Create the parent directory
			static_sprintf(directory, "%s\\%s", app_data_dir, FILES_DIR);
			if ((_mkdirU(directory) != 0) && (errno != EEXIST)) {
				uprintf("Warning: Could not create DBX update directory '%s'", directory);
				break;
			}
		}
		if (DownloadToFileOrBuffer(dbx_info[i].url, path, NULL, NULL, FALSE) != 0) {
			WriteSetting64(reg_name, timestamp);
			uprintf("Saved %s as 'dbx_%s.bin'", dbx_info[i].url, efi_archname[i + 1]);
		}
		else
			uprintf("Warning: Failed to download %s", dbx_info[i].url);
	}
}

/*
 * Background thread to check for updates (including UEFI DBX updates)
 */
static DWORD WINAPI CheckForUpdatesThread(LPVOID param)
{
	BOOL releases_only = TRUE, found_new_version = FALSE;
	int status = 0;
	const char* server_url = RUFUS_URL "/";
	int i, j, k, max_channel, verbose = 0, verpos[4];
	static const char* channel[] = { "release", "beta", "test" };		// release channel
	const char* accept_types[] = { "*/*\0", NULL };
	char* buf = NULL;
	// Changed urlpath from 128 to 1024, same as in IsDownloadable()
	char agent[64], hostname[64], urlpath[1024], sigpath[256];
	DWORD dwSize, dwDownloaded, dwTotalSize, dwStatus;
	BYTE* sig = NULL;
	HINTERNET hSession = NULL, hConnection = NULL, hRequest = NULL;
	URL_COMPONENTSA UrlParts = { sizeof(URL_COMPONENTSA), NULL, 1, (INTERNET_SCHEME)0,
		hostname, sizeof(hostname), 0, NULL, 1, urlpath, sizeof(urlpath), NULL, 1 };
	SYSTEMTIME ServerTime, LocalTime;
	FILETIME FileTime;
	int64_t local_time = 0, reg_time, server_time, update_interval;
	verbose = ReadSetting32(SETTING_VERBOSE_UPDATES);
	// Without this the FileDialog will produce error 0x8001010E when compiled for Vista or later
	IGNORE_RETVAL(CoInitializeEx(NULL, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE));
	// Unless the update was forced, wait a while before performing the update check
	if (!force_update_check) {
		// It would of course be a lot nicer to use a timer and wake the thread, but my
		// development time is limited and this is FASTER to implement.
		do {
			for (i = 0; (i < 30) && (!force_update_check); i++)
				Sleep(500);
		} while ((!force_update_check) && ((op_in_progress || (dialog_showing > 0))));
		if (!force_update_check) {
			if ((ReadSetting32(SETTING_UPDATE_INTERVAL) == -1)) {
				vuprintf("Check for updates disabled, as per settings.");
				goto out;
			}
			reg_time = ReadSetting64(SETTING_LAST_UPDATE);
			update_interval = (int64_t)ReadSetting32(SETTING_UPDATE_INTERVAL);
			if (update_interval == 0) {
				WriteSetting32(SETTING_UPDATE_INTERVAL, DEFAULT_UPDATE_INTERVAL);
				update_interval = DEFAULT_UPDATE_INTERVAL;
			}
			GetSystemTime(&LocalTime);
			if (!SystemTimeToFileTime(&LocalTime, &FileTime))
				goto out;
			local_time = ((((int64_t)FileTime.dwHighDateTime) << 32) + FileTime.dwLowDateTime) / 10000000;
			vvuprintf("Local time: %" PRId64, local_time);
			if (local_time < reg_time + update_interval) {
				vuprintf("Next update check in %" PRId64 " seconds.", reg_time + update_interval - local_time);
				goto out;
			}
		}
	}

	// Perform the DBX Update check
	PrintInfoDebug(3000, MSG_352);
	CheckForDBXUpdates(verbose);

	PrintInfoDebug(3000, MSG_243);
	status++;	// 1

	if (!InternetCrackUrlA(server_url, (DWORD)safe_strlen(server_url), 0, &UrlParts))
		goto out;
	hostname[sizeof(hostname) - 1] = 0;

	static_sprintf(agent, APPLICATION_NAME "/%d.%d.%d (Windows NT %lu.%lu%s)",
		rufus_version[0], rufus_version[1], rufus_version[2],
		WindowsVersion.Major, WindowsVersion.Minor, is_WOW64() ? "; WOW64" : "");
	hSession = GetInternetSession(NULL, FALSE);
	if (hSession == NULL)
		goto out;
	hConnection = InternetConnectA(hSession, UrlParts.lpszHostName, UrlParts.nPort,
		NULL, NULL, INTERNET_SERVICE_HTTP, 0, (DWORD_PTR)NULL);
	if (hConnection == NULL)
		goto out;

	status++;	// 2
	// BETAs are only made available when the application arch is x86_64
	if (is_x86_64)
		releases_only = !ReadSettingBool(SETTING_INCLUDE_BETAS);

	// Test releases get their own distribution channel (and also force beta checks)
#if defined(TEST)
	max_channel = (int)ARRAYSIZE(channel);
#else
	max_channel = releases_only ? 1 : (int)ARRAYSIZE(channel) - 1;
#endif
	vuprintf("Using %s for the update check", RUFUS_URL);
	for (k = 0; (k < max_channel) && (!found_new_version); k++) {
		// Get the arch name and convert it lowercase
		char* archname = strdup(GetArchName(WindowsVersion.Arch));
		safe_strtolower(archname);
		// Free any previous buffers we might have used
		safe_free(buf);
		safe_free(sig);
		uprintf("Checking %s channel...", channel[k]);
		// At this stage we can query the server for various update version files.
		// We first try to lookup for "<appname>_<os_arch>_<os_version_major>_<os_version_minor>.ver"
		// and then remove each of the <os_> components until we find our match. For instance, we may first
		// look for rufus_win_x64_6.2.ver (Win8 x64) but only get a match for rufus_win_x64_6.ver (Vista x64 or later)
		// This allows sunsetting OS versions (eg XP) or providing different downloads for different archs/groups.
		// Note that for BETAs, we only catter for x64 regardless of the OS arch.
		static_sprintf(urlpath, "%s%s%s_win_%s_%lu.%lu.ver", APPLICATION_NAME, (k == 0) ? "" : "_",
			(k == 0) ? "" : channel[k], archname, WindowsVersion.Major, WindowsVersion.Minor);
		safe_free(archname);
		vuprintf("Base update check: %s", urlpath);
		for (i = 0, j = (int)safe_strlen(urlpath) - 5; (j > 0) && (i < ARRAYSIZE(verpos)); j--) {
			if ((urlpath[j] == '.') || (urlpath[j] == '_')) {
				verpos[i++] = j;
			}
		}
		assert(i == ARRAYSIZE(verpos));

		UrlParts.lpszUrlPath = urlpath;
		UrlParts.dwUrlPathLength = sizeof(urlpath);
		for (i = 0; i < ARRAYSIZE(verpos); i++) {
			vvuprintf("Trying %s", UrlParts.lpszUrlPath);
			hRequest = HttpOpenRequestA(hConnection, "GET", UrlParts.lpszUrlPath, NULL, NULL, accept_types,
				INTERNET_FLAG_IGNORE_REDIRECT_TO_HTTP | INTERNET_FLAG_IGNORE_REDIRECT_TO_HTTPS |
				INTERNET_FLAG_NO_COOKIES | INTERNET_FLAG_NO_UI | INTERNET_FLAG_NO_CACHE_WRITE | INTERNET_FLAG_HYPERLINK |
				((UrlParts.nScheme == INTERNET_SCHEME_HTTPS) ? INTERNET_FLAG_SECURE : 0), (DWORD_PTR)NULL);
			if ((hRequest == NULL) || (!HttpSendRequestA(hRequest,
				request_headers[1], -1L, NULL, 0))) {
				uprintf("Unable to send request: %s", WindowsErrorString());
				goto out;
			}

			// Ensure that we get a text file
			dwSize = sizeof(dwStatus);
			dwStatus = 404;
			HttpQueryInfoA(hRequest, HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER, (LPVOID)&dwStatus, &dwSize, NULL);
			if (dwStatus == 200)
				break;
			InternetCloseHandle(hRequest);
			hRequest = NULL;
			safe_strcpy(&urlpath[verpos[i]], 5, ".ver");
		}
		if (dwStatus != 200) {
			vuprintf("Could not find a %s version file on server %s", channel[k], server_url);
			if ((releases_only) || (k + 1 >= ARRAYSIZE(channel)))
				goto out;
			continue;
		}
		vuprintf("Found match for %s on server %s", urlpath, server_url);

		// We also get a date from the web server, which we'll use to avoid out of sync check,
		// in case some set their clock way into the future and back.
		// On the other hand, if local clock is set way back in the past, we will never check.
		dwSize = sizeof(ServerTime);
		// If we can't get a date we can trust, don't bother...
		if ((!HttpQueryInfoA(hRequest, HTTP_QUERY_DATE | HTTP_QUERY_FLAG_SYSTEMTIME, (LPVOID)&ServerTime, &dwSize, NULL))
			|| (!SystemTimeToFileTime(&ServerTime, &FileTime)))
			goto out;
		server_time = ((((int64_t)FileTime.dwHighDateTime) << 32) + FileTime.dwLowDateTime) / 10000000;
		vvuprintf("Server time: %" PRId64, server_time);
		// Always store the server response time - the only clock we trust!
		WriteSetting64(SETTING_LAST_UPDATE, server_time);
		// Might as well let the user know
		if (!force_update_check) {
			if ((local_time > server_time + 600) || (local_time < server_time - 600)) {
				uprintf("IMPORTANT: Your local clock is more than 10 minutes in the %s. Unless you fix this, "
					APPLICATION_NAME " may not be able to check for updates...",
					(local_time > server_time + 600) ? "future" : "past");
			}
		}

		dwSize = sizeof(dwTotalSize);
		if (!HttpQueryInfoA(hRequest, HTTP_QUERY_CONTENT_LENGTH | HTTP_QUERY_FLAG_NUMBER, (LPVOID)&dwTotalSize, &dwSize, NULL))
			goto out;

		// Make sure the file is NUL terminated
		buf = (char*)calloc(dwTotalSize + 1, 1);
		if (buf == NULL)
			goto out;
		// This is a version file - we should be able to gulp it down in one go
		if (!InternetReadFile(hRequest, buf, dwTotalSize, &dwDownloaded) || (dwDownloaded != dwTotalSize))
			goto out;
		vuprintf("Successfully downloaded version file (%d bytes)", dwTotalSize);

		// Now download the signature file
		static_sprintf(sigpath, "%s/%s.sig", server_url, urlpath);
		dwDownloaded = (DWORD)DownloadToFileOrBuffer(sigpath, NULL, &sig, NULL, FALSE);
		if ((dwDownloaded != RSA_SIGNATURE_SIZE) || (!ValidateOpensslSignature(buf, dwTotalSize, sig, dwDownloaded))) {
			uprintf("FATAL: Version signature is invalid ✗");
			goto out;
		}
		vuprintf("Version signature is valid ✓");

		status++;
		parse_update(buf, dwTotalSize + 1);

		vuprintf("UPDATE DATA:");
		vuprintf("  version: %d.%d.%d (%s)", update.version[0], update.version[1], update.version[2], channel[k]);
		vuprintf("  platform_min: %d.%d", update.platform_min[0], update.platform_min[1]);
		vuprintf("  url: %s", update.download_url);

		found_new_version = ((to_uint64_t(update.version) > to_uint64_t(rufus_version)) || (force_update))
			&& ((WindowsVersion.Major > update.platform_min[0])
				|| ((WindowsVersion.Major == update.platform_min[0]) && (WindowsVersion.Minor >= update.platform_min[1])));
		uprintf("N%sew %s version found%c", found_new_version ? "" : "o n", channel[k], found_new_version ? '!' : '.');
	}

out:
	safe_free(buf);
	safe_free(sig);
	if (hRequest)
		InternetCloseHandle(hRequest);
	if (hConnection)
		InternetCloseHandle(hConnection);
	if (hSession)
		InternetCloseHandle(hSession);
	switch (status) {
	case 1:
		PrintInfoDebug(3000, MSG_244);
		break;
	case 2:
		// MSG_245 -> MSG_247, updates are disabled anyways, so show no updates available for aesthetics lol (port)
		PrintInfoDebug(3000, MSG_247);
		break;
	case 3:
	case 4:
		PrintInfo(3000, found_new_version ? MSG_246 : MSG_247);
	default:
		break;
	}
	// Start the new download after cleanup
	if (found_new_version) {
		// User may have started an operation while we were checking
		while ((!force_update_check) && (op_in_progress || (dialog_showing > 0))) {
			Sleep(15000);
		}
		DownloadNewVersion();
	}
	else if (force_update_check) {
		PostMessage(hMainDialog, UM_NO_UPDATE, 0, 0);
	}
	force_update_check = FALSE;
	update_check_thread = NULL;
	CoUninitialize();
	ExitThread(0);
}

/*
 * Initiate a check for updates. If force is true, ignore the wait period
 */
BOOL CheckForUpdates(BOOL force)
{
	// Disable networking on Windows Vista and older (port)
	if (WindowsVersion.Version <= WINDOWS_VISTA)
		return FALSE;
	force_update_check = force;
	if (update_check_thread != NULL)
		return FALSE;

	update_check_thread = CreateThread(NULL, 0, CheckForUpdatesThread, NULL, 0, NULL);
	if (update_check_thread == NULL) {
		uprintf("Unable to start update check thread");
		return FALSE;
	}
	return TRUE;
}

static int CheckPowerShellCandidate(const char* path, char* selected_path, size_t selected_path_size)
{
	int selection;
	LONG signature_status;
	version_t* version;
	char* choices[] = {
		lmprintf(MSG_537),
		lmprintf(MSG_538),
		lmprintf(MSG_539)
	};

	if ((path == NULL) || !PathFileExistsU((char*)path))
		return 0;
	version = GetExecutableVersion(path);
	if ((version == NULL) || (version->Major < 7)) {
		uprintf("Ignoring incompatible PowerShell executable '%s'", path);
		return 0;
	}
	signature_status = ValidateMicrosoftSignature(path);
	if (signature_status == ERROR_SUCCESS) {
		safe_strcpy(selected_path, selected_path_size, path);
		WriteRegistryKeyStr(REGKEY_HKCU, SETTING_POWERSHELL_PATH, selected_path);
		uprintf("Using signed PowerShell 7 executable '%s'", selected_path);
		return 1;
	}

	selection = CustomSelectionDialog(BS_AUTORADIOBUTTON, lmprintf(MSG_535),
		lmprintf(MSG_536, path), choices, ARRAYSIZE(choices), 2, -1);
	if (selection == 1) {
		safe_strcpy(selected_path, selected_path_size, path);
		WriteRegistryKeyStr(REGKEY_HKCU, SETTING_POWERSHELL_PATH, selected_path);
		uprintf("WARNING: Using PowerShell 7 with an invalid signature at '%s'", selected_path);
		return 1;
	}
	if (selection == 2) {
		uprintf("Ignoring PowerShell 7 with an invalid signature at '%s'", path);
		return 2;
	}
	return -1;
}

static BOOL IsIgnoredPowerShellPath(const char* path, char ignored_paths[][MAX_PATH], size_t ignored_count)
{
	for (size_t i = 0; i < ignored_count; i++) {
		if (strcmpi(path, ignored_paths[i]) == 0)
			return TRUE;
	}
	return FALSE;
}

/*
 * Download an ISO through Fido
 */
static DWORD WINAPI DownloadISOThread(LPVOID param)
{
	BOOL is_vista = (WindowsVersion.Version == WINDOWS_VISTA);
	BOOL is_seven = (WindowsVersion.Version == WINDOWS_7);
	char locale_str[1024], cmdline[sizeof(locale_str) + 512], pipe[MAX_GUID_STRING_LENGTH + 16] = "\\\\.\\pipe\\";
	char powershell_path[MAX_PATH], icon_path[MAX_PATH] = { 0 }, script_path[MAX_PATH] = { 0 };
	char found_pwsh[MAX_PATH] = { 0 }, selected_powershell[MAX_PATH] = { 0 };
	char* url = NULL, sig_url[128];
	uint64_t uncompressed_size;
	int64_t size = -1;
	BYTE* compressed = NULL, * sig = NULL;
	HANDLE hFile = INVALID_HANDLE_VALUE, hPipe = INVALID_HANDLE_VALUE;
	DWORD dwExitCode = 99, dwCompressedSize, dwSize, dwAvail, dwPipeSize = 4096;
	DWORD previous_secure_protocols = 0;
	BOOL had_previous_secure_protocols = FALSE, win7_protocol_override = FALSE;
	LARGE_INTEGER patch_pos;
	char* version_line, * version_eol, * add_type_line, * show_window_line;
	GUID guid;

	dialog_showing++;
	IGNORE_RETVAL(CoInitializeEx(NULL, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE));
	// Disable Fido on Windows Vista and older
	if (WindowsVersion.Version <= WINDOWS_VISTA)
		goto out;
	if (!EnsureTLS12Enabled(hMainDialog))
		goto out;
	if (is_seven) {
		if (!ApplyWin7FidoProtocols(&previous_secure_protocols, &had_previous_secure_protocols)) {
			uprintf("Could not apply the Windows 7 TLS settings: %s", WindowsErrorString());
			goto out;
		}
		win7_protocol_override = TRUE;
	}

	// Use a GUID as random unique string, else ill-intentioned security "researchers"
	// may either spam our pipe or replace our script to fool antivirus solutions into
	// thinking that Rufus is doing something malicious...
	IGNORE_RETVAL(CoCreateGuid(&guid));
	// coverity[fixed_size_dest]
	strcpy(&pipe[9], GuidToString(&guid, TRUE));
	static_sprintf(icon_path, "%s%s.ico", temp_dir, APPLICATION_NAME);
	ExtractAppIcon(icon_path, TRUE);

	//#define FORCE_URL "https://github.com/pbatard/rufus/raw/master/res/loc/test/windows_to_go.iso"
	//#define FORCE_URL "https://cdimage.debian.org/debian-cd/current/amd64/iso-cd/debian-9.8.0-amd64-netinst.iso"
#if !defined(FORCE_URL)
#if defined(RUFUS_TEST)
	IGNORE_RETVAL(hFile);
	IGNORE_RETVAL(sig_url);
	IGNORE_RETVAL(dwCompressedSize);
	IGNORE_RETVAL(uncompressed_size);
	// In test mode, just use our local script
	static_strcpy(script_path, "D:\\Projects\\Fido\\Fido.ps1");
#else
	// If we don't have the script, download it
	if (fido_script == NULL) {
		dwCompressedSize = (DWORD)DownloadToFileOrBuffer(fido_url, NULL, &compressed, hMainDialog, FALSE);
		if (dwCompressedSize == 0)
			goto out;
		static_sprintf(sig_url, "%s.sig", fido_url);
		dwSize = (DWORD)DownloadToFileOrBuffer(sig_url, NULL, &sig, NULL, FALSE);
		if ((dwSize != RSA_SIGNATURE_SIZE) || (!ValidateOpensslSignature(compressed, dwCompressedSize, sig, dwSize))) {
			uprintf("FATAL: Download signature is invalid ✗");
			ErrorStatus = RUFUS_ERROR(APPERR(ERROR_BAD_SIGNATURE));
			SendMessage(hProgress, PBM_SETSTATE, (WPARAM)PBST_ERROR, 0);
			SetTaskbarProgressState(TASKBAR_ERROR);
			safe_free(compressed);
			free(sig);
			goto out;
		}
		free(sig);
		uprintf("Download signature is valid ✓");
		uncompressed_size = *((uint64_t*)&compressed[5]);
		if ((uncompressed_size < 1 * MB) && (bled_init(0, uprintf, NULL, NULL, NULL, NULL, &ErrorStatus) >= 0)) {
			fido_script = malloc((size_t)uncompressed_size);
			size = bled_uncompress_from_buffer_to_buffer(compressed, dwCompressedSize, fido_script, (size_t)uncompressed_size, BLED_COMPRESSION_LZMA);
			bled_exit();
		}
		safe_free(compressed);
		if (size != uncompressed_size) {
			uprintf("FATAL: Could not uncompressed download script");
			safe_free(fido_script);
			ErrorStatus = RUFUS_ERROR(ERROR_INVALID_DATA);
			SendMessage(hProgress, PBM_SETSTATE, (WPARAM)PBST_ERROR, 0);
			SetTaskbarProgressState(TASKBAR_ERROR);
			goto out;
		}
		fido_len = (DWORD)size;

		SendMessage(hProgress, PBM_SETSTATE, (WPARAM)PBST_NORMAL, 0);
		SendMessage(hProgress, PBM_SETPOS, 0, 0);
	}
	PrintInfo(0, MSG_148);

	if ((fido_script == NULL) || (fido_len == 0))
		goto out;

	// Why oh why does PowerShell refuse to open read-only files that haven't been closed?
	// Because of this limitation, we can't fully prevent TOCTOUs on the file we create, and therefore we:
	// - Create the file with a "random" non-guessable name => TOCTOUs require a permanently running script/exe
	// - Create the file in the user's AppData temp directory => TOCTOUs can't be enacted by a different user
	// - Create the file with Administrator access only => TOCTOUs require elevated privileges (in which case
	// the machine is already compromised anyway, so TOCTOU attacks become entirely moot)
	// See https://github.com/pbatard/rufus/security/advisories/GHSA-hcx5-hrhj-xhq9 and CVE-2026-23988.
	static_sprintf(script_path, "%s%s.ps1", temp_dir, GuidToString(&guid, TRUE));
	hFile = CreateFileRestrictedU(script_path, GENERIC_WRITE, FILE_SHARE_READ,
		CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL);
	if (hFile == INVALID_HANDLE_VALUE) {
		uprintf("Unable to create download script '%s': %s", script_path, WindowsErrorString());
		goto out;
	}
	if ((!WriteFile(hFile, fido_script, fido_len, &dwSize, NULL)) || (dwSize != fido_len)) {
		uprintf("Unable to write download script '%s': %s", script_path, WindowsErrorString());
		goto out;
	}
	safe_closehandle(hFile);
	if (ValidateSignature(INVALID_HANDLE_VALUE, script_path) != NO_ERROR) {
		uprintf("FATAL: Script signature is invalid ✗");
		ErrorStatus = RUFUS_ERROR(APPERR(ERROR_BAD_SIGNATURE));
		SendMessage(hProgress, PBM_SETSTATE, (WPARAM)PBST_ERROR, 0);
		SetTaskbarProgressState(TASKBAR_ERROR);
		goto out;
	}
	uprintf("Script signature is valid ✓");

	// FIDO PATCH (port)
	if (is_vista || is_seven) {
		version_line = strstr((char*)fido_script, "$winver =");
		version_eol = (version_line == NULL) ? NULL : strchr(version_line, '\n');
		add_type_line = strstr((char*)fido_script, "Add-Type @Signature");
		show_window_line = strstr((char*)fido_script, "[WinAPI.Utils]::ShowWindow");
		if ((version_eol != NULL) && (version_eol - version_line >= 17)) {
			hFile = CreateFileU(script_path, GENERIC_WRITE, FILE_SHARE_READ, NULL,
				OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
			patch_pos.QuadPart = version_line - (char*)fido_script;
			if ((hFile == INVALID_HANDLE_VALUE) || !SetFilePointerEx(hFile, patch_pos, NULL, FILE_BEGIN) ||
				!WriteFile(hFile, "$winver = 10.0; #", 17, &dwSize, NULL) || (dwSize != 17)) {
				uprintf("Could not prepare Fido for PowerShell 7: %s", WindowsErrorString());
				safe_closehandle(hFile);
				goto out;
			}
			if ((add_type_line != NULL) && (show_window_line != NULL)) {
				patch_pos.QuadPart = add_type_line - (char*)fido_script;
				if (!SetFilePointerEx(hFile, patch_pos, NULL, FILE_BEGIN) ||
					!WriteFile(hFile, "#", 1, &dwSize, NULL) || (dwSize != 1)) {
					uprintf("Could not prepare the Fido window: %s", WindowsErrorString());
					safe_closehandle(hFile);
					goto out;
				}
				patch_pos.QuadPart = show_window_line - (char*)fido_script;
				if (!SetFilePointerEx(hFile, patch_pos, NULL, FILE_BEGIN) ||
					!WriteFile(hFile, "#", 1, &dwSize, NULL) || (dwSize != 1)) {
					uprintf("Could not prepare the Fido window: %s", WindowsErrorString());
					safe_closehandle(hFile);
					goto out;
				}
			}
			safe_closehandle(hFile);
			duprintf("Adjusted Fido version check for PowerShell 7");
		}
	}
	SetFileAttributesU(script_path, FILE_ATTRIBUTE_READONLY);
#endif
	static_sprintf(powershell_path, "%s\\WindowsPowerShell\\v1.0\\powershell.exe", system_dir);
	static_sprintf(locale_str, "%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s",
		selected_locale->txt[0], lmprintf(MSG_135), lmprintf(MSG_136), lmprintf(MSG_137),
		lmprintf(MSG_138), lmprintf(MSG_139), lmprintf(MSG_040), lmprintf(MSG_140), lmprintf(MSG_141),
		lmprintf(MSG_006), lmprintf(MSG_007), lmprintf(MSG_042), lmprintf(MSG_142), lmprintf(MSG_143),
		lmprintf(MSG_144), lmprintf(MSG_145), lmprintf(MSG_146), lmprintf(MSG_199));

	hPipe = CreateNamedPipeA(pipe, PIPE_ACCESS_INBOUND,
		PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT, PIPE_UNLIMITED_INSTANCES,
		dwPipeSize, dwPipeSize, 0, NULL);
	if (hPipe == INVALID_HANDLE_VALUE) {
		uprintf("Could not create pipe '%s': %s", pipe, WindowsErrorString());
		goto out;
	}

	// External Powershell for Fido on 7 and Vista (port)
	if (WindowsVersion.Version >= WINDOWS_8)
		static_strcpy(selected_powershell, powershell_path);
	if (selected_powershell[0] == 0) {
		const char* pwsh_candidates[] = {
			"C:\\Program Files\\PowerShell\\7\\pwsh.exe",
			"C:\\Program Files (x86)\\PowerShell\\7\\pwsh.exe",
			"C:\\Program Files\\PowerShell\\7-preview\\pwsh.exe",
		};

		int candidate_status;
		char cached_pwsh[MAX_PATH] = { 0 }, checked_locations[3 * MAX_PATH] = { 0 };
		char expanded_pwsh[MAX_PATH] = { 0 }, powershell_prompt[1024] = { 0 };
		char ignored_pwsh[4][MAX_PATH] = { 0 };
		char reg_subkey[MAX_PATH] = { 0 };
		HKEY hParentKey, hSubKey;
		DWORD reg_type, subkey_index, subkey_len, val_size;
		REGSAM reg_views[] = { KEY_READ | KEY_WOW64_64KEY, KEY_READ | KEY_WOW64_32KEY };
		size_t ignored_pwsh_count = 0;

		safe_strcpy(cached_pwsh, sizeof(cached_pwsh), ReadRegistryKeyStr(REGKEY_HKCU, SETTING_POWERSHELL_PATH));
		if (cached_pwsh[0] != 0) {
			candidate_status = CheckPowerShellCandidate(cached_pwsh, selected_powershell, sizeof(selected_powershell));
			if (candidate_status < 0)
				goto out;
			if (candidate_status != 1)
				WriteRegistryKeyStr(REGKEY_HKCU, SETTING_POWERSHELL_PATH, "");
			if (candidate_status == 2)
				safe_strcpy(ignored_pwsh[ignored_pwsh_count++], MAX_PATH, cached_pwsh);
		}

		for (size_t k = 0; (selected_powershell[0] == 0) && (k < ARRAYSIZE(pwsh_candidates)); k++) {
			if (IsIgnoredPowerShellPath(pwsh_candidates[k], ignored_pwsh, ignored_pwsh_count) ||
				((cached_pwsh[0] != 0) && (strcmpi(cached_pwsh, pwsh_candidates[k]) == 0)))
				continue;
			candidate_status = CheckPowerShellCandidate(pwsh_candidates[k], selected_powershell, sizeof(selected_powershell));
			if (candidate_status < 0)
				goto out;
			if ((candidate_status == 2) && (ignored_pwsh_count < ARRAYSIZE(ignored_pwsh)))
				safe_strcpy(ignored_pwsh[ignored_pwsh_count++], MAX_PATH, pwsh_candidates[k]);
			if (candidate_status == 1)
				break;
		}

		if (selected_powershell[0] == 0) {
			for (size_t view = 0; (selected_powershell[0] == 0) && (view < ARRAYSIZE(reg_views)); view++) {
				subkey_index = 0;
				if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\PowerShellCore\\InstalledVersions",
					0, reg_views[view], &hParentKey) != ERROR_SUCCESS)
					continue;
				while (subkey_len = sizeof(reg_subkey),
					RegEnumKeyExA(hParentKey, subkey_index++, reg_subkey, &subkey_len, NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
					char full_subkey_path[MAX_PATH];
					static_sprintf(full_subkey_path, "SOFTWARE\\Microsoft\\PowerShellCore\\InstalledVersions\\%s", reg_subkey);
					if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, full_subkey_path, 0, reg_views[view], &hSubKey) != ERROR_SUCCESS)
						continue;
					val_size = sizeof(found_pwsh);
					reg_type = 0;
					found_pwsh[0] = 0;
					if ((RegQueryValueExA(hSubKey, "InstallLocation", NULL, &reg_type,
						(LPBYTE)found_pwsh, &val_size) != ERROR_SUCCESS) || (found_pwsh[0] == 0)) {
						val_size = sizeof(found_pwsh);
						reg_type = 0;
						found_pwsh[0] = 0;
						RegQueryValueExA(hSubKey, "InstallDir", NULL, &reg_type, (LPBYTE)found_pwsh, &val_size);
					}
					if (((reg_type == REG_SZ) || (reg_type == REG_EXPAND_SZ)) && (found_pwsh[0] != 0)) {
						found_pwsh[sizeof(found_pwsh) - 1] = 0;
						if (reg_type == REG_EXPAND_SZ) {
							DWORD expanded_len;
							expanded_pwsh[0] = 0;
							expanded_len = ExpandEnvironmentStringsA(found_pwsh, expanded_pwsh, ARRAYSIZE(expanded_pwsh));
							if ((expanded_len != 0) && (expanded_len <= ARRAYSIZE(expanded_pwsh)))
								safe_strcpy(found_pwsh, sizeof(found_pwsh), expanded_pwsh);
						}
						PathCombineA(found_pwsh, found_pwsh, "pwsh.exe");
						if (!IsIgnoredPowerShellPath(found_pwsh, ignored_pwsh, ignored_pwsh_count) &&
							((cached_pwsh[0] == 0) || (strcmpi(cached_pwsh, found_pwsh) != 0))) {
							candidate_status = CheckPowerShellCandidate(found_pwsh, selected_powershell, sizeof(selected_powershell));
							if (candidate_status < 0) {
								RegCloseKey(hSubKey);
								RegCloseKey(hParentKey);
								goto out;
							}
							if ((candidate_status == 2) && (ignored_pwsh_count < ARRAYSIZE(ignored_pwsh)))
								safe_strcpy(ignored_pwsh[ignored_pwsh_count++], MAX_PATH, found_pwsh);
						}
					}
					RegCloseKey(hSubKey);
					if (selected_powershell[0] != 0)
						break;
				}
				RegCloseKey(hParentKey);
			}
		}

		if (selected_powershell[0] == 0) {
			safe_sprintf(checked_locations, sizeof(checked_locations), "%s\n%s\n%s",
				pwsh_candidates[0], pwsh_candidates[1], pwsh_candidates[2]);
			MessageBoxExU(hMainDialog, lmprintf(MSG_534, checked_locations), lmprintf(MSG_533),
				MB_OK | MB_ICONINFORMATION | MB_IS_RTL, selected_langid);
			if (!IsDotNet45OrNewerInstalled()) {
				int response;
				if (is_vista) {
					response = MessageBoxA(NULL,
						"Powershell 7 requires .NET Framework 4.6 or newer to run, but it isn't detected on your system.\n\n"
						"Would you like to open your browser to download .NET Framework 4.6?",
						".NET Framework 4.6 Required",
						MB_YESNO | MB_ICONEXCLAMATION);

					if (response == IDYES) {
						ShellExecuteA(NULL, "open",
							"https://www.microsoft.com/en-us/download/details.aspx?id=48130",
							NULL, NULL, SW_SHOWNORMAL);
					}
				}
				else {
					response = MessageBoxA(NULL,
						"Windows Management Framework (WMF) requires .NET Framework 4.5.2 or newer to be installed, but it isn't detected on your system.\n\n"
						"Would you like to open your browser to download .NET Framework 4.8?",
						".NET Framework 4.5.2+ Required",
						MB_YESNO | MB_ICONEXCLAMATION);

					if (response == IDYES) {
						ShellExecuteA(NULL, "open",
							"https://dotnet.microsoft.com/en-us/download/dotnet-framework/net48",
							NULL, NULL, SW_SHOWNORMAL);
					}
				}
				goto out;
			}

			if (!is_vista && !IsWMF4OrNewerInstalled()) {
				int response = MessageBoxA(NULL,
					"PowerShell needs Windows Management Framework (WMF) 4.0 or newer to run, but your system version is out of date.\n\n"
					"Would you like to open your browser to download WMF 5.1?",
					"WMF 4.0+ Required",
					MB_YESNO | MB_ICONEXCLAMATION);

				if (response == IDYES) {
					ShellExecuteA(NULL, "open",
						"https://www.microsoft.com/en-us/download/details.aspx?id=54616",
						NULL, NULL, SW_SHOWNORMAL);
				}
				goto out;
			}

			int response;
			if (is_vista) {
				safe_sprintf(powershell_prompt, sizeof(powershell_prompt), "%s\n\n%s", lmprintf(MSG_540), lmprintf(MSG_541));
			}
			else if (is_seven) {
				safe_sprintf(powershell_prompt, sizeof(powershell_prompt), "%s\n\n%s", lmprintf(MSG_540), lmprintf(MSG_542));
			}
			else {
				safe_sprintf(powershell_prompt, sizeof(powershell_prompt), "%s\n\n%s", lmprintf(MSG_540), lmprintf(MSG_543));
			}
			response = MessageBoxExU(hMainDialog, powershell_prompt, lmprintf(MSG_533),
				MB_YESNO | MB_ICONEXCLAMATION | MB_IS_RTL, selected_langid);

			if (response == IDYES) {
				if (is_vista) {
					ShellExecuteA(NULL, "open",
						"https://forum.legacydev.org/viewtopic.php?t=231",
						NULL, NULL, SW_SHOWNORMAL);
				}
				else if (is_seven) {
					ShellExecuteA(NULL, "open",
						"https://github.com/PowerShell/PowerShell/releases/download/v7.2.24/PowerShell-7.2.24-win-x64.msi",
						NULL, NULL, SW_SHOWNORMAL);
				}
				else {
					ShellExecuteA(NULL, "open",
						"https://github.com/PowerShell/powershell/releases/latest",
						NULL, NULL, SW_SHOWNORMAL);
				}
			}

			goto out;
		}
	}

	if (is_vista) {
		// Written with Powershell 7.2.2 running through the extended kernel in mind
		// Credits go to TSNH https://forum.legacydev.org/viewtopic.php?t=231
		static_sprintf(cmdline,
			"\"%s\" -NonInteractive -Sta -NoLogo -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -Command \""
			"$host.UI.RawUI.WindowTitle = 'PowerShell 7'; "
			"[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; "
			"if ((Get-ExecutionPolicy) -ne 'AllSigned') { Set-ExecutionPolicy -Scope Process Bypass }; "
			"& '%s' -PipeName '%s' -LocData '%s' -Icon '%s' -AppTitle '%s' -PlatformArch '%s'\"",
			selected_powershell, script_path, &pipe[9], locale_str, icon_path, lmprintf(MSG_149), GetArchName(NativeMachine)
		);
	}
	else {
		static_sprintf(cmdline, "\"%s\" -NonInteractive -Sta -NoLogo -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass "
			"-Command \"[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; & '%s' -PipeName '%s' -LocData '%s' -Icon '%s' -AppTitle '%s' -PlatformArch '%s'\"",
			selected_powershell, script_path, &pipe[9], locale_str, icon_path, lmprintf(MSG_149), GetArchName(NativeMachine));
	}
	ErrorStatus = 0;
	dwExitCode = RunCommand(cmdline, app_data_dir, TRUE);
	uprintf("Exited download script with code: %d", dwExitCode);
	if ((dwExitCode == 0) && PeekNamedPipe(hPipe, NULL, dwPipeSize, NULL, &dwAvail, NULL) && (dwAvail != 0)) {
		url = malloc(dwAvail + 1);
		dwSize = 0;
		if ((url != NULL) && ReadFile(hPipe, url, dwAvail, &dwSize, NULL) && (dwSize > 4)) {
#else
			{ {	url = strdup(FORCE_URL);
			dwSize = (DWORD)strlen(FORCE_URL);
#endif
			IMG_SAVE img_save = { 0 };
			// WTF is wrong with Microsoft's static analyzer reporting a potential buffer overflow here?!?
#if defined(_MSC_VER)
#pragma warning(disable: 6386)
#endif
			url[min(dwSize, dwAvail)] = 0;
#if defined(_MSC_VER)
#pragma warning(default: 6386)
#endif
			EXT_DECL(img_ext, GetShortName(url), __VA_GROUP__("*.iso"), __VA_GROUP__(lmprintf(MSG_036)));
			img_save.Type = VIRTUAL_STORAGE_TYPE_DEVICE_ISO;
			img_save.ImagePath = FileDialog(TRUE, NULL, &img_ext, NULL);
			if (img_save.ImagePath == NULL) {
				goto out;
			}
			// Download the ISO and report errors if any
			SendMessage(hMainDialog, UM_PROGRESS_INIT, 0, 0);
			ErrorStatus = 0;
			SendMessage(hMainDialog, UM_TIMER_START, 0, 0);
			if (DownloadToFileOrBuffer(url, img_save.ImagePath, NULL, hMainDialog, TRUE) == 0) {
				if (SCODE_CODE(ErrorStatus) == ERROR_CANCELLED) {
					uprintf("Download cancelled by user");
					Notification(MSG_INFO, NULL, NULL, lmprintf(MSG_211), lmprintf(MSG_041));
					PrintInfo(0, MSG_211);
				}
				else {
					Notification(MSG_ERROR, NULL, NULL, lmprintf(MSG_194, GetShortName(url)), lmprintf(MSG_043, WindowsErrorString()));
					PrintInfo(0, MSG_212);
				}
			}
			else {
				// Download was successful => Select and scan the ISO
				image_path = safe_strdup(img_save.ImagePath);
				PostMessage(hMainDialog, UM_SELECT_ISO, 0, 0);
			}
			safe_free(img_save.ImagePath);
				}
			}

		out:
			SetTaskbarProgressState(TASKBAR_NOPROGRESS);
			safe_closehandle(hPipe);
			safe_closehandle(hFile);
			if (win7_protocol_override)
				RestoreWin7FidoProtocols(previous_secure_protocols, had_previous_secure_protocols);
			if (icon_path[0] != 0)
				DeleteFileU(icon_path);
#if !defined(RUFUS_TEST)
			if (script_path[0] != 0) {
				SetFileAttributesU(script_path, FILE_ATTRIBUTE_NORMAL);
				DeleteFileU(script_path);
			}
#endif
			free(url);
			SendMessage(hMainDialog, UM_ENABLE_CONTROLS, 0, 0);
			dialog_showing--;
			CoUninitialize();
			ExitThread(dwExitCode);
		}

BOOL DownloadISO()
{
	// Do not expose network-backed ISO downloads on Windows Vista and older. (port)
	if (WindowsVersion.Version <= WINDOWS_VISTA)
		return FALSE;
	if (CreateThread(NULL, 0, DownloadISOThread, NULL, 0, NULL) == NULL) {
		uprintf("Unable to start Windows ISO download thread");
		ErrorStatus = RUFUS_ERROR(APPERR(ERROR_CANT_START_THREAD));
		SendMessage(hMainDialog, UM_ENABLE_CONTROLS, 0, 0);
		return FALSE;
	}
	return TRUE;
}

BOOL IsDownloadable(const char* url)
{
	DWORD dwSize, dwTotalSize = 0;
	const char* accept_types[] = { "*/*\0", NULL };
	// Changed urlpath from 128 to 1024, modern microsoft download URLs reach 400 + characters in some cases
	char hostname[64], urlpath[1024];
	HINTERNET hSession = NULL, hConnection = NULL, hRequest = NULL;
	URL_COMPONENTSA UrlParts = { sizeof(URL_COMPONENTSA), NULL, 1, (INTERNET_SCHEME)0,
		hostname, sizeof(hostname), 0, NULL, 1, urlpath, sizeof(urlpath), NULL, 1 };

	// Do not probe remote URLs on Windows Vista and older. (port)
	if ((WindowsVersion.Version <= WINDOWS_VISTA) || (url == NULL))
		return FALSE;

	ErrorStatus = 0;
	DownloadStatus = 404;

	if ((!InternetCrackUrlA(url, (DWORD)safe_strlen(url), 0, &UrlParts))
		|| (UrlParts.lpszHostName == NULL) || (UrlParts.lpszUrlPath == NULL))
		goto out;
	hostname[sizeof(hostname) - 1] = 0;

	// Open an Internet session
	hSession = GetInternetSession(NULL, FALSE);
	if (hSession == NULL)
		goto out;

	hConnection = InternetConnectA(hSession, UrlParts.lpszHostName, UrlParts.nPort, NULL, NULL, INTERNET_SERVICE_HTTP, 0, (DWORD_PTR)NULL);
	if (hConnection == NULL)
		goto out;

	hRequest = HttpOpenRequestA(hConnection, "GET", UrlParts.lpszUrlPath, NULL, NULL, accept_types,
		INTERNET_FLAG_IGNORE_REDIRECT_TO_HTTP | INTERNET_FLAG_IGNORE_REDIRECT_TO_HTTPS |
		INTERNET_FLAG_NO_COOKIES | INTERNET_FLAG_NO_UI | INTERNET_FLAG_NO_CACHE_WRITE | INTERNET_FLAG_HYPERLINK |
		((UrlParts.nScheme == INTERNET_SCHEME_HTTPS) ? INTERNET_FLAG_SECURE : 0), (DWORD_PTR)NULL);
	if (hRequest == NULL)
		goto out;

	if (!HttpSendRequestA(hRequest, request_headers[1], -1L, NULL, 0))
		goto out;

	// Get the file size
	dwSize = sizeof(DownloadStatus);
	HttpQueryInfoA(hRequest, HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER, (LPVOID)&DownloadStatus, &dwSize, NULL);
	if (DownloadStatus != 200)
		goto out;
	dwSize = sizeof(dwTotalSize);
	HttpQueryInfoA(hRequest, HTTP_QUERY_CONTENT_LENGTH | HTTP_QUERY_FLAG_NUMBER, (LPVOID)&dwTotalSize, &dwSize, NULL);

out:
	if (hRequest)
		InternetCloseHandle(hRequest);
	if (hConnection)
		InternetCloseHandle(hConnection);
	if (hSession)
		InternetCloseHandle(hSession);

	return (dwTotalSize > 0);
}
