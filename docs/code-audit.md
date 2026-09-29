# Update 5 Audit (to make up for the unclear commits)
Rufus-NT was originally based on Rufus 4.7.2231 and evolved from my previous project Rufus-Legacy, (source uploaded under "Update 1").<br>
I decided to go with this exact version, as it's the last one to use a non-wimlib base and be compatible with old versions of VS2022.

Rufus-NT uses compatibility layers for Windows NT 4.0, Windows 2000 and Windows XP. Most fallbacks are selected at runtime through `WindowsVersion.Version`. In other words, compiling with `RUFUS_TARGET_NT4` only makes the compatibility code available, and doesn't force newer systems through the same compatibility paths meant for NT 4.0. This allows one executable to work completely fine on all Windows versions.

<details>
<summary><strong>1. Build and compatibility layout</strong></summary>
<br>

Rufus-NT produces one x86 executable for every supported system.

- `rufusnt.sln` builds the regular version with GRUB, Grub4DOS and Syslinux embedded, recommended for every system
- `rufusnt-noembed.sln` builds the smaller version, meant for Windows 7 and newer systems with working Internet access, saves around 900kb after compression
- Both .sln files use `.vs/rufus.vcxproj` and compile into `rufusnt.exe`
- Many code changes got separated into `RUFUS_TARGET_NT4` and `RUFUS_TARGET_WIN2K` during testing, it's pretty obsolete though as the NT4 and W2k paths are only loaded as fallbacks on newer OSes and are otherwise never used
- `RUFUS_NO_EMBED` removes the optional bootloader payloads 
- `nt4_imports.asm` and `win2k_imports.asm` replace imports that cannot be left in the executable unconditionally
- `.vs/patch_pe_subsystem.ps1` changes the final PE operating-system and subsystem versions to NT 4.0<br>
  The ps1 script is required as VS2022 doesn't support any subsys lower than 5.01 (XP x86) to pass through

Before uploading to github, every executable is compressed using UPX 3.91 from 2013-09-30 with "--lzma --best"

The main 'philosophy' behind the project is one executable being able to run on all operating systems. Everything works through fallbacks and OS-version checks, meaning native handling is always prefered depending on the OS and situation. 

</details>

<details>
<summary><strong>2. Windows NT 4.0</strong></summary>
<br>

This OS made me develop stockholmer syndrome. Rufus expects SetupAPI disk interfaces, volume GUIDs, modern partition structures and an actually working (_cough_) USB stack. NT4 provides none of these things. None. 

`nt4.c` and `nt4.h` implement/route the missing file, volume, shell, security, SetupAPI and Configuration Manager calls. `NT4_CreateFileA()` can reach a physical disk through a temporary DOS-device alias when `\\.\PhysicalDriveN` is unavailable. Volume mounting is handled by `AltMountVolume()` and `AltUnmountVolume()`, which use DOS-device mappings instead of volume GUID mount points.

Device discovery is handled through a small virtual SetupAPI set. `NT4_CreateVirtualDiskSet()` correlates drive letters and physical disks, then obtains the usable identity from SCSI inquiry data. Rufus' normal device loop can therefore keep using `SetupDiEnumDeviceInfo()` and related calls without having a second, completely separate device scanner.

Only information NT4 can actually report is exposed. The device name can receive a `USB Device` suffix, trying to fetch VID:PID BSODs NT4 so it's been left out as well. The end-of-list `ERROR_NO_MORE_ITEMS` result is ignored, and the extra media-presence query is skipped because some NT4 USB drivers really do not like unnecessary IOCTLs.

The USB-driver existance startup check is a simple warning I added just to let the user know that they're trying to use a USB formatting utility without USB drivers. It checks driver services and known files such as `usbd.sys`, `usbhub.sys`, `usbhid.sys`, `usbrm.sys`, `usbprint.sys` and `usbms.sys`. There are many different USB drivers for NT4 and the one I used during testing came from Dell. Usbd seems to be universal but I still decided to expand it a bit more.

Disk handling had to be changed in a few more places:

- `GetLogicalName()` and `GetDriveNumber()` have old-partition-information fallbacks
- `GetDrivePartitionData()` avoids the modern volume-label/file-system queries on NT4
- `NT4_HasSafePartitionTable()` rejects obviously broken MBR data before the old partition-layout IOCTL is used (highly necessary because it'd otherwise softlock Rufus-NT requiring a full OS restart)
- `W2K_SetLegacyDriveLayout()` converts Rufus' modern layout into the old structure understood by Windows 2000 and NT4
- GPT is staged as a writable MBR layout and finalized later by `FinalizeXpGpt()` through direct primary/backup GPT writes
- NT4 FAT32 always uses Rufus' Large FAT32 formatter (Rufus already has a custom writer for it, so its code was reused)
- NTFS and UEFI:NTFS share the same `FormatNative()` path and formatter I/O shim
- ext2/ext3 use the native physical-device backend and do not rely on Windows mounting the volume
- The final NTFS `chkdsk` pass are skipped

Syslinux was EXTREMELY problematic on NT4; `/src/ms-sys/file.c` and `/src/syslinux.c` were both edited to fix the 206 FAT32 formatter BSODs, as well as ldlinux.sys patching and lookup.<br>
NTFS partitioning for Syslinux has also been disabled there.

The NTFS shim is the ugliest looking part for a reason. `NT4_InstallFormatterIoShim()` patches the formatter modules' imported read/write functions and routes them through aligned, split I/O with proper pending-I/O waits. This is what keeps NT4's formatter and unstable USB drivers from receiving shit they cannot handle.

</details>

<details>
<summary><strong>3. Windows 2000 and Windows XP</strong></summary>
<br>

Windows 2000 mostly only needed missing APIs, old disk-layout structures and a few Common Controls v6 fixes. `win2k.c` supplies pointer encoding, module lookup, SList, heap, shell and system-information fallbacks. It also precomposes alpha icons and restores combo-box dropdown heights where the old controls mess them up.

`winxp.c` contains the XP-specific dynamic wrappers. The important ones include `XP_GetTickCount64()`, volume information, cancellation APIs, process paths, known folders and DLL-directory handling. `XP_GetTickCount64()` extends the 32-bit tick counter and tracks rollover instead of making progress reporting jump or disappear.

XP and older also use the manual GPT finalization path. The disk is temporarily exposed in a form the operating system can write, after which `FinalizeXpGpt()` writes the protective MBR, both partition arrays and both GPT headers.

The exFAT check happens before the regular destructive-operation warning. `CheckXpExFatSupport()` looks for `exfat.sys` and KB955704. When the update is missing, Rufus-NT offers the correct update for supported XP locales. XP x64 is limited to English and Japanese because those are the packages which actually exist. Declining the prompt returns straight to the UI without the operation ever starting.
The updates are sourced from [here.](https://archive.org/download/winxp-exfat-driver)

</details>

<details>
<summary><strong>4. Networking, TLS and Fido</strong></summary>
<br>

The 4.7 connection check was not enough for this project. Windows can report an active connection while Rufus itself is blocked by a firewall, proxy or broken TLS configuration. Windows even reports an inactive connection when in reality it's just connected to a VPN.

`NetworkStartupPreflight()` checks the WinINet connection state, the effective TLS 1.2 configuration and finally performs a small request to `https://rufus.ie/`. The result is cached for 30 seconds. If Windows claims to be online but the request fails, Rufus treats networking as unavailable and logs a short firewall warning. GRUB, Syslinux and diskcopy.dll then use their offline paths instead of showing the regular download prompt for something Rufus cannot actually reach.

Networking is disabled on XP and older at the public entry points, not only in the UI. `GetInternetSession()`, downloads, update checks, Fido and `IsDownloadable()` all reject these systems. Windows 7 and newer continue to use the system WinINet proxy configuration.

When TLS 1.2 is missing, `EnsureTLS12Enabled()` checks Group Policy and offers to enable the relevant HKCU, HKLM, Wow6432Node and SCHANNEL values. These changes are persistent. When Fido is ran on Windows 7, Rufus-NT temporarily selects "TLS 1.2 only" and restores the old value when it's closed.

The downloader itself was also updated. Long Microsoft URLs no longer overflow the old 128-character URL-path buffer, chunked responses work without `Content-Length`, in-memory downloads grow with overflow checks, and two terminating zero bytes are reserved for text callers. There was some work done with the taskbar progress bug, but it still isn't finished.

Fido is available on Windows 7 through PowerShell 7.2. The compressed script and detached signature are checked, the decompressed PowerShell script receives its Authenticode check, and the temporary-script replacement fix from newer Rufus was backported. The script gets a GUID filename and an ACL which prevents ordinary users from replacing it.

For Windows 7, Rufus-NT patches Fido's Windows-version line after validating the original script. This is intentional, but it also means the final executed bytes are no longer the exact Authenticode-signed bytes. The selected ISO URL comes back through a named pipe and the actual ISO is downloaded by Rufus.

Networking has been disabled for Windows Vista as well due to requiring too many things for too little benefit. Some changes and failed attempts can still be found in `net.c`.

The Fido availability thread also downloads current SBAT and Secure Boot certificate lists. If they are unavailable or invalid, the embedded lists from `db.h` are used.

</details>

<details>
<summary><strong>5. Windows To Go and offline bootloaders</strong></summary>
<br>

Anything older than Windows 8 can't mount WIM files. Windows 7 and older extract the selected index to %temp% instead.

- Retro7zip handles WIM file extraction (for ex. dbx checks)
- wimlib is the preferred image-apply and metadata backend below Windows 8 (well... there goes the non wimlib base)
- Windows 7's WIMGAPI remains as a fallback
- The embedded `bcdboot.exe` and `wimgapi.dll` use `ntapi.dll` [read more about it here](https://github.com/non4med-dev/rufus-nt/docs/bcdboot-wimgapi-ntapi.md)
- Windows 8+ uses native `bcdboot.exe` and `wimgapi.dll`

The regular build also embeds GRUB 2 `core.img` files, Grub4DOS `grldr` and Syslinux 6.04 `ldlinux.c32` due to the fact that networking is deliberately disabled on anything below Vista. It's done so that even offline all features are available. The noembed build keeps the regular download prompts and saves around 900kb of space. 

`diskcopy.dll` is not executed. `ExtractMSDOS()` reads it as data and accepts it only when both the exact size and SHA-256 match. The bytes which pass validation are the same bytes used to extract the MS-DOS image, which avoids the old validate-one-file/reopen-another-file problem. A valid `.dll` or Microsoft `.blob` can also be dragged onto the main window and installed into Rufus-NT's appdata directory.

</details>

<details>
<summary><strong>6. File systems, partitioning and Secure Boot</strong></summary>
<br>

`GetFsName()` now recognizes ext2, ext3 and ext4 directly from the superblock. This works even when Windows has no ext driver and cannot mount the volume. That detection doesn't seem to be working on NT4 and it's not crucial to functionality at all.

Large ext2/ext3 formats can be REALLY slow on some modern and large USB drives. Vista and newer therefore show a warning for drives that are 16GB or larger. I have made attempts to speed it up and optimize it but it really seems to be entirely USB-dependant. My USB 2.0 8GB cruzer blade took 1m to format as ext2. My USB 3.2 64GB intenso ultra line took 25 minutes.

FAT32, NTFS, UEFI:NTFS and bootsector writes all route through the compatible handle selected for the host. MS-DOS, FreeDOS, Syslinux, GRUB and ReactOS therefore use the same NT4 physical I/O path instead of patching every option one by one.

The Secure Boot (DBX) checks are half upstream and half custom code.

- DBX paths were updated to KEK2023 during the time Microsoft removed regular .bin files from their PostSigned objects [18ae93b](https://github.com/pbatard/rufus/commit/18ae93bf37f94764d77216cff4168e0549a14c4d)
- `GetPeSignatureData()` validates PE and certificate bounds before exposing the signature data
- Windows 2000/NT4 use a bounded raw DER parser as their crypt32 can't decode the CMS structure
- active/revoked certificate lists include both the 2011 and 2023 Microsoft authorities
- Windows UEFI CA 2023 media creation was backported, including the Windows 11 update flag and EFI loader replacement

</details>

<details>
<summary><strong>7. Diagnostics, UI and localization</strong></summary>
<br>
The NT4 diagnostics exist because that damn USB drivers crash the system before Rufus can even spit out what's wrong.

`NT4_SetDiskFunction()` stores the current larger operation in `LastDiskFunction`, `NT4_SetDiskStage()` stores numbered checkpoint in `LastDiskStage`. They're extremely useful for pinpointing which stage actually failed. Both are written under `HKCU\Software\Rufus-NT` and flushed. They survive a crash and are cleared only after a successful operation, therefore reopening Rufus by accident after a crash doesn't erase them.

A Diagnostics button was added to the Log window, and it writes three sections into a text report: 
- Rufus-NT's registry tree
- AppData filenames/sizes
- and the normal log.

The UI required a LOT of work. Buttons were overshadowed by invisible masks, icons didn't load, half the UI would disappear and dialogs wouldn't load. Most of the work should be in `stdlg.c`, `rufus.c` and `ui.c`. Lots of custom dialogs have been invented and some preexisting ones like the DBX popup had to be reworked. Tahoma is used as the applicationwide font on W2k and XP, whilst my pretty baby NT4 received MS Sans Serif and LOTS of ANSII compatibility fixes.

The `About Rufus` window was completely reworked, retro7zip wimlib, grub, grub4dos and syslinux were added to additional copyrights, localization has been added to `Additional Copyrights`, the Rufus and Rufus-NT changelogs were added there as well. The window is dynamically sized based on the longest string in the selected language and the font used. `Additional Copyrights` and `Changelogs appear` in a RICHEDIT SIDEBAR!!!! :D When its opened, the window centers itself, UNLESS it was moved by the user beforehand.

Rufus-NT-specific localization strings moved to the 500 source-ID block because the 300 block is reserved for strings backported from newer Rufus versions (for future updates).

Windows NT 4.0 doesn't support ASCII formatting for "MS Shell Dlg", or any other font for that sake, and therefore custom localization files had to be introduced for certain languages with special characters.<br>
Those languages are: Croatian, Czech, Latvian, Lithuanian, Polish, Romanian, Serbian, Slovak, Slovenian, and Vietnamese<br>
The custom fonts can be found in `/res/loc/po/NT4` with a `-NT4` suffix (ex. pl-PL -> pl-NT4)<br>
They work by turning special characters such as `ą` `ł` `š` `ă` `ệ` into regular ASCII letters `a` `l` `s` `a` `e`<br>
There are some little ASCII translators in the code itself like `NT4_SanitizeLogText` which simply translate non-ASCII characters into, well, ASCII compatible ones
Languages like Arabic, Greek, Hebrew, Persian had to be removed as they completely broke the UI.<br>
The only languages natively supported in NT4 are English, Danish, Dutch, Finnish, French, German, Hungarian, Indonesian, Italian, Malay, Norwegian, Portuguese (both), Spanish, Swedish and Turkish<br>
They are dynamically selected in `GetNT4Locale()` and are yet again behind a WindowsVersion.Version check<br>

All other languages were removed there. On Windows XP and 2000 only Arabic was removed.


</details>

<details>
<summary><strong>8. Windows User Experience</strong></summary>
<br>
The quality of life, windows user experience... Hello, beautiful

It was backported straight from source. Pretty much no changes have been made.<br>
Exact commits are labeled and can be found by simply searching
`// commit `

yey

</details>