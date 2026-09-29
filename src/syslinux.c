/* ----------------------------------------------------------------------- *
 *
 *   Copyright 2003 Lars Munch Christensen - All Rights Reserved
 *   Copyright 1998-2008 H. Peter Anvin - All Rights Reserved
 *   Copyright 2012-2024 Pete Batard
 *
 *   Based on the Linux installer program for SYSLINUX by H. Peter Anvin
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, Inc., 53 Temple Place Ste 330,
 *   Boston MA 02111-1307, USA; either version 2 of the License, or
 *   (at your option) any later version; incorporated herein by reference.
 *
 * ----------------------------------------------------------------------- */

 /* Memory leaks detection - define _CRTDBG_MAP_ALLOC as preprocessor macro */

// Regarding NT4, yey it works now

#ifdef _CRTDBG_MAP_ALLOC
#include <stdlib.h>
#include <crtdbg.h>
#endif

#include <windows.h>
#include <windowsx.h>
#include <stdio.h>
#include <malloc.h>
#include <ctype.h>

#include "rufus.h"
#include "winxp.h"
#include "missing.h"
#include "resource.h"
#include "msapi_utf8.h"
#include "localization.h"

#include "drive.h"

#include "syslinux.h"
#include "syslxfs.h"
#include "libfat.h"
#include "setadv.h"
#include "ntfssect.h"

unsigned char* syslinux_ldlinux[2] = { NULL, NULL };
unsigned long syslinux_ldlinux_len[2];
unsigned char* syslinux_mboot = NULL;
unsigned long syslinux_mboot_len;

/* Workaround for 4K support */
uint32_t SECTOR_SHIFT = 9;
uint32_t SECTOR_SIZE = 512;
uint32_t LIBFAT_SECTOR_SHIFT = 9;
uint32_t LIBFAT_SECTOR_SIZE = 512;
uint32_t LIBFAT_SECTOR_MASK = 511;

/*
 * Wrapper for ReadFile suitable for libfat
 */
int libfat_readfile(intptr_t pp, void* buf, size_t secsize, libfat_sector_t sector)
{
	LARGE_INTEGER offset;
	DWORD bytes_read;

	offset.QuadPart = (LONGLONG)sector * secsize;
	if (!SetFilePointerEx((HANDLE)pp, offset, NULL, FILE_BEGIN)) {
		uprintf("Could not set pointer to position %llu: %s", offset.QuadPart, WindowsErrorString());
		return 0;
	}

	if (!ReadFile((HANDLE)pp, buf, (DWORD)secsize, &bytes_read, NULL)) {
		uprintf("Could not read sector %llu: %s", sector, WindowsErrorString());
		return 0;
	}

	if (bytes_read != secsize) {
		uprintf("Sector %llu: Read %lu bytes instead of %zu requested", sector, bytes_read, secsize);
		return 0;
	}

	return (int)secsize;
}

#ifdef RUFUS_TARGET_NT4
typedef struct {
	HANDLE handle;
	uint64_t partition_offset;
} GPT_SYSLINUX_NT4_FAT_READER;

static HANDLE GPT_SyslinuxOpenNT4Volume(char drive_letter)
{
	HANDLE h = INVALID_HANDLE_VALUE;
	char volume_path[] = "\\\\.\\?:";
	int i;

	volume_path[4] = (char)toupper(drive_letter);

	// DOS Device enumeration
	for (i = 0; i < 4; i++) {
		h = CreateFileA(volume_path, GENERIC_READ | GENERIC_WRITE,
			FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING,
			FILE_ATTRIBUTE_NORMAL, NULL);
		if (h != INVALID_HANDLE_VALUE)
			break;
		if ((GetLastError() != ERROR_SHARING_VIOLATION) &&
			(GetLastError() != ERROR_ACCESS_DENIED))
			break;
		Sleep(50 * (i + 1));
	}

	if (h != INVALID_HANDLE_VALUE)
		uprintf("Opened %s for shared write access (NT4 Syslinux)", volume_path);
	return h;
}

static BOOL GPT_SyslinuxPhysicalVbrNT4(DWORD drive_index,
	uint64_t partition_offset, void* buffer, DWORD size, BOOL write)
{
	HANDLE h = INVALID_HANDLE_VALUE;
	LARGE_INTEGER pos;
	DWORD transferred = 0, error = ERROR_SUCCESS;
	BYTE* verify = NULL;
	BOOL r = FALSE;

	if ((buffer == NULL) || (size == 0) ||
		((size % SelectedDrive.SectorSize) != 0)) {
		SetLastError(ERROR_INVALID_PARAMETER);
		return FALSE;
	}

	// VBR I/O after patching and closing FastFAT
	// Dont reopen the raw volume, my fragile little NT4 cant handle that
	h = GetPhysicalHandle(drive_index, FALSE, write, TRUE);
	if ((h == INVALID_HANDLE_VALUE) || (h == NULL))
		return FALSE;

	pos.QuadPart = (LONGLONG)partition_offset;
	if (!SetFilePointerEx(h, pos, NULL, FILE_BEGIN)) {
		error = GetLastError();
		goto out;
	}

	if (!write) {
		if (!ReadFile(h, buffer, size, &transferred, NULL) ||
			(transferred != size)) {
			error = GetLastError();
			if ((transferred != size) && (error == ERROR_SUCCESS))
				error = ERROR_READ_FAULT;
			goto out;
		}
		r = TRUE;
		goto out;
	}

	// FlushFileBuffers() returns ERROR_INVALID_FUNCTION !!
	if (!WriteFile(h, buffer, size, &transferred, NULL) ||
		(transferred != size)) {
		error = GetLastError();
		if ((transferred != size) && (error == ERROR_SUCCESS))
			error = ERROR_WRITE_FAULT;
		goto out;
	}

	safe_closehandle(h);

	// Fallback to FlushFileBuffers, same shit all over again
	verify = (BYTE*)VirtualAlloc(NULL, size,
		MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (verify == NULL) {
		error = GetLastError();
		goto out;
	}

	h = GetPhysicalHandle(drive_index, FALSE, FALSE, TRUE);
	if ((h == INVALID_HANDLE_VALUE) || (h == NULL)) {
		error = GetLastError();
		goto out;
	}

	pos.QuadPart = (LONGLONG)partition_offset;
	transferred = 0;
	if (!SetFilePointerEx(h, pos, NULL, FILE_BEGIN) ||
		!ReadFile(h, verify, size, &transferred, NULL) ||
		(transferred != size)) {
		error = GetLastError();
		if ((transferred != size) && (error == ERROR_SUCCESS))
			error = ERROR_READ_FAULT;
		goto out;
	}

	if (memcmp(verify, buffer, size) != 0) {
		error = ERROR_WRITE_FAULT;
		uprintf("Syslinux VBR physical readback mismatch");
		goto out;
	}

	uprintf("Verified Syslinux boot record by physical readback");
	r = TRUE;

out:
	if (verify != NULL)
		VirtualFree(verify, 0, MEM_RELEASE);
	safe_closehandle(h);
	if (!r && (error != ERROR_SUCCESS))
		SetLastError(error);
	return r;
}

static int GPT_SyslinuxReadPhysicalFatNT4(intptr_t pp, void* buf,
	size_t secsize, libfat_sector_t sector)
{
	GPT_SYSLINUX_NT4_FAT_READER* reader =
		(GPT_SYSLINUX_NT4_FAT_READER*)pp;
	LARGE_INTEGER offset;
	DWORD bytes_read = 0;
	void* bounce = NULL;

	if ((reader == NULL) || (reader->handle == INVALID_HANDLE_VALUE) ||
		(buf == NULL) || (secsize == 0))
		return 0;

	// Read FAT thru physical disk and partition offset
	// Cached raw volume view causes NT4 to :freeze:
	offset.QuadPart = (LONGLONG)reader->partition_offset +
		((LONGLONG)sector * (LONGLONG)secsize);

	bounce = VirtualAlloc(NULL, secsize,
		MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (bounce == NULL)
		return 0;

	if (!SetFilePointerEx(reader->handle, offset, NULL, FILE_BEGIN) ||
		!ReadFile(reader->handle, bounce, (DWORD)secsize, &bytes_read, NULL) ||
		(bytes_read != secsize)) {
		VirtualFree(bounce, 0, MEM_RELEASE);
		return 0;
	}

	memcpy(buf, bounce, secsize);
	VirtualFree(bounce, 0, MEM_RELEASE);
	return (int)secsize;
}

static BOOL GPT_SyslinuxMapFatFileNT4(DWORD drive_index,
	uint64_t partition_offset, HANDLE volume_handle,
	libfat_sector_t* sectors, int wanted_sectors, int* mapped_sectors)
{
	GPT_SYSLINUX_NT4_FAT_READER reader;
	HANDLE physical = INVALID_HANDLE_VALUE;
	struct libfat_filesystem* fs = NULL;
	libfat_sector_t s;
	int32_t cluster;
	int attempt, nsectors;

	if ((sectors == NULL) || (mapped_sectors == NULL) ||
		(wanted_sectors <= 0))
		return FALSE;

	*mapped_sectors = 0;

	for (attempt = 0; attempt < 5; attempt++) {
		if ((volume_handle != INVALID_HANDLE_VALUE) &&
			(volume_handle != NULL) &&
			!FlushFileBuffers(volume_handle)) {
			uprintf("Warning: Volume flush before Syslinux mapping failed: %s",
				WindowsErrorString());
		}

		physical = GetPhysicalHandle(drive_index, FALSE, FALSE, TRUE);
		if ((physical == INVALID_HANDLE_VALUE) || (physical == NULL)) {
			uprintf("Could not open physical disk for Syslinux FAT mapping");
			return FALSE;
		}

		reader.handle = physical;
		reader.partition_offset = partition_offset;
		fs = libfat_open(GPT_SyslinuxReadPhysicalFatNT4, (intptr_t)&reader);
		if (fs == NULL) {
			safe_closehandle(physical);
			uprintf("Could not read FAT through the physical disk");
			return FALSE;
		}

		cluster = libfat_searchdir(fs, 0, "LDLINUX SYS", NULL);
		nsectors = 0;

		if (cluster > 0) {
			s = libfat_clustertosector(fs, cluster);
			while ((s != 0) && (s != (libfat_sector_t)-1) &&
				(nsectors < wanted_sectors)) {
				sectors[nsectors++] = s;
				s = libfat_nextsector(fs, s);
			}
		}

		libfat_close(fs);
		fs = NULL;
		safe_closehandle(physical);

		if ((cluster > 0) && (nsectors == wanted_sectors)) {
			*mapped_sectors = nsectors;
			uprintf("Mapped 'ldlinux.sys' from the physical FAT view (NT4)");
			return TRUE;
		}

		if (cluster <= 0)
			uprintf("NT4 physical FAT view does not contain 'ldlinux.sys' yet (attempt %d/5, libfat=%d)",
				attempt + 1, cluster);
		else
			uprintf("NT4 physical FAT map is incomplete (attempt %d/5: %d of %d sectors)",
				attempt + 1, nsectors, wanted_sectors);

		// Just in case
		if (attempt != 4)
			Sleep(100 << attempt);
	}

	return FALSE;
}
#endif

/*
 * Extract the ldlinux.sys and ldlinux.bss from resources,
 * then patch and install them
 */
BOOL InstallSyslinux(DWORD drive_index, char drive_letter, uint64_t partition_offset, int file_system)
{
	const LARGE_INTEGER liZero = { {0, 0} };
	HANDLE f_handle = INVALID_HANDLE_VALUE;
	HANDLE d_handle = INVALID_HANDLE_VALUE;
#ifdef RUFUS_TARGET_NT4
	BOOL nt4_virtual_sectbuf = FALSE;
#endif
	DWORD bytes_read, err, file_attributes;
#ifndef RUFUS_NO_EMBED
	DWORD ldlinux_c32_len;
#endif
	S_NTFSSECT_VOLINFO vol_info = { 0 };
	LARGE_INTEGER vcn, lba, len;
	S_NTFSSECT_EXTENT extent;
	BOOL r = FALSE, reopen_ldlinux = FALSE;
	FILE* fd;
	size_t length;

	static unsigned char* sectbuf = NULL;
#ifndef RUFUS_NO_EMBED
	unsigned char* ldlinux_c32 = NULL;
#endif
	static char* resource[2][2] = {
		{ MAKEINTRESOURCEA(IDR_SL_LDLINUX_V4_SYS), MAKEINTRESOURCEA(IDR_SL_LDLINUX_V4_BSS) },
		{ MAKEINTRESOURCEA(IDR_SL_LDLINUX_V6_SYS), MAKEINTRESOURCEA(IDR_SL_LDLINUX_V6_BSS) } };
	const char* ldlinux = "ldlinux";
	const char* syslinux = "syslinux";
	const char* ldlinux_ext[3] = { "sys", "bss", "c32" };
	const char* mboot_c32 = "mboot.c32";
	char path[MAX_PATH], tmp[64];
	const char* errmsg;
	struct libfat_filesystem* lf_fs = NULL;
	libfat_sector_t s, * secp;
	libfat_sector_t* sectors = NULL;
	int ldlinux_sectors;
	uint32_t ldlinux_cluster;
	int i, w, nsectors, sl_fs_stype;
	BOOL use_v5 = (boot_type == BT_SYSLINUX_V6) || ((boot_type == BT_IMAGE) && (SL_MAJOR(img_report.sl_version) >= 5));

	PrintInfoDebug(0, MSG_234, (boot_type == BT_IMAGE) ? img_report.sl_version_str : embedded_sl_version_str[use_v5 ? 1 : 0]);

#ifdef RUFUS_TARGET_NT4
	// No NTFS for Syslinux
	if ((WindowsVersion.Version <= WINDOWS_NT4) && (file_system == FS_NTFS)) {
		SetLastError(ERROR_NOT_SUPPORTED);
		goto out;
	}
#endif

	/* 4K sector size workaround */
	SECTOR_SHIFT = 0;
	SECTOR_SIZE = SelectedDrive.SectorSize;
	while (SECTOR_SIZE >>= 1)
		SECTOR_SHIFT++;
	SECTOR_SIZE = SelectedDrive.SectorSize;
	LIBFAT_SECTOR_SHIFT = SECTOR_SHIFT;
	LIBFAT_SECTOR_SIZE = SECTOR_SIZE;
	LIBFAT_SECTOR_MASK = SECTOR_SIZE - 1;

	/* sectbuf should be aligned to at least 8 bytes - see github #767 */
#ifdef RUFUS_TARGET_NT4
	if (WindowsVersion.Version <= WINDOWS_NT4) {
		sectbuf = (unsigned char*)VirtualAlloc(NULL, SECTOR_SIZE,
			MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
		nt4_virtual_sectbuf = (sectbuf != NULL);
	}
	else
#endif
		sectbuf = _mm_malloc(SECTOR_SIZE, 16);
	if (sectbuf == NULL)
		goto out;

	/*
	 * First, reopen the volume (we already have a lock). Also, for some
	 * weird reason.the Syslinux install process *MUST* have FILE_SHARE_WRITE
	 * on the volume, or else creating 'ldlinux.sys' will fail...
	 */
#ifdef RUFUS_TARGET_NT4
	if (WindowsVersion.Version <= WINDOWS_NT4)
		d_handle = GPT_SyslinuxOpenNT4Volume(drive_letter);
	else
#endif
		d_handle = GetLogicalHandle(drive_index, 0, FALSE, TRUE, TRUE);
	if ((d_handle == INVALID_HANDLE_VALUE) || (d_handle == NULL)) {
		uprintf("Could not open volume for Syslinux installation: %s", WindowsErrorString());
		goto out;
	}

	/* Make sure we can read the boot sector (NB: Re-open already set us to offset 0) */
	if (!ReadFile(d_handle, sectbuf, SECTOR_SIZE, &bytes_read, NULL)) {
		uprintf("Could not read VBR");
		goto out;
	}
	if (bytes_read != SECTOR_SIZE) {
		uprintf("Could not read the whole VBR");
		goto out;
	}
	if ((errmsg = syslinux_check_bootsect(sectbuf, &sl_fs_stype))) {
		uprintf("Error: %s", errmsg);
		goto out;
	}

#ifdef RUFUS_TARGET_NT4
	if (WindowsVersion.Version <= WINDOWS_NT4) {
		// Close volume handle before FastFAT is invoked, else brrr frrrreeeze
		safe_closehandle(d_handle);
	}
#endif

	/* Initialize the ADV -- this should be smarter */
	syslinux_reset_adv(syslinux_adv);

	/* Access a copy of the ldlinux.sys & ldlinux.bss resources (downloaded or embedded) */
	if ((syslinux_ldlinux_len[0] != 0) && (syslinux_ldlinux_len[1] != 0)) {
		IGNORE_RETVAL(_chdirU(app_data_dir));
		for (i = 0; i < 2; i++) {
			syslinux_ldlinux[i] = (unsigned char*)malloc(syslinux_ldlinux_len[i]);
			if (syslinux_ldlinux[i] == NULL)
				goto out;
			static_sprintf(path, "%s\\%s-%s%s\\%s.%s", FILES_DIR, syslinux, img_report.sl_version_str,
				img_report.sl_version_ext, ldlinux, i == 0 ? "sys" : "bss");
			fd = fopen(path, "rb");
			if (fd == NULL) {
				uprintf("Could not open %s\\%s", app_data_dir, path);
				goto out;
			}
			length = fread(syslinux_ldlinux[i], 1, (size_t)syslinux_ldlinux_len[i], fd);
			fclose(fd);
			if (length != (size_t)syslinux_ldlinux_len[i]) {
				uprintf("Could not read %s\\%s", app_data_dir, path);
				goto out;
			}
			uprintf("Using existing '%s\\%s' %s", app_data_dir, path,
				IsBufferInDB(syslinux_ldlinux[i], (size_t)syslinux_ldlinux_len[i]) ? "✓" : "✗");
		}
	}
	else {
		for (i = 0; i < 2; i++) {
			static_sprintf(tmp, "%s.%s", ldlinux, ldlinux_ext[i]);
			syslinux_ldlinux_len[i] = 0;
			syslinux_ldlinux[i] = GetResource(hMainInstance, resource[use_v5 ? 1 : 0][i],
				_RT_RCDATA, tmp, &syslinux_ldlinux_len[i], TRUE);
			if (syslinux_ldlinux[i] == NULL)
				goto out;
		}
	}

	/* Create ldlinux.sys file */
	static_sprintf(path, "%c:\\%s.%s", toupper(drive_letter), ldlinux, ldlinux_ext[0]);
	reopen_ldlinux = (WindowsVersion.Version <= WINDOWS_NT4) && (file_system != FS_NTFS);
#ifdef RUFUS_TARGET_NT4
	if (WindowsVersion.Version <= WINDOWS_NT4) {
		DWORD old_attributes = GetFileAttributesA(path);
		if (old_attributes != INVALID_FILE_ATTRIBUTES) {
			// Clear attributes before writing, else it will fail with 0x5
			uprintf("Removing existing '%s' before Syslinux installation", &path[3]);
			if (!SetFileAttributesA(path, FILE_ATTRIBUTE_NORMAL)) {
				uprintf("Could not clear attributes on existing '%s': %s",
					&path[3], WindowsErrorString());
				goto out;
			}
			if (!DeleteFileA(path)) {
				uprintf("Could not remove existing '%s': %s",
					&path[3], WindowsErrorString());
				goto out;
			}
			if (GetFileAttributesA(path) != INVALID_FILE_ATTRIBUTES) {
				uprintf("Existing '%s' is still present after deletion", &path[3]);
				SetLastError(ERROR_ACCESS_DENIED);
				goto out;
			}
		}
	}
#endif
	file_attributes = FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN;
	if (!reopen_ldlinux)
		file_attributes |= FILE_ATTRIBUTE_READONLY;
#ifdef RUFUS_TARGET_NT4
	if (WindowsVersion.Version <= WINDOWS_NT4) {
		// Its the safest it gets
		file_attributes |= FILE_FLAG_WRITE_THROUGH;
	}
#endif
	f_handle = CreateFileA(path, GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL, CREATE_ALWAYS, file_attributes, NULL);

	if (f_handle == INVALID_HANDLE_VALUE) {
		uprintf("Unable to create '%s': %s", &path[3], WindowsErrorString());
		goto out;
	}

#ifdef RUFUS_TARGET_NT4
	if (WindowsVersion.Version <= WINDOWS_NT4) {
		LARGE_INTEGER final_size;
		final_size.QuadPart = (LONGLONG)syslinux_ldlinux_len[0] + (2 * ADV_SIZE);

		// Preallocate file length before writing anything
		// FAT fucking sucks in here
		if (!SetFilePointerEx(f_handle, final_size, NULL, FILE_BEGIN) ||
			!SetEndOfFile(f_handle) || !FlushFileBuffers(f_handle) ||
			!SetFilePointerEx(f_handle, liZero, NULL, FILE_BEGIN)) {
			uprintf("Could not preallocate '%s': %s", &path[3], WindowsErrorString());
			goto out;
		}
	}
#endif

	/* Write ldlinux.sys file */
	if (!WriteFileWithRetry(f_handle, (const char _force*)syslinux_ldlinux[0],
		syslinux_ldlinux_len[0], NULL, WRITE_RETRIES)) {
		uprintf("Could not write '%s': %s", &path[3], WindowsErrorString());
		goto out;
	}
	if (!WriteFileWithRetry(f_handle, syslinux_adv, 2 * ADV_SIZE, NULL, WRITE_RETRIES)) {
		uprintf("Could not write ADV to '%s': %s", &path[3], WindowsErrorString());
		goto out;
	}

	uprintf("Successfully wrote '%s'", &path[3]);
	if (boot_type != BT_IMAGE)
		UpdateProgress(OP_FILE_COPY, -1.0f);

	/* Now flush the media */
	if (!FlushFileBuffers(f_handle)) {
		uprintf("FlushFileBuffers failed");
		goto out;
	}
	if (reopen_ldlinux) {
		safe_closehandle(f_handle);
	}

#ifdef RUFUS_TARGET_NT4
	if (WindowsVersion.Version <= WINDOWS_NT4) {
		LARGE_INTEGER committed_size;
		LONGLONG expected_size =
			(LONGLONG)syslinux_ldlinux_len[0] + (2 * ADV_SIZE);

		// Verify before touching anything

		f_handle = CreateFileA(path, GENERIC_READ,
			FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING,
			FILE_ATTRIBUTE_NORMAL, NULL);
		if ((f_handle == INVALID_HANDLE_VALUE) ||
			!GetFileSizeEx(f_handle, &committed_size) ||
			(committed_size.QuadPart != expected_size)) {
			uprintf("FastFAT did not commit the expected 'ldlinux.sys' size (NT4)");
			safe_closehandle(f_handle);
			goto out;
		}
		safe_closehandle(f_handle);
		uprintf("Verified 'ldlinux.sys' through FastFAT (%lld bytes) (NT4)",
			expected_size);

		// Dismounting an unfinished volume will make it unmountable on NT4
		// Thats one of the thousand examples why I call it fragile

		d_handle = GPT_SyslinuxOpenNT4Volume(drive_letter);
		if ((d_handle == INVALID_HANDLE_VALUE) || (d_handle == NULL)) {
			uprintf("Could not reopen volume after creating 'ldlinux.sys' (NT4): %s",
				WindowsErrorString());
			goto out;
		}
		if (!FlushFileBuffers(d_handle))
			uprintf("Warning: volume flush after creating 'ldlinux.sys' failed (NT4): %s",
				WindowsErrorString());
	}
#endif

	/* Map the file (is there a better way to do this?) */
	ldlinux_sectors = (syslinux_ldlinux_len[0] + 2 * ADV_SIZE + SECTOR_SIZE - 1) >> SECTOR_SHIFT;
	sectors = (libfat_sector_t*)calloc(ldlinux_sectors, sizeof * sectors);
	if (sectors == NULL)
		goto out;
	nsectors = 0;

	switch (file_system) {
	case FS_NTFS:
		static_sprintf(tmp, "%c:\\", toupper(drive_letter));
		vol_info.Handle = d_handle;
		err = NtfsSectGetVolumeInfo(tmp, &vol_info);
		if (err != ERROR_SUCCESS) {
			uprintf("Could not fetch NTFS volume info");
			goto out;
		}
		secp = sectors;
		nsectors = 0;
		for (vcn.QuadPart = 0;
			NtfsSectGetFileVcnExtent(f_handle, &vcn, &extent) == ERROR_SUCCESS;
			vcn = extent.NextVcn) {
			err = NtfsSectLcnToLba(&vol_info, &extent.FirstLcn, &lba);
			if (err != ERROR_SUCCESS) {
				uprintf("Could not translate 'ldlinux.sys' LCN to disk LBA");
				goto out;
			}
			lba.QuadPart -= vol_info.PartitionLba.QuadPart;
			len.QuadPart = ((extent.NextVcn.QuadPart -
				extent.FirstVcn.QuadPart) *
				vol_info.SectorsPerCluster);
			while (len.QuadPart-- && nsectors < ldlinux_sectors) {
				*secp++ = lba.QuadPart++;
				nsectors++;
			}
		}
		break;
	case FS_FAT16:
	case FS_FAT32:
	case FS_EXFAT:
#ifdef RUFUS_TARGET_NT4
		if (WindowsVersion.Version <= WINDOWS_NT4) {

			// Verify through a fresh physical disk view at the partition offset
			// Should avoid the stale view NT4 somehow creates
			if (!GPT_SyslinuxMapFatFileNT4(drive_index, partition_offset,
				d_handle, sectors, ldlinux_sectors, &nsectors)) {
				uprintf("Could not map 'ldlinux.sys' from committed FAT metadata (NT4)");
				goto out;
			}
			break;
		}
#endif
		lf_fs = libfat_open(libfat_readfile, (intptr_t)d_handle);
		if (lf_fs == NULL) {
			uprintf("Syslinux FAT access error");
			goto out;
		}
		ldlinux_cluster = libfat_searchdir(lf_fs, 0, "LDLINUX SYS", NULL);
		if ((int32_t)ldlinux_cluster <= 0) {
			uprintf("Could not locate 'ldlinux.sys' in the FAT directory (libfat=%d)",
				(int32_t)ldlinux_cluster);
			libfat_close(lf_fs);
			lf_fs = NULL;
			goto out;
		}
		secp = sectors;
		s = libfat_clustertosector(lf_fs, ldlinux_cluster);
		while ((s != 0) && (s != (libfat_sector_t)-1) &&
			(nsectors < ldlinux_sectors)) {
			*secp++ = s;
			nsectors++;
			s = libfat_nextsector(lf_fs, s);
		}
		libfat_close(lf_fs);
		lf_fs = NULL;
		if (nsectors != ldlinux_sectors) {
			uprintf("Incomplete Syslinux FAT mapping: mapped %d of %d sectors",
				nsectors, ldlinux_sectors);
			goto out;
		}
		break;
	default:
		uprintf("Unsupported Syslinux filesystem");
		goto out;
	}

#ifdef RUFUS_TARGET_NT4
	if (WindowsVersion.Version <= WINDOWS_NT4) {
		// Close handle before FAT verification, else BRRR CRASHHH
		uprintf("Closing NT4 logical volume after verified FAT mapping");
		safe_closehandle(d_handle);
	}
	if ((WindowsVersion.Version <= WINDOWS_NT4) && (boot_type != BT_IMAGE)) {
		// Just so it doesnt look stuck, it normally takes about a minute with no UI indication whatsoever
		UpdateProgress(OP_FILE_COPY, -1.0f);
	}
#endif

	/* Set the base directory and patch ldlinux.sys and the boot sector */
	for (i = (int)strlen(img_report.cfg_path); (i > 0) && (img_report.cfg_path[i] != '/'); i--);
	if (i > 0)
		img_report.cfg_path[i] = 0;
#ifdef RUFUS_TARGET_NT4
	if (WindowsVersion.Version <= WINDOWS_NT4)
		uprintf("Patching 'ldlinux.sys' using %d verified sectors (NT4)", nsectors);
#endif
	w = syslinux_patch(sectors, nsectors, 0, 0, img_report.cfg_path, NULL);
	if (i > 0)
		img_report.cfg_path[i] = '/';
	if (w < 0) {
		uprintf("Could not patch Syslinux files (mapped %d of %d sectors)", nsectors, ldlinux_sectors);
		goto out;
	}

	/* Rewrite the file */
	if (reopen_ldlinux) {
		DWORD reopen_flags = FILE_ATTRIBUTE_NORMAL;
#ifdef RUFUS_TARGET_NT4
		if (WindowsVersion.Version <= WINDOWS_NT4)
			reopen_flags |= FILE_FLAG_WRITE_THROUGH;
#endif
		f_handle = CreateFileA(path, GENERIC_READ | GENERIC_WRITE,
			FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, reopen_flags, NULL);
		if (f_handle == INVALID_HANDLE_VALUE) {
			uprintf("Could not reopen '%s': %s", &path[3], WindowsErrorString());
			goto out;
		}
	}
#ifdef RUFUS_TARGET_NT4
	if (WindowsVersion.Version <= WINDOWS_NT4) {
		DWORD nt4_written = 0;

		// ONE (1) synchronous write
		uprintf("Rewriting patched 'ldlinux.sys' through FastFAT (NT4)");
		if (!SetFilePointerEx(f_handle, liZero, NULL, FILE_BEGIN) ||
			!WriteFile(f_handle, syslinux_ldlinux[0],
				syslinux_ldlinux_len[0], &nt4_written, NULL) ||
			(nt4_written != syslinux_ldlinux_len[0])) {
			uprintf("Could not rewrite '%s': %s", &path[3], WindowsErrorString());
			goto out;
		}
		if (!FlushFileBuffers(f_handle)) {
			uprintf("Could not flush patched '%s': %s",
				&path[3], WindowsErrorString());
			goto out;
		}
		uprintf("Flushed patched 'ldlinux.sys' through FastFAT (NT4)");
		if (boot_type != BT_IMAGE)
			UpdateProgress(OP_FILE_COPY, -1.0f);
	}
	else
#endif
	{
		if (!SetFilePointerEx(f_handle, liZero, NULL, FILE_BEGIN) ||
			!WriteFileWithRetry(f_handle, syslinux_ldlinux[0],
				syslinux_ldlinux_len[0], NULL, WRITE_RETRIES)) {
			uprintf("Could not rewrite '%s': %s\n", &path[3], WindowsErrorString());
			goto out;
		}
	}

	/* Close file */
	safe_closehandle(f_handle);
#ifdef RUFUS_TARGET_NT4
	if (WindowsVersion.Version <= WINDOWS_NT4)
		uprintf("Closed patched 'ldlinux.sys' before VBR I/O (NT4)");
#endif

	if (reopen_ldlinux)
		SetFileAttributesA(path, FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN);

	/* Read existing FAT data into boot sector */
#ifdef RUFUS_TARGET_NT4
	if (WindowsVersion.Version <= WINDOWS_NT4) {
		uprintf("Reading Syslinux boot record through physical disk (NT4)");
		if (!GPT_SyslinuxPhysicalVbrNT4(drive_index, partition_offset,
			sectbuf, SECTOR_SIZE, FALSE)) {
			uprintf("Could not read Syslinux boot record from physical disk: %s",
				WindowsErrorString());
			goto out;
		}
	}
	else
#endif
	{
		if (!SetFilePointerEx(d_handle, liZero, NULL, FILE_BEGIN) ||
			!ReadFile(d_handle, sectbuf, SECTOR_SIZE,
				&bytes_read, NULL)) {
			uprintf("Could not read Syslinux boot record: %s", WindowsErrorString());
			goto out;
		}
		if (bytes_read < SECTOR_SIZE) {
			uprintf("Partial read of Syslinux boot record: read %d bytes but requested %d",
				bytes_read, SECTOR_SIZE);
			goto out;
		}
	}

	/* Make the syslinux boot sector */
	syslinux_make_bootsect(sectbuf, (file_system == FS_NTFS) ? NTFS : VFAT);

	/* Write boot sector back */
#ifdef RUFUS_TARGET_NT4
	if (WindowsVersion.Version <= WINDOWS_NT4) {
		uprintf("Writing Syslinux boot record through physical disk (NT4)");
		if (!GPT_SyslinuxPhysicalVbrNT4(drive_index, partition_offset,
			sectbuf, SECTOR_SIZE, TRUE)) {
			uprintf("Could not write Syslinux boot record through physical disk: %s",
				WindowsErrorString());
			goto out;
		}
	}
	else
#endif
		if (!SetFilePointerEx(d_handle, liZero, NULL, FILE_BEGIN) ||
			!WriteFileWithRetry(d_handle, sectbuf, SECTOR_SIZE, NULL, WRITE_RETRIES)) {
			uprintf("Could not write Syslinux boot record: %s", WindowsErrorString());
			goto out;
		}

	uprintf("Successfully wrote Syslinux boot record");
#ifdef RUFUS_TARGET_NT4
	if ((WindowsVersion.Version <= WINDOWS_NT4) && (boot_type != BT_IMAGE))
		UpdateProgress(OP_FILE_COPY, -1.0f);
#endif

	if (boot_type == BT_SYSLINUX_V6) {
#ifdef RUFUS_NO_EMBED
		IGNORE_RETVAL(_chdirU(app_data_dir));
		static_sprintf(path, "%s\\%s-%s", FILES_DIR, syslinux, embedded_sl_version_str[1]);
		IGNORE_RETVAL(_chdir(path));
		static_sprintf(path, "%c:\\%s.%s", toupper(drive_letter), ldlinux, ldlinux_ext[2]);
		fd = fopen(&path[3], "rb");
		if (fd == NULL) {
			uprintf("Caution: No '%s' was provided. The target will be missing a required Syslinux file!", &path[3]);
		}
		else {
			fclose(fd);
			if (CopyFileU(&path[3], path, TRUE)) {
				uprintf("Created '%s' (from '%s\\%s\\%s-%s\\%s') %s", path, app_data_dir, FILES_DIR,
					syslinux, embedded_sl_version_str[1], &path[3], IsFileInDB(&path[3]) ? "✓" : "✗");
			}
			else {
				uprintf("Failed to create '%s': %s", path, WindowsErrorString());
			}
		}
#else
		static_sprintf(path, "%c:\\%s.%s", toupper(drive_letter), ldlinux, ldlinux_ext[2]);
		ldlinux_c32 = GetResource(hMainInstance, MAKEINTRESOURCEA(IDR_SL_LDLINUX_C32),
			_RT_RCDATA, &path[3], &ldlinux_c32_len, FALSE);
		if (ldlinux_c32 == NULL) {
			uprintf("Could not access embedded '%s'", &path[3]);
			goto out;
		}
		f_handle = CreateFileA(path, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ,
			NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
		if ((f_handle == INVALID_HANDLE_VALUE) ||
			!WriteFileWithRetry(f_handle, ldlinux_c32, ldlinux_c32_len, NULL, WRITE_RETRIES)) {
			uprintf("Failed to create '%s': %s", path, WindowsErrorString());
		}
		else {
			uprintf("Created '%s' (from embedded resource) %s", path,
				IsBufferInDB(ldlinux_c32, ldlinux_c32_len) ? "✓" : "✗");
		}
		safe_closehandle(f_handle);
#endif
	}
	else if (HAS_REACTOS(img_report)) {
		uprintf("Setting up ReactOS...");
		syslinux_mboot = GetResource(hMainInstance, MAKEINTRESOURCEA(IDR_SL_MBOOT_C32),
			_RT_RCDATA, "mboot.c32", &syslinux_mboot_len, FALSE);
		if (syslinux_mboot == NULL) {
			goto out;
		}
		/* Create mboot.c32 file */
		static_sprintf(path, "%c:\\%s", toupper(drive_letter), mboot_c32);
		f_handle = CreateFileA(path, GENERIC_READ | GENERIC_WRITE,
			FILE_SHARE_READ | FILE_SHARE_WRITE,
			NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
		if (f_handle == INVALID_HANDLE_VALUE) {
			uprintf("Unable to create '%s'\n", path);
			goto out;
		}
		if (!WriteFileWithRetry(f_handle, syslinux_mboot, syslinux_mboot_len, NULL, WRITE_RETRIES)) {
			uprintf("Could not write '%s'", path);
			goto out;
		}
		safe_closehandle(f_handle);
		static_sprintf(path, "%c:\\syslinux.cfg", toupper(drive_letter));
		fd = fopen(path, "w");
		if (fd == NULL) {
			uprintf("Could not create ReactOS 'syslinux.cfg'");
			goto out;
		}
		/* Write the syslinux.cfg for ReactOS */
		fprintf(fd, "DEFAULT ReactOS\nLABEL ReactOS\n  KERNEL %s\n  APPEND %s",
			mboot_c32, img_report.reactos_path);
		fclose(fd);
	}

	if (boot_type != BT_IMAGE)
		UpdateProgress(OP_FILE_COPY, -1.0f);

	r = TRUE;

out:
	if (lf_fs != NULL)
		libfat_close(lf_fs);
#ifdef RUFUS_TARGET_NT4
	if (nt4_virtual_sectbuf) {
		if (sectbuf != NULL)
			VirtualFree(sectbuf, 0, MEM_RELEASE);
		sectbuf = NULL;
	}
	else
#endif
		safe_mm_free(sectbuf);
	safe_free(syslinux_ldlinux[0]);
	safe_free(syslinux_ldlinux[1]);
	safe_free(sectors);
#ifdef RUFUS_TARGET_NT4
	if (WindowsVersion.Version <= WINDOWS_NT4) {
		// Close and dont unlock, Im not playing around with this shit anymore
		safe_closehandle(d_handle);
	}
	else
#endif
		safe_unlockclose(d_handle);
	safe_closehandle(f_handle);
	return r;
}

uint16_t GetSyslinuxVersion(char* buf, size_t buf_size, char** ext)
{
	size_t i, j, k;
	char* p;
	uint16_t version;
	const char LINUX[] = { 'L', 'I', 'N', 'U', 'X', ' ' };
	static char* nullstr = "";
	char unauthorized[] = { '<', '>', ':', '|', '*', '?', '\\', '/' };

	*ext = nullstr;
	if (buf_size < 256)
		return 0;

	// Start at 64 to avoid the short incomplete version at the beginning of ldlinux.sys
	for (i = 64; i < buf_size - 64; i++) {
		if (memcmp(&buf[i], LINUX, sizeof(LINUX)) == 0) {
			// Check for ISO or SYS prefix
			if (!(((buf[i - 3] == 'I') && (buf[i - 2] == 'S') && (buf[i - 1] == 'O'))
				|| ((buf[i - 3] == 'S') && (buf[i - 2] == 'Y') && (buf[i - 1] == 'S'))))
				continue;
			i += sizeof(LINUX);
			version = (((uint8_t)strtoul(&buf[i], &p, 10)) << 8) + (uint8_t)strtoul(&p[1], &p, 10);
			// Our buffer is either from our internal legit syslinux (i.e. with a NUL terminated
			// version string) or from a buffer that has been NUL-terminated through read_file(),
			// so the string we work with in p is always NUL terminated at this stage.
			if (version == 0)
				continue;
			// Ensure that our extra version string starts with a slash
			*p = '/';
			// Remove the x.yz- duplicate if present
			for (j = 0; (buf[i + j] == p[1 + j]) && (buf[i + j] != ' '); j++);
			if (p[j + 1] == '-')
				j++;
			if (j >= 4) {
				p[j] = '/';
				p = &p[j];
			}
			for (j = safe_strlen(p) - 1; j > 0; j--) {
				// Arch Linux affixes a star for their version - who knows what else is out there...
				if ((p[j] == ' ') || (p[j] == '*'))
					p[j] = 0;
				else
					break;
			}
			// Sanitize the string
			for (j = 1; j < safe_strlen(p); j++) {
				// Some people are bound to have invalid chars in their date strings
				for (k = 0; k < sizeof(unauthorized); k++) {
					if (p[j] == unauthorized[k])
						p[j] = '_';
				}
			}
			// If all we have is a slash, return the empty string for the extra version
			*ext = (p[1] == 0) ? nullstr : p;
			return version;
		}
	}
	return 0;
}
