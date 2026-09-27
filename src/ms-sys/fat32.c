/******************************************************************
    Copyright (C) 2009  Henrik Carlqvist

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
******************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "file.h"
#include "fat32.h"
#ifdef RUFUS_TARGET_NT4
#include "../nt4.h"
#endif

int is_fat_32_fs(FILE *fp)
{
   char *szMagic = "FAT32   ";

   return contains_data(fp, 0x52, szMagic, strlen(szMagic));
} /* is_fat_32_fs */

int is_fat_32_br(FILE *fp)
{
   /* A "file" is probably some kind of FAT32 boot record if it contains the
      magic chars 0x55, 0xAA at positions 0x1FE, 0x3FE and 0x5FE */
   unsigned char aucRef[] = {0x55, 0xAA};
   unsigned char aucMagic[] = {'M','S','W','I','N','4','.','1'};
   int i;

   for(i=0 ; i<3 ; i++)
      if( ! contains_data(fp, 0x1FEULL + i * 0x200ULL, aucRef, sizeof(aucRef)))
	 return 0;
   if( ! contains_data(fp, 0x03, aucMagic, sizeof(aucMagic)))
      return 0;
   return 1;
} /* is_fat_32_br */

int entire_fat_32_br_matches(FILE *fp)
{
   #include "br_fat32_0x0.h"
   #include "br_fat32_0x52.h"
   #include "br_fat32_0x3f0.h"

   return
      ( contains_data(fp, 0x0, br_fat32_0x0, sizeof(br_fat32_0x0)) &&
	/* BIOS Parameter Block might differ between systems */
	contains_data(fp, 0x52, br_fat32_0x52, sizeof(br_fat32_0x52)) &&
	/* Cluster information might differ between systems */
	contains_data(fp, 0x3f0, br_fat32_0x3f0, sizeof(br_fat32_0x3f0)) );
} /* entire_fat_32_br_matches */

int write_fat_32_br(FILE *fp, int bKeepLabel)
{
   #include "label_11_char.h"
   #include "br_fat32_0x0.h"
   #include "br_fat32_0x52.h"
   #include "br_fat32_0x3f0.h"

   if(bKeepLabel)
      return
	 ( write_data(fp, 0x0, br_fat32_0x0, sizeof(br_fat32_0x0)) &&
	   /* BIOS Parameter Block should not be overwritten */
	   write_data(fp, 0x52, br_fat32_0x52, sizeof(br_fat32_0x52)) &&
	   /* Cluster information is not overwritten, however, it would be OK
	      to write 0xff 0xff 0xff 0xff 0xff 0xff 0xff 0xff here. */
	   write_data(fp, 0x3f0, br_fat32_0x3f0, sizeof(br_fat32_0x3f0)) );
   else
      return
	 ( write_data(fp, 0x0, br_fat32_0x0, sizeof(br_fat32_0x0)) &&
	   /* BIOS Parameter Block should not be overwritten */
	   write_data(fp, 0x47, label_11_char, sizeof(label_11_char)) &&
	   write_data(fp, 0x52, br_fat32_0x52, sizeof(br_fat32_0x52)) &&
	   /* Cluster information is not overwritten, however, it would be OK
	      to write 0xff 0xff 0xff 0xff 0xff 0xff 0xff 0xff here. */
	   write_data(fp, 0x3f0, br_fat32_0x3f0, sizeof(br_fat32_0x3f0)) );
} /* write_fat_32_br */

int entire_fat_32_fd_br_matches(FILE *fp)
{
   #include "br_fat32_0x0.h"
   #include "br_fat32fd_0x52.h"
   #include "br_fat32fd_0x3f0.h"

   return
      ( contains_data(fp, 0x0, br_fat32_0x0, sizeof(br_fat32_0x0)) &&
	/* BIOS Parameter Block might differ between systems */
	contains_data(fp, 0x52, br_fat32_0x52, sizeof(br_fat32_0x52)) &&
	/* Cluster information might differ between systems */
	contains_data(fp, 0x3f0, br_fat32_0x3f0, sizeof(br_fat32_0x3f0)) );
} /* entire_fat_32_fd_br_matches */

int write_fat_32_fd_br(FILE *fp, int bKeepLabel)
{
   #include "label_11_char.h"
   #include "br_fat32_0x0.h"
   #include "br_fat32fd_0x52.h"
   #include "br_fat32fd_0x3f0.h"

   if(bKeepLabel)
      return
	 ( write_data(fp, 0x0, br_fat32_0x0, sizeof(br_fat32_0x0)) &&
	   /* BIOS Parameter Block should not be overwritten */
	   write_data(fp, 0x52, br_fat32_0x52, sizeof(br_fat32_0x52)) &&
	   /* Cluster information is not overwritten, however, it would be OK
	      to write 0xff 0xff 0xff 0xff 0xff 0xff 0xff 0xff here. */
	   write_data(fp, 0x3f0, br_fat32_0x3f0, sizeof(br_fat32_0x3f0)) );
   else
      return
	 ( write_data(fp, 0x0, br_fat32_0x0, sizeof(br_fat32_0x0)) &&
	   /* BIOS Parameter Block should not be overwritten */
	   write_data(fp, 0x47, label_11_char, sizeof(label_11_char)) &&
	   write_data(fp, 0x52, br_fat32_0x52, sizeof(br_fat32_0x52)) &&
	   /* Cluster information is not overwritten, however, it would be OK
	      to write 0xff 0xff 0xff 0xff 0xff 0xff 0xff 0xff here. */
	   write_data(fp, 0x3f0, br_fat32_0x3f0, sizeof(br_fat32_0x3f0)) );
} /* write_fat_32_fd_br */

static int write_fat_32_nt4_data(FILE *fp, const unsigned char *boot_code,
	 size_t boot_code_len, const unsigned char *cluster_code, size_t cluster_code_len,
	 int secondary)
{
   #include "label_11_char.h"
   #include "br_fat32_0x0.h"

	int r = 0;
	size_t len = 0x3f0 + cluster_code_len;
	unsigned char *buf = (unsigned char*)malloc(len);
#ifndef RUFUS_TARGET_NT4
	(void)secondary;
#endif

	if (buf == NULL)
		return 0;
#ifdef RUFUS_TARGET_NT4
	NT4_SetDiskStage(secondary ? "124 preparing secondary FAT32 boot sector" :
		"123 preparing primary FAT32 boot sector");
#endif
	if (!read_data(fp, 0, buf, len))
		goto out;
   memcpy(&buf[0x0], br_fat32_0x0, sizeof(br_fat32_0x0));
   memcpy(&buf[0x47], label_11_char, sizeof(label_11_char));
   buf[0x40] = 0x80;
   memcpy(&buf[0x52], boot_code, boot_code_len);
   memcpy(&buf[0x3f0], cluster_code, cluster_code_len);
#ifdef RUFUS_TARGET_NT4
	NT4_SetDiskStage(secondary ? "126 writing secondary FAT32 boot sector" :
		"125 writing primary FAT32 boot sector");
#endif
	r = write_data_once(fp, 0, buf, len);
out:
   free(buf);
   return r;
}

static int write_fat_32_nt4_standard_br(FILE *fp, int secondary)
{
   #include "br_fat32_0x52.h"
   #include "br_fat32_0x3f0.h"

	return write_fat_32_nt4_data(fp, br_fat32_0x52, sizeof(br_fat32_0x52),
		br_fat32_0x3f0, sizeof(br_fat32_0x3f0), secondary);
}

static int write_fat_32_nt4_freedos_br(FILE *fp, int secondary)
{
   #include "br_fat32fd_0x52.h"
   #include "br_fat32fd_0x3f0.h"

	return write_fat_32_nt4_data(fp, br_fat32_0x52, sizeof(br_fat32_0x52),
		br_fat32_0x3f0, sizeof(br_fat32_0x3f0), secondary);
}

int write_fat_32_nt4_br(FILE *fp, int bFreeDOS, int secondary)
{
	return bFreeDOS ? write_fat_32_nt4_freedos_br(fp, secondary) :
		write_fat_32_nt4_standard_br(fp, secondary);
}

int entire_fat_32_nt_br_matches(FILE *fp)
{
   #include "br_fat32_0x0.h"
   #include "br_fat32nt_0x52.h"
   #include "br_fat32nt_0x3f0.h"
   #include "br_fat32nt_0x1800.h"

   return
      ( contains_data(fp, 0x0, br_fat32_0x0, sizeof(br_fat32_0x0)) &&
	/* BIOS Parameter Block might differ between systems */
	contains_data(fp, 0x52, br_fat32nt_0x52, sizeof(br_fat32nt_0x52)) &&
	/* Cluster information might differ between systems */
	contains_data(fp, 0x3f0, br_fat32nt_0x3f0, sizeof(br_fat32nt_0x3f0)) &&
	contains_data(fp, 0x1800, br_fat32nt_0x1800, sizeof(br_fat32nt_0x1800))
	 );
} /* entire_fat_32_nt_br_matches */

int write_fat_32_nt_br(FILE *fp, int bKeepLabel)
{
   #include "label_11_char.h"
   #include "br_fat32_0x0.h"
   #include "br_fat32nt_0x52.h"
   #include "br_fat32nt_0x3f0.h"
   #include "br_fat32nt_0x1800.h"

   if(bKeepLabel)
      return
	 ( write_data(fp, 0x0, br_fat32_0x0, sizeof(br_fat32_0x0)) &&
	   /* BIOS Parameter Block should not be overwritten */
	   write_data(fp, 0x52, br_fat32nt_0x52, sizeof(br_fat32nt_0x52)) &&
   /* Cluster information is not overwritten, however, it would be OK
      to write 0xff 0xff 0xff 0xff 0xff 0xff 0xff 0xff here. */
	   write_data(fp, 0x3f0, br_fat32nt_0x3f0, sizeof(br_fat32nt_0x3f0)) &&
	   write_data(fp, 0x1800, br_fat32nt_0x1800, sizeof(br_fat32nt_0x1800))
	    );
   else
      return
	 ( write_data(fp, 0x0, br_fat32_0x0, sizeof(br_fat32_0x0)) &&
	   /* BIOS Parameter Block should not be overwritten */
	   write_data(fp, 0x47, label_11_char, sizeof(label_11_char)) &&
	   write_data(fp, 0x52, br_fat32nt_0x52, sizeof(br_fat32nt_0x52)) &&
   /* Cluster information is not overwritten, however, it would be OK
      to write 0xff 0xff 0xff 0xff 0xff 0xff 0xff 0xff here. */
	   write_data(fp, 0x3f0, br_fat32nt_0x3f0, sizeof(br_fat32nt_0x3f0)) &&
	   write_data(fp, 0x1800, br_fat32nt_0x1800, sizeof(br_fat32nt_0x1800))
	    );
} /* write_fat_32_nt_br */

int entire_fat_32_pe_br_matches(FILE *fp)
{
   #include "br_fat32_0x0.h"
   #include "br_fat32pe_0x52.h"
   #include "br_fat32pe_0x3f0.h"
   #include "br_fat32pe_0x1800.h"

   return
      ( contains_data(fp, 0x0, br_fat32_0x0, sizeof(br_fat32_0x0)) &&
	/* BIOS Parameter Block might differ between systems */
	contains_data(fp, 0x52, br_fat32pe_0x52, sizeof(br_fat32pe_0x52)) &&
	/* Cluster information might differ between systems */
	contains_data(fp, 0x3f0, br_fat32pe_0x3f0, sizeof(br_fat32pe_0x3f0)) &&
	contains_data(fp, 0x1800, br_fat32pe_0x1800, sizeof(br_fat32pe_0x1800))
	 );
} /* entire_fat_32_nt_br_matches */

int write_fat_32_pe_br(FILE *fp, int bKeepLabel)
{
   #include "label_11_char.h"
   #include "br_fat32_0x0.h"
   #include "br_fat32pe_0x52.h"
   #include "br_fat32pe_0x3f0.h"
   #include "br_fat32pe_0x1800.h"

   if(bKeepLabel)
      return
	 ( write_data(fp, 0x0, br_fat32_0x0, sizeof(br_fat32_0x0)) &&
	   /* BIOS Parameter Block should not be overwritten */
	   write_data(fp, 0x52, br_fat32pe_0x52, sizeof(br_fat32pe_0x52)) &&
   /* Cluster information is not overwritten, however, it would bo OK
      to write 0xff 0xff 0xff 0xff 0xff 0xff 0xff 0xff here. */
	   write_data(fp, 0x3f0, br_fat32pe_0x3f0, sizeof(br_fat32pe_0x3f0)) &&
	   write_data(fp, 0x1800, br_fat32pe_0x1800, sizeof(br_fat32pe_0x1800))
	    );
   else
      return
	 ( write_data(fp, 0x0, br_fat32_0x0, sizeof(br_fat32_0x0)) &&
	   /* BIOS Parameter Block should not be overwritten */
	   write_data(fp, 0x47, label_11_char, sizeof(label_11_char)) &&
	   write_data(fp, 0x52, br_fat32pe_0x52, sizeof(br_fat32pe_0x52)) &&
   /* Cluster information is not overwritten, however, it would bo OK
      to write 0xff 0xff 0xff 0xff 0xff 0xff 0xff 0xff here. */
	   write_data(fp, 0x3f0, br_fat32pe_0x3f0, sizeof(br_fat32pe_0x3f0)) &&
	   write_data(fp, 0x1800, br_fat32pe_0x1800, sizeof(br_fat32pe_0x1800))
	    );
} /* write_fat_32_pe_br */

int entire_fat_32_ros_br_matches(FILE *fp)
{
   #include "br_fat32_0x0.h"
   #include "br_fat32ros_0x52.h"
   #include "br_fat32ros_0x3f0.h"
   #include "br_fat32ros_0x1c00.h"

   return
      ( contains_data(fp, 0x0, br_fat32_0x0, sizeof(br_fat32_0x0)) &&
	/* BIOS Parameter Block might differ between systems */
	contains_data(fp, 0x52, br_fat32ros_0x52, sizeof(br_fat32ros_0x52)) &&
	/* Cluster information might differ between systems */
	contains_data(fp, 0x3f0, br_fat32ros_0x3f0, sizeof(br_fat32ros_0x3f0)) &&
	contains_data(fp, 0x1c00, br_fat32ros_0x1c00, sizeof(br_fat32ros_0x1c00))
	 );
} /* entire_fat_32_ros_br_matches */

/* See http://doxygen.reactos.org/dc/d83/bootsup_8c_source.html#l01596 */
int write_fat_32_ros_br(FILE *fp, int bKeepLabel)
{
   #include "label_11_char.h"
   #include "br_fat32_0x0.h"
   #include "br_fat32ros_0x52.h"
   #include "br_fat32ros_0x3f0.h"
   #include "br_fat32ros_0x1c00.h"

   if(bKeepLabel)
      return
	 ( write_data(fp, 0x0, br_fat32_0x0, sizeof(br_fat32_0x0)) &&
	   /* BIOS Parameter Block should not be overwritten */
	   write_data(fp, 0x52, br_fat32ros_0x52, sizeof(br_fat32ros_0x52)) &&
   /* Cluster information is not overwritten, however, it would be OK
      to write 0xff 0xff 0xff 0xff 0xff 0xff 0xff 0xff here. */
	   write_data(fp, 0x3f0, br_fat32ros_0x3f0, sizeof(br_fat32ros_0x3f0)) &&
	   write_data(fp, 0x1c00, br_fat32ros_0x1c00, sizeof(br_fat32ros_0x1c00))
	    );
   else
      return
	 ( write_data(fp, 0x0, br_fat32_0x0, sizeof(br_fat32_0x0)) &&
	   /* BIOS Parameter Block should not be overwritten */
	   write_data(fp, 0x47, label_11_char, sizeof(label_11_char)) &&
	   write_data(fp, 0x52, br_fat32ros_0x52, sizeof(br_fat32ros_0x52)) &&
   /* Cluster information is not overwritten, however, it would be OK
      to write 0xff 0xff 0xff 0xff 0xff 0xff 0xff 0xff here. */
	   write_data(fp, 0x3f0, br_fat32ros_0x3f0, sizeof(br_fat32ros_0x3f0)) &&
	   write_data(fp, 0x1c00, br_fat32ros_0x1c00, sizeof(br_fat32ros_0x1c00))
	    );
} /* write_fat_32_ros_br */

int entire_fat_32_kos_br_matches(FILE *fp)
{
   #include "br_fat32_0x0.h"
   #include "br_fat32kos_0x52.h"

   return
      ( contains_data(fp, 0x0, br_fat32_0x0, sizeof(br_fat32_0x0)) &&
        contains_data(fp, 0x52, br_fat32kos_0x52, sizeof(br_fat32kos_0x52)) );
} /* entire_fat_32_kos_br_matches */

int write_fat_32_kos_br(FILE *fp, int bKeepLabel)
{
   #include "label_11_char.h"
   #include "br_fat32_0x0.h"
   #include "br_fat32kos_0x52.h"

   if(bKeepLabel)
      return
	 ( write_data(fp, 0x0, br_fat32_0x0, sizeof(br_fat32_0x0)) &&
	   write_data(fp, 0x52, br_fat32kos_0x52, sizeof(br_fat32kos_0x52)) );
   else
      return
	 ( write_data(fp, 0x0, br_fat32_0x0, sizeof(br_fat32_0x0)) &&
	   write_data(fp, 0x47, label_11_char, sizeof(label_11_char)) &&
	   write_data(fp, 0x52, br_fat32kos_0x52, sizeof(br_fat32kos_0x52)) );
} /* write_fat_32_kos_br */
