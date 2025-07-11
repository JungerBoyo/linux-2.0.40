#ifndef _LINUX_MAJOR_H
#define _LINUX_MAJOR_H

/*
 * This file has definitions for major device numbers.
 * For the device number assignments, see Documentation/devices.txt.
 */

/* limits */

#define MAX_CHRDEV 128
#define MAX_BLKDEV 128

#define UNNAMED_MAJOR	0
#define MEM_MAJOR	1
#define RAMDISK_MAJOR	1
#define FLOPPY_MAJOR	2
#define PTY_MASTER_MAJOR 2
#define IDE0_MAJOR	3
#define PTY_SLAVE_MAJOR 3
#define HD_MAJOR	IDE0_MAJOR
#define TTY_MAJOR	4
#define TTYAUX_MAJOR	5
#define LP_MAJOR	6
#define VCS_MAJOR	7
#define LOOP_MAJOR	7
#define SCSI_DISK_MAJOR	8
#define SCSI_TAPE_MAJOR	9
#define MD_MAJOR        9
#define MISC_MAJOR	10
#define SCSI_CDROM_MAJOR 11
#define QIC02_TAPE_MAJOR 12
#define XT_DISK_MAJOR	13
#define SOUND_MAJOR	14
#define CDU31A_CDROM_MAJOR 15
#define JOYSTICK_MAJOR	15
#define GOLDSTAR_CDROM_MAJOR 16
#define OPTICS_CDROM_MAJOR 17
#define SANYO_CDROM_MAJOR 18
#define CYCLADES_MAJOR  19
#define CYCLADESAUX_MAJOR 20
#define MITSUMI_X_CDROM_MAJOR 20
#define SCSI_GENERIC_MAJOR 21
#define Z8530_MAJOR 34
#define DIGI_MAJOR 23
#define IDE1_MAJOR	22
#define DIGICU_MAJOR 22
#define MITSUMI_CDROM_MAJOR 23
#define CDU535_CDROM_MAJOR 24
#define STL_SERIALMAJOR 24
#define MATSUSHITA_CDROM_MAJOR 25
#define STL_CALLOUTMAJOR 25
#define MATSUSHITA_CDROM2_MAJOR 26
#define QIC117_TAPE_MAJOR 27
#define MATSUSHITA_CDROM3_MAJOR 27
#define MATSUSHITA_CDROM4_MAJOR 28
#define STL_SIOMEMMAJOR 28
#define ACSI_MAJOR	28
#define AZTECH_CDROM_MAJOR 29
#define GRAPHDEV_MAJOR	29	/* SparcLinux & Linux/68k /dev/fb */
#define CM206_CDROM_MAJOR 32
#define IDE2_MAJOR	33
#define IDE3_MAJOR	34
#define NETLINK_MAJOR	36
#define IDETAPE_MAJOR	37
#define Z2RAM_MAJOR	37
#define RISCOM8_NORMAL_MAJOR 48
#define DAC960_MAJOR	48	/* 48..55 */
#define RISCOM8_CALLOUT_MAJOR 49
#define MKISS_MAJOR	55

#define IDE4_MAJOR	56
#define IDE5_MAJOR	57
#define ZRAMDISK_MAJOR 58

#define APBLOCK_MAJOR   60   /* AP1000 Block device */
#define DDV_MAJOR       61   /* AP1000 DDV block device */

#define COMPAQ_SMART2_MAJOR	72
#define COMPAQ_SMART2_MAJOR1	73
#define COMPAQ_SMART2_MAJOR2	74
#define COMPAQ_SMART2_MAJOR3	75
#define COMPAQ_SMART2_MAJOR4	76
#define COMPAQ_SMART2_MAJOR5	77
#define COMPAQ_SMART2_MAJOR6	78
#define COMPAQ_SMART2_MAJOR7	79

#define SPECIALIX_NORMAL_MAJOR 75
#define SPECIALIX_CALLOUT_MAJOR 76

/*
 * Tests for SCSI devices.
 */

#define SCSI_BLK_MAJOR(M) \
  ((M) == SCSI_DISK_MAJOR	\
   || (M) == SCSI_CDROM_MAJOR)

static __inline__ int scsi_blk_major(int m) {
	return SCSI_BLK_MAJOR(m);
}

#endif
