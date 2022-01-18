
#ifndef VICKY_3_H
#define VICKY_3_H

#define VKY3_MASTER_CONTROL_REG     ((volatile unsigned long *)0x00B40000)
#define VKY3_MCR_TEXT_ON            0x00000001  /* Text Mode Enable */
#define VKY3_MCR_TEXT_OVERLAY       0x00000002  /* Text Mode overlay */
#define VKY3_MCR_GRAPH_ON           0x00000004  /* Graphic Mode Enable */
#define VKY3_MCR_BITMAP_ON          0x00000008  /* Bitmap Engine Enable */
#define VKY3_MCR_RESOLUTION_MASK    0x00000300  /* Resolution - 00: 640x480, 01:800x600, 10: 1024x768, 11: 640x400 */
#define VKY3_MCR_640x480            0x00000000
#define VKY3_MCR_800x600            0x00000100
#define VKY3_MCR_1024x768           0x00000200
#define VKY3_MCR_640x400            0x00000300
#define VKY3_MCR_DOUBLE_ON          0x00000400  /* Doubling Pixel */
#define VKY3_MCR_GAMMA_ON           0x00010000  /* GAMMA Enable */
#define VKY3_MCR_MANUAL_GAMMA_ON    0x00020000  /* Enable Manual GAMMA Enable */
#define VKY3_MCR_BLANK_ON           0x00040000  /* Turn OFF sync (to monitor in sleep mode) */


#define VKY3_BORDER_CONTROL_REG     ((volatile unsigned long *)0x00B40008)
#define VKY3_BORDER_ON              0x00000001  /* Border Enable */
#define VKY3_X_SCROLL_MASK          0x00000070  /* X Scroll */
#define VKY3_X_SIZE_MASK            0x00003f00  /* X Size */
#define VKY3_Y_SIZE_MASK            0x003f0000  /* Y Size */

#define VKY3_BACKGROUND_CONTROL_REG ((volatile unsigned long *)0x00B4000C)
#define VKY3_CURSOR_SETTINGS_REG    ((volatile unsigned long *)0x00B40010)
#define VKY3_CURSOR_POSITION_REG    ((volatile unsigned long *)0x00B40014)

#define VKY3_SCREEN_TEXT            ((volatile char *)0x00B60000)           /* Text matrix */
#define VKY3_COLOR_TEXT             ((volatile unsigned char *)0x00B68000)  /* Color matrix */

#endif