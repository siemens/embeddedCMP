/*
 * Copyright (c) 2016, Freescale Semiconductor, Inc.
 * Copyright 2016-2018 NXP
 * All rights reserved.
 *
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

/*******************************************************************************
 * Includes
 ******************************************************************************/
#include "cmp_main.h"
#include "mbedtls_helper.h"

#include "sys_arch.h"   /* from lwip/port/, needed for time_init() */

#include <stdio.h>
#include <string.h>
#include "fsl_sd.h"
#include "fsl_debug_console.h"
#include "fsl_uart.h"
#include "ff.h"
#include "diskio.h"
#include "fsl_sd_disk.h"
#include "board.h"

#include "fsl_sysmpu.h"
#include "fsl_device_registers.h"
#include "pin_mux.h"
#include "clock_config.h"

/*******************************************************************************
 * Variables
 ******************************************************************************/
#ifdef __MCUXPRESSO
extern unsigned int __end_of_heap;
uart_config_t config;
#endif

/*******************************************************************************
 * Code
 ******************************************************************************/
static FATFS g_fileSystem; /* File system object */

static status_t sdcardWaitCardInsert(void) {
	const sdmmchost_detect_card_t s_sdCardDetect = {
#ifndef BOARD_SD_DETECT_TYPE
			.cdType = kSDMMCHOST_DetectCardByGpioCD,
#else
			.cdType = BOARD_SD_DETECT_TYPE,
#endif
			.cdTimeOut_ms = (~0U), };
	/* Save host information. */
	g_sd.host.base = SD_HOST_BASEADDR;
	g_sd.host.sourceClock_Hz = SD_HOST_CLK_FREQ;
	/* card detect type */
	g_sd.usrParam.cd = &s_sdCardDetect;
#if defined DEMO_SDCARD_POWER_CTRL_FUNCTION_EXIST
	g_sd.usrParam.pwr = &s_sdCardPwrCtrl;
#endif
	/* SD host init function */
	if (SD_HostInit(&g_sd) != kStatus_Success) {
        PRINTF("\r\nSD host init fail\r\n");
		return kStatus_Fail;
	}
	/* power off card */
	SD_PowerOffCard(g_sd.host.base, g_sd.usrParam.pwr);
	/* wait card insert */
	if (SD_WaitCardDetectStatus(SD_HOST_BASEADDR, &s_sdCardDetect, true)
			== kStatus_Success) {
        PRINTF("\r\nSDHC Card detected.\r\n");
		/* power on the card */
		SD_PowerOnCard(g_sd.host.base, g_sd.usrParam.pwr);
	} else {
        PRINTF("\r\nCard detect fail.\r\n");
		return kStatus_Fail;
	}
	return kStatus_Success;
}

static int mount_sdcard() {
    //PRINTF("\r\nPlease insert a SDHC card into the NXP board.\r\n");
	if (sdcardWaitCardInsert() != kStatus_Success) {
		return -1;
	}
	const TCHAR driverNumberBuffer[3U] = { SDDISK + '0', ':', '/' };
	if (f_mount(&g_fileSystem, driverNumberBuffer, 0U)) {
        PRINTF("Mount volume failed.\r\n");
		return -1;
	}

#if (FF_FS_RPATH >= 2U)
	FRESULT error = f_chdrive((char const *) &driverNumberBuffer[0U]);
	if (error) {
        PRINTF("Change drive failed.\r\n");
		return -1;
	}
	return 0;
#endif
}

/*!
 * @brief Interrupt service for SysTick timer.
 */
void SysTick_Handler(void) {
	time_isr();
}

static void init_board() {
	BOARD_InitPins();
	BOARD_BootClockRUN();
	BOARD_InitDebugConsole();
	/* Disable SYSMPU. */
	SYSMPU_Enable(SYSMPU, false);
    PRINTF("\r\nBoard initialized.\r\n");
}

void init_uart() {
    /* configure UART for use with ksdk */
    UART_GetDefaultConfig(&config);
    config.baudRate_Bps = BOARD_DEBUG_UART_BAUDRATE;
    config.enableTx = true;
    UART_Init(UART0, &config, SYS_CLK);
    /* TODO clear terminal */
}

/*!
 * @brief Main function
 */
int main(void) {

	init_board();
	init_uart();

	time_init();
    if (mount_sdcard() < 0) {
        return -1;
    }

    return cmp_main();
}

