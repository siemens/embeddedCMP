/*
 *  Copyright (c) 2019 Siemens AG
 * *
 *  Licensed under the Apache License, Version 2.0
 *
 *  SPDX-License-Identifier: Apache-2.0
 *
 * lwip_helper.c
 *
 *  Created on: 09.01.2019
 *      Author: kretscha
 */
#include "lwip/ip4_addr.h"
#include "lwip/opt.h"
#include "lwip/apps/httpd.h"
#include "lwip/timeouts.h"
#include "lwip/init.h"
#include "netif/ethernet.h"
#include "ethernetif.h"
#include "board.h"

/*******************************************************************************
 * Definitions
 ******************************************************************************/

/* IP address configuration. */
#define configIP_ADDR0 192
#define configIP_ADDR1 168
#define configIP_ADDR2 0
#define configIP_ADDR3 102

/* Netmask configuration. */
#define configNET_MASK0 255
#define configNET_MASK1 255
#define configNET_MASK2 255
#define configNET_MASK3 0

/* Gateway address configuration. */
#define configGW_ADDR0 192
#define configGW_ADDR1 168
#define configGW_ADDR2 0
#define configGW_ADDR3 100

/* MAC address configuration. */
#define configMAC_ADDR {0x02, 0x12, 0x13, 0x10, 0x15, 0x11}

/* Address of PHY interface. */
#define EXAMPLE_PHY_ADDRESS BOARD_ENET0_PHY_ADDRESS

/* System clock name. */
#define EXAMPLE_CLOCK_NAME kCLOCK_CoreSysClk

static struct netif fsl_netif0;

void poll_lwip_driver() {
    ethernetif_input(&fsl_netif0);
    sys_check_timeouts(); /* Handle all system timeouts for all core protocols */
}

void setup_lwip() {
    lwip_init();
    ip4_addr_t fsl_netif0_ipaddr, fsl_netif0_netmask, fsl_netif0_gw;
    ethernetif_config_t fsl_enet_config0 = { .phyAddress = EXAMPLE_PHY_ADDRESS,
            .clockName = EXAMPLE_CLOCK_NAME, .macAddress = configMAC_ADDR };
    IP4_ADDR(&fsl_netif0_ipaddr, configIP_ADDR0, configIP_ADDR1, configIP_ADDR2,
            configIP_ADDR3);
    IP4_ADDR(&fsl_netif0_netmask, configNET_MASK0, configNET_MASK1,
            configNET_MASK2, configNET_MASK3);
    IP4_ADDR(&fsl_netif0_gw, configGW_ADDR0, configGW_ADDR1, configGW_ADDR2,
            configGW_ADDR3);
    netif_add(&fsl_netif0, &fsl_netif0_ipaddr, &fsl_netif0_netmask,
            &fsl_netif0_gw, &fsl_enet_config0, ethernetif0_init,
            ethernet_input);
    netif_set_default(&fsl_netif0);
    netif_set_up(&fsl_netif0);
    PRINTF("\r\n************************************************\r\n");
    PRINTF(" IP setup:\r\n");
    PRINTF("************************************************\r\n");
    PRINTF(" IPv4 Address     : %u.%u.%u.%u\r\n",
            ((u8_t*) &fsl_netif0_ipaddr)[0], ((u8_t*) &fsl_netif0_ipaddr)[1],
            ((u8_t*) &fsl_netif0_ipaddr)[2], ((u8_t*) &fsl_netif0_ipaddr)[3]);
    PRINTF(" IPv4 Subnet mask : %u.%u.%u.%u\r\n",
            ((u8_t*) &fsl_netif0_netmask)[0], ((u8_t*) &fsl_netif0_netmask)[1],
            ((u8_t*) &fsl_netif0_netmask)[2], ((u8_t*) &fsl_netif0_netmask)[3]);
    PRINTF(" IPv4 Gateway     : %u.%u.%u.%u\r\n", ((u8_t*) &fsl_netif0_gw)[0],
            ((u8_t*) &fsl_netif0_gw)[1], ((u8_t*) &fsl_netif0_gw)[2],
            ((u8_t*) &fsl_netif0_gw)[3]);
    PRINTF("************************************************\r\n");
}
