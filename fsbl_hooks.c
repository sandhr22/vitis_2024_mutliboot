/******************************************************************************
* Copyright (c) 2012 - 2020 Xilinx, Inc.  All rights reserved.
* SPDX-License-Identifier: MIT
******************************************************************************/


/*****************************************************************************
*
* @file fsbl_hooks.c
*
* This file provides functions that serve as user hooks.  The user can add the
* additional functionality required into these routines.  This would help retain
* the normal FSBL flow unchanged.
*
* <pre>
* MODIFICATION HISTORY:
*
* Ver   Who  Date        Changes
* ----- ---- -------- -------------------------------------------------------
* 3.00a np   08/03/12 Initial release
* </pre>
*
* @note
*
******************************************************************************/


#include "fsbl.h"
#include "xstatus.h"
#include "fsbl_hooks.h"
#include "sleep.h"
#include "xil_mmu.h"
#include "xil_cache.h"

/************************** Variable Definitions *****************************/


/************************** Function Prototypes ******************************/


/******************************************************************************
* This function is the hook which will be called  before the bitstream download.
* The user can add all the customized code required to be executed before the
* bitstream download to this routine.
*
* @param None
*
* @return
*		- XST_SUCCESS to indicate success
*		- XST_FAILURE.to indicate failure
*
****************************************************************************/
u32 FsblHookBeforeBitstreamDload(void)
{
	u32 Status;

	Status = XST_SUCCESS;

	/*
	 * User logic to be added here. Errors to be stored in the status variable
	 * and returned
	 */
	fsbl_printf(DEBUG_INFO,"In FsblHookBeforeBitstreamDload function \r\n");

	return (Status);
}

/******************************************************************************
* This function is the hook which will be called  after the bitstream download.
* The user can add all the customized code required to be executed after the
* bitstream download to this routine.
*
* @param None
*
* @return
*		- XST_SUCCESS to indicate success
*		- XST_FAILURE.to indicate failure
*
****************************************************************************/
u32 FsblHookAfterBitstreamDload(void)
{
	u32 Status;

	Status = XST_SUCCESS;

	fsbl_printf(DEBUG_INFO, "In FsblHookAfterBitstreamDload function \r\n");

	/* Remap BRAM region from Strongly-Ordered to Normal Non-Cacheable.
	 * The default standalone MMU maps 0x80000000-0xBFFFFFFF as Strongly-Ordered
	 * which makes cache maintenance instructions (DCIMVAC) UNPREDICTABLE and
	 * causes data aborts. Normal Non-Cacheable allows cache ops on the region
	 * while keeping BRAM out of the cache — the application will upgrade to
	 * NORM_WB_CACHE on startup once the ELF is loaded. Covers 1MB section
	 * (0x80000000-0x800FFFFF), which contains the full 512KB BRAM extent. */
	Xil_SetTlbAttributes(0x80000000U, NORM_NONCACHE);

	/* Dump key SLCR/AXI state before touching anything */
	fsbl_printf(DEBUG_GENERAL,
		"SLCR_LOCKST  0xF800000C = 0x%08x (0=unlocked,1=locked)\r\n",
		(unsigned int)Xil_In32(0xF800000CU));
	fsbl_printf(DEBUG_GENERAL,
		"LVL_SHFTR_EN 0xF8000900 = 0x%08x (before write)\r\n",
		(unsigned int)Xil_In32(PS_LVL_SHFTR_EN));
	fsbl_printf(DEBUG_GENERAL,
		"FPGA_RST_CTRL 0xF8000240 = 0x%08x\r\n",
		(unsigned int)Xil_In32(FPGA_RESET_REG));

	/* Enable full bidirectional level shifters for M_AXI_GP1 */
	Xil_Out32(PS_LVL_SHFTR_EN, LVL_PL_PS);
	fsbl_printf(DEBUG_GENERAL,
		"LVL_SHFTR_EN 0xF8000900 = 0x%08x (after write 0xF)\r\n",
		(unsigned int)Xil_In32(PS_LVL_SHFTR_EN));

	/* Pulse FPGA_RST_CTRL to give proc_sys_reset IPs a clean 0->1 edge on
	 * FCLK_RESETn_N. ps7_init leaves FPGA_RST_CTRL=0x00 so FCLK_RESETn_N
	 * are always high and never toggled after bitstream load. proc_sys_reset
	 * requires seeing ext_reset_in go low then return high to sequence its
	 * internal counters and release peripheral_aresetn. Without this edge,
	 * axi_smc and axi_bram_ctrl_0 stay in AXI reset (s_axi_aresetn=0) and
	 * the CPU write to 0x80000000 stalls forever waiting for AWREADY. */
	Xil_Out32(FPGA_RESET_REG, 0x0000000FU); /* assert all FCLK_RESETn (active-low) */
	usleep(1000U);                           /* hold: 1ms >> SmartConnect minimum reset assertion */
	Xil_Out32(FPGA_RESET_REG, 0x00000000U); /* deassert -> rising edge on FCLK_RESETn_N */
	usleep(1000U);                           /* wait for peripheral_aresetn to release + axi_smc init */
	fsbl_printf(DEBUG_GENERAL,
		"FPGA_RST_CTRL 0xF8000240 = 0x%08x (after pulse)\r\n",
		(unsigned int)Xil_In32(FPGA_RESET_REG));

	/* Dump SLCR PLL status and FCLK clock control registers.
	 * rst_ps7_0_150M needs FCLK_CLK1 on slowest_sync_clk to sequence
	 * peripheral_aresetn. M_AXI_GP1_ACLK is also FCLK_CLK1, so if it is
	 * not running no GP1 transaction can complete.
	 * FPGA0/1_CLK_CTRL format: [13:8]=DIVISOR0, [25:20]=DIVISOR1 (both nonzero needed) */
	fsbl_printf(DEBUG_GENERAL,
		"PLL_STATUS      0xF800010C = 0x%08x (b0=ARM,b1=DDR,b2=IO locked)\r\n",
		(unsigned int)Xil_In32(0xF800010CU));
	fsbl_printf(DEBUG_GENERAL,
		"FPGA0_CLK_CTRL  0xF8000170 = 0x%08x ([13:8]=DIV0,[25:20]=DIV1)\r\n",
		(unsigned int)Xil_In32(0xF8000170U));
	fsbl_printf(DEBUG_GENERAL,
		"FPGA1_CLK_CTRL  0xF8000180 = 0x%08x ([13:8]=DIV0,[25:20]=DIV1)\r\n",
		(unsigned int)Xil_In32(0xF8000180U));

	/* Verify M_AXI_GP0 is accessible via axi_gpio_0 ch2 (0x41200008).
	 * GP0 is on FCLK_CLK0/proc_sys_reset_0, independent of GP1.
	 * If this hangs: level shifters or FPGA_RST_CTRL pulse failed entirely.
	 * Note: this write drives PL LEDs; it is cleared in FsblHookBeforeHandoff. */
	fsbl_printf(DEBUG_GENERAL, "Testing M_AXI_GP0 via axi_gpio_0 at 0x41200008...\r\n");
	*((volatile u32 *)0x41200008U) = 0x12345678U;
	fsbl_printf(DEBUG_GENERAL, "GPIO0 ch2 readback = 0x%08x (expect 0x12345678)\r\n",
		(unsigned int)*((volatile u32 *)0x41200008U));

	/* Read axi_gpio_0 ch1 input data register (0x41200000).
	 * Bits [1:0] = {rst_ps7_0_150M_peripheral_aresetn, FCLK_RESET1_N}.
	 * After FPGA_RST_CTRL pulse and 1ms wait both should be 1 (not in reset).
	 * bit0 = FCLK_RESET1_N, bit1 = peripheral_aresetn */
	fsbl_printf(DEBUG_GENERAL,
		"axi_gpio_0 ch1 input (0x41200000) = 0x%08x (expect bits[1:0]=0b11)\r\n",
		(unsigned int)*((volatile u32 *)0x41200000U));

	/* Test M_AXI_GP1 BRAM at 0x80000000 (Normal Non-Cacheable after TLB remap above) */
	fsbl_printf(DEBUG_GENERAL, "Attempting test write to BRAM 0x80000000...\r\n");
	*((volatile u32 *)0x80000000U) = 0xDEADBEEFU;
	fsbl_printf(DEBUG_GENERAL, "BRAM[0] readback = 0x%08x (expect 0xDEADBEEF)\r\n",
		(unsigned int)*((volatile u32 *)0x80000000U));

	return (Status);
}

/******************************************************************************
* This function is the hook which will be called  before the FSBL does a handoff
* to the application. The user can add all the customized code required to be
* executed before the handoff to this routine.
*
* @param None
*
* @return
*		- XST_SUCCESS to indicate success
*		- XST_FAILURE.to indicate failure
*
****************************************************************************/
u32 FsblHookBeforeHandoff(void)
{
	u32 Status;

	Status = XST_SUCCESS;

	fsbl_printf(DEBUG_INFO,"In FsblHookBeforeHandoff function \r\n");

	/* Clear axi_gpio_0 ch2 output (LEDs) before handing off to application.
	 * The FSBL diagnostic test writes 0x12345678 to 0x41200008 which drives
	 * PL LEDs. Zero it so the application starts with all LEDs off. */
	Xil_Out32(0x41200008U, 0x00000000U);

	return (Status);
}


/******************************************************************************
* This function is the hook which will be called in case FSBL fall back
*
* @param None
*
* @return None
*
****************************************************************************/
void FsblHookFallback(void)
{
	/*
	 * User logic to be added here.
	 * Errors to be stored in the status variable and returned
	 */
	fsbl_printf(DEBUG_INFO,"In FsblHookFallback function \r\n");
	while(1);
}


