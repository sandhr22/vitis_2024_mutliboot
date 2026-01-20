/******************************************************************************
* Copyright (c) 2012 - 2020 Xilinx, Inc.  All rights reserved.
* Copyright (c) 2022 - 2023, Advanced Micro Devices, Inc. All Rights Reserved.
* SPDX-License-Identifier: MIT
******************************************************************************/

/*****************************************************************************/
/**
*
* @file qspi.c
*
* Contains code for the QSPI FLASH functionality.
*
* <pre>
* MODIFICATION HISTORY:
*
* Ver	Who	Date		Changes
* ----- ---- -------- -------------------------------------------------------
* 1.00a ecm	01/10/10 Initial release
* 3.00a mb  25/06/12 InitQspi, data is read first and required config bits
*                    are set
* 4.00a sg	02/28/13 Cleanup
* 					 Removed LPBK_DLY_ADJ register setting code as we use
* 					 divisor 8
* 5.00a sgd	05/17/13 Added Flash Size > 128Mbit support
* 					 Dual Stack support
*					 Fix for CR:721674 - FSBL- Failed to boot from Dual
*					                     stacked QSPI
* 6.00a kc  08/30/13 Fix for CR#722979 - Provide customer-friendly
*                                        changelogs in FSBL
*                    Fix for CR#739711 - FSBL not able to read Large QSPI
*                    					 (512M) in IO Mode
* 7.00a kc  10/25/13 Fix for CR#739968 - FSBL should do the QSPI config
*                    					 settings for Dual parallel
*                    					 configuration in IO mode
* 14.0 gan 01/13/16  Fix for CR#869081 - (2016.1)FSBL picks the qspi read
*                                        command from LQSPI_CFG register
*					 					 instead of hard coded read
*					 					 command (0x6B).
* 15.0 bsv 09/04/20  Add support for 2Gb flash parts
* 21.1  ng 07/13/23  Add SDT support
* 21.2  ng 07/25/23  Updated QSPI address support in SDT flow
* </pre>
*
* @note
*
******************************************************************************/

/***************************** Include Files *********************************/

#include "qspi.h"
#include "image_mover.h"

#if defined(XPAR_PS7_QSPI_LINEAR_0_S_AXI_BASEADDR) || defined(XPAR_PS7_QSPI_LINEAR_0_BASEADDR)
#include "xqspips_hw.h"
#include "xqspips.h"

/************************** Constant Definitions *****************************/

/*
 * The following constants map to the XPAR parameters created in the
 * xparameters.h file. They are defined here such that a user can easily
 * change all the needed parameters in one place.
 */
#ifndef SDT
#define QSPI_DEVICE_ID		XPAR_XQSPIPS_0_DEVICE_ID
#define QSPI_CONNECTION_MODE (XPAR_XQSPIPS_0_QSPI_MODE)
#define QSPI_BUS_WIDTH (XPAR_XQSPIPS_0_QSPI_BUS_WIDTH)
#else
#define QSPI_DEVICE_ID		XPAR_XQSPIPS_0_BASEADDR
#define QSPI_CONNECTION_MODE (XPAR_XQSPIPS_0_CONNECTION_MODE)
#define QSPI_BUS_WIDTH (XPAR_XQSPIPS_0_QSPI_BUS_WIDTH)
#endif

/*
 * The following constants define the commands which may be sent to the FLASH
 * device.
 */
#define QUAD_READ_CMD		0x6B
#define READ_ID_CMD			0x9F

#define WRITE_ENABLE_CMD	0x06
#define BANK_REG_RD			0x16
#define BANK_REG_WR			0x17
/* Bank register is called Extended Address Reg in Micron */
#define EXTADD_REG_RD		0xC8
#define EXTADD_REG_WR		0xC5

#define COMMAND_OFFSET		0 /* FLASH instruction */
#define ADDRESS_1_OFFSET	1 /* MSB byte of address to read or write */
#define ADDRESS_2_OFFSET	2 /* Middle byte of address to read or write */
#define ADDRESS_3_OFFSET	3 /* LSB byte of address to read or write */
#define DATA_OFFSET			4 /* Start of Data for Read/Write */
#define DUMMY_OFFSET		4 /* Dummy byte offset for fast, dual and quad
				     reads */
#define DUMMY_SIZE			1 /* Number of dummy bytes for fast, dual and
				     quad reads */
#define RD_ID_SIZE			4 /* Read ID command + 3 bytes ID response */
#define BANK_SEL_SIZE		2 /* BRWR or EARWR command + 1 byte bank value */
#define WRITE_ENABLE_CMD_SIZE	1 /* WE command */
/*
 * The following constants specify the extra bytes which are sent to the
 * FLASH on the QSPI interface, that are not data, but control information
 * which includes the command and address
 */
#define OVERHEAD_SIZE		4

/*
 * The following constants specify the max amount of data and the size of the
 * the buffer required to hold the data and overhead to transfer the data to
 * and from the FLASH.
 */
#define DATA_SIZE		4096

/*
 * The following defines are for dual flash interface.
 */
#define LQSPI_CR_FAST_READ			0x0000000B
#define LQSPI_CR_FAST_DUAL_READ		0x0000003B
#define LQSPI_CR_FAST_QUAD_READ		0x0000006B /* Fast Quad Read output */
#define LQSPI_CR_1_DUMMY_BYTE		0x00000100 /* 1 Dummy Byte between
						     address and return data */

#define SINGLE_QSPI_CONFIG_FAST_READ	(XQSPIPS_LQSPI_CR_LINEAR_MASK | \
					 LQSPI_CR_1_DUMMY_BYTE | \
					 LQSPI_CR_FAST_READ)

#define SINGLE_QSPI_CONFIG_FAST_DUAL_READ	(XQSPIPS_LQSPI_CR_LINEAR_MASK | \
					 LQSPI_CR_1_DUMMY_BYTE | \
					 LQSPI_CR_FAST_DUAL_READ)

#define SINGLE_QSPI_CONFIG_FAST_QUAD_READ	(XQSPIPS_LQSPI_CR_LINEAR_MASK | \
					 LQSPI_CR_1_DUMMY_BYTE | \
					 LQSPI_CR_FAST_QUAD_READ)

#define DUAL_QSPI_CONFIG_FAST_QUAD_READ	(XQSPIPS_LQSPI_CR_LINEAR_MASK | \
					 XQSPIPS_LQSPI_CR_TWO_MEM_MASK | \
					 XQSPIPS_LQSPI_CR_SEP_BUS_MASK | \
					 LQSPI_CR_1_DUMMY_BYTE | \
					 LQSPI_CR_FAST_QUAD_READ)

#define DUAL_STACK_CONFIG_FAST_READ	(XQSPIPS_LQSPI_CR_TWO_MEM_MASK | \
					 LQSPI_CR_1_DUMMY_BYTE | \
					 LQSPI_CR_FAST_READ)

#define DUAL_STACK_CONFIG_FAST_DUAL_READ	(XQSPIPS_LQSPI_CR_TWO_MEM_MASK | \
					 LQSPI_CR_1_DUMMY_BYTE | \
					 LQSPI_CR_FAST_DUAL_READ)

#define DUAL_STACK_CONFIG_FAST_QUAD_READ	(XQSPIPS_LQSPI_CR_TWO_MEM_MASK | \
					 LQSPI_CR_1_DUMMY_BYTE | \
					 LQSPI_CR_FAST_QUAD_READ)

#define SINGLE_QSPI_IO_CONFIG_FAST_READ	(LQSPI_CR_1_DUMMY_BYTE | \
					 LQSPI_CR_FAST_READ)

#define SINGLE_QSPI_IO_CONFIG_FAST_DUAL_READ	(LQSPI_CR_1_DUMMY_BYTE | \
					 LQSPI_CR_FAST_DUAL_READ)

#define SINGLE_QSPI_IO_CONFIG_FAST_QUAD_READ	(LQSPI_CR_1_DUMMY_BYTE | \
					 LQSPI_CR_FAST_QUAD_READ)

#define DUAL_QSPI_IO_CONFIG_FAST_QUAD_READ	(XQSPIPS_LQSPI_CR_TWO_MEM_MASK | \
					 XQSPIPS_LQSPI_CR_SEP_BUS_MASK | \
					 LQSPI_CR_1_DUMMY_BYTE | \
					 LQSPI_CR_FAST_QUAD_READ)

#define QSPI_BUSWIDTH_ONE	0U
#define QSPI_BUSWIDTH_TWO	1U
#define QSPI_BUSWIDTH_FOUR	2U

/**************************** Type Definitions *******************************/

/***************** Macros (Inline Functions) Definitions *********************/

/************************** Function Prototypes ******************************/

/************************** Variable Definitions *****************************/

XQspiPs QspiInstance;
XQspiPs *QspiInstancePtr;
u32 QspiFlashSize;
u32 QspiFlashMake;
extern u32 FlashReadBaseAddress;
extern u8 LinearBootDeviceFlag;

/*
 * The following variables are used to read and write to the eeprom and they
 * are global to avoid having large buffers on the stack
 */
u8 ReadBuffer[DATA_SIZE + DATA_OFFSET + DUMMY_SIZE];
u8 WriteBuffer[DATA_OFFSET + DUMMY_SIZE];

/******************************************************************************/
/**
*
* This function initializes the controller for the QSPI interface.
*
* @param	None
*
* @return	None
*
* @note		None
*
****************************************************************************/
u32 InitQspi(void)
{
	XQspiPs_Config *QspiConfig;
	int Status;
	u32 ConfigCmd;

	QspiInstancePtr = &QspiInstance;

	/*
	 * Set up the base address for access
	 */
	FlashReadBaseAddress = XPS_QSPI_LINEAR_BASEADDR;

	/*
	 * Initialize the QSPI driver so that it's ready to use
	 */
	QspiConfig = XQspiPs_LookupConfig(QSPI_DEVICE_ID);
	if (NULL == QspiConfig) {
		return XST_FAILURE;
	}

	Status = XQspiPs_CfgInitialize(QspiInstancePtr, QspiConfig,
					QspiConfig->BaseAddress);
	if (Status != XST_SUCCESS) {
		return XST_FAILURE;
	}

	/*
	 * Set Manual Chip select options and drive HOLD_B pin high.
	 */
	XQspiPs_SetOptions(QspiInstancePtr, XQSPIPS_FORCE_SSELECT_OPTION |
			XQSPIPS_HOLD_B_DRIVE_OPTION);

	/*
	 * Set the prescaler for QSPI clock
	 */
	XQspiPs_SetClkPrescaler(QspiInstancePtr, XQSPIPS_CLK_PRESCALE_8);

	/*
	 * Assert the FLASH chip select.
	 */
	XQspiPs_SetSlaveSelect(QspiInstancePtr);

	/*
	 * Read Flash ID and extract Manufacture and Size information
	 */
	Status = FlashReadID();
	if (Status != XST_SUCCESS) {
		return XST_FAILURE;
	}

	if (QSPI_CONNECTION_MODE == SINGLE_FLASH_CONNECTION) {

		fsbl_printf(DEBUG_INFO,"QSPI is in single flash connection\r\n");
		/*
		 * For Flash size <128Mbit controller configured in linear mode
		 */
		if (QspiFlashSize <= FLASH_SIZE_16MB) {
			LinearBootDeviceFlag = 1;

			/*
			 * Enable linear mode
			 */
			XQspiPs_SetOptions(QspiInstancePtr,  XQSPIPS_LQSPI_MODE_OPTION |
					XQSPIPS_HOLD_B_DRIVE_OPTION);

			switch (QSPI_BUS_WIDTH) {

				case QSPI_BUSWIDTH_ONE:
				{
					fsbl_printf(DEBUG_INFO,"QSPI is in 1-bit mode\r\n");
					ConfigCmd = SINGLE_QSPI_CONFIG_FAST_READ;
				}
				break;

				case QSPI_BUSWIDTH_TWO:
				{
					fsbl_printf(DEBUG_INFO,"QSPI is in 2-bit mode\r\n");
					ConfigCmd = SINGLE_QSPI_CONFIG_FAST_DUAL_READ;
				}
				break;

				case QSPI_BUSWIDTH_FOUR:
				{
					fsbl_printf(DEBUG_INFO,"QSPI is in 4-bit mode\r\n");
					ConfigCmd = SINGLE_QSPI_CONFIG_FAST_QUAD_READ;
				}
				break;

			}

			/*
			 * Single linear read
			 */
			XQspiPs_SetLqspiConfigReg(QspiInstancePtr, ConfigCmd);

			/*
			 * Enable the controller
			 */
			XQspiPs_Enable(QspiInstancePtr);
		} else {

			switch (QSPI_BUS_WIDTH) {

				case QSPI_BUSWIDTH_ONE:
				{
					fsbl_printf(DEBUG_INFO,"QSPI is in 1-bit mode\r\n");
					ConfigCmd = SINGLE_QSPI_IO_CONFIG_FAST_READ;
				}
				break;

				case QSPI_BUSWIDTH_TWO:
				{
					fsbl_printf(DEBUG_INFO,"QSPI is in 2-bit mode\r\n");
					ConfigCmd = SINGLE_QSPI_IO_CONFIG_FAST_DUAL_READ;
				}
				break;

				case QSPI_BUSWIDTH_FOUR:
				{
					fsbl_printf(DEBUG_INFO,"QSPI is in 4-bit mode\r\n");
					ConfigCmd = SINGLE_QSPI_IO_CONFIG_FAST_QUAD_READ;
				}
				break;

			}
			/*
			 * Single flash IO read
			 */
			XQspiPs_SetLqspiConfigReg(QspiInstancePtr, ConfigCmd);

			/*
			 * Enable the controller
			 */
			XQspiPs_Enable(QspiInstancePtr);
		}
	}

	if (QSPI_CONNECTION_MODE == DUAL_PARALLEL_CONNECTION) {

		fsbl_printf(DEBUG_INFO,"QSPI is in Dual Parallel connection\r\n");
		/*
		 * For Single Flash size <128Mbit controller configured in linear mode
		 */
		if (QspiFlashSize <= FLASH_SIZE_16MB) {
			/*
			 * Setting linear access flag
			 */
			LinearBootDeviceFlag = 1;

			/*
			 * Enable linear mode
			 */
			XQspiPs_SetOptions(QspiInstancePtr,  XQSPIPS_LQSPI_MODE_OPTION |
					XQSPIPS_HOLD_B_DRIVE_OPTION);

			/*
			 * Dual linear read
			 */
			XQspiPs_SetLqspiConfigReg(QspiInstancePtr, DUAL_QSPI_CONFIG_FAST_QUAD_READ);

			/*
			 * Enable the controller
			 */
			XQspiPs_Enable(QspiInstancePtr);
		} else {
			/*
			 * Dual flash IO read
			 */
			XQspiPs_SetLqspiConfigReg(QspiInstancePtr, DUAL_QSPI_IO_CONFIG_FAST_QUAD_READ);

			/*
			 * Enable the controller
			 */
			XQspiPs_Enable(QspiInstancePtr);

		}

		/*
		 * Total flash size is two time of single flash size
		 */
		QspiFlashSize = 2 * QspiFlashSize;
	}

	/*
	 * It is expected to same flash size for both chip selection
	 */
	if (QSPI_CONNECTION_MODE == DUAL_STACK_CONNECTION) {

		fsbl_printf(DEBUG_INFO,"QSPI is in Dual Stack connection\r\n");

		QspiFlashSize = 2 * QspiFlashSize;

		/*
		 * Enable two flash memories on separate buses
		 */
		switch (QSPI_BUS_WIDTH) {

			case QSPI_BUSWIDTH_ONE:
			{
				fsbl_printf(DEBUG_INFO,"QSPI is in 1-bit mode\r\n");
				ConfigCmd =  DUAL_STACK_CONFIG_FAST_READ;
			}
			break;

			case QSPI_BUSWIDTH_TWO:
			{
				fsbl_printf(DEBUG_INFO,"QSPI is in 2-bit mode\r\n");
				ConfigCmd =  DUAL_STACK_CONFIG_FAST_DUAL_READ;
			}
			break;

			case QSPI_BUSWIDTH_FOUR:
			{
				fsbl_printf(DEBUG_INFO,"QSPI is in 4-bit mode\r\n");
				ConfigCmd =  DUAL_STACK_CONFIG_FAST_QUAD_READ;
			}
			break;

		}
		XQspiPs_SetLqspiConfigReg(QspiInstancePtr, ConfigCmd);
	}

	return XST_SUCCESS;
}

/******************************************************************************
*
* This function reads serial FLASH ID connected to the SPI interface.
* It then deduces the make and size of the flash and obtains the
* connection mode to point to corresponding parameters in the flash
* configuration table. The flash driver will function based on this and
* it presently supports Micron and Spansion - 128, 256 and 512Mbit and
* Winbond 128Mbit
*
* @param	none
*
* @return	XST_SUCCESS if read id, otherwise XST_FAILURE.
*
* @note		None.
*
******************************************************************************/
u32 FlashReadID(void)
{
	u32 Status;

	/*
	 * Read ID in Auto mode.
	 */
	WriteBuffer[COMMAND_OFFSET]   = READ_ID_CMD;
	WriteBuffer[ADDRESS_1_OFFSET] = 0x00;		/* 3 dummy bytes */
	WriteBuffer[ADDRESS_2_OFFSET] = 0x00;
	WriteBuffer[ADDRESS_3_OFFSET] = 0x00;

	Status = XQspiPs_PolledTransfer(QspiInstancePtr, WriteBuffer, ReadBuffer,
				RD_ID_SIZE);
	if (Status != XST_SUCCESS) {
		return XST_FAILURE;
	}

	fsbl_printf(DEBUG_INFO,"Single Flash Information\r\n");

	fsbl_printf(DEBUG_INFO,"FlashID=0x%x 0x%x 0x%x\r\n", ReadBuffer[1],
			ReadBuffer[2],
			ReadBuffer[3]);

	/*
	 * Deduce flash make
	 */
	if (ReadBuffer[1] == MICRON_ID) {
		QspiFlashMake = MICRON_ID;
		fsbl_printf(DEBUG_INFO, "MICRON ");
	} else if(ReadBuffer[1] == SPANSION_ID) {
		QspiFlashMake = SPANSION_ID;
		fsbl_printf(DEBUG_INFO, "SPANSION ");
	} else if(ReadBuffer[1] == WINBOND_ID) {
		QspiFlashMake = WINBOND_ID;
		fsbl_printf(DEBUG_INFO, "WINBOND ");
	} else if(ReadBuffer[1] == MACRONIX_ID) {
		QspiFlashMake = MACRONIX_ID;
		fsbl_printf(DEBUG_INFO, "MACRONIX ");
	} else if(ReadBuffer[1] == ISSI_ID) {
		QspiFlashMake = ISSI_ID;
		fsbl_printf(DEBUG_INFO, "ISSI ");
	}

	/*
	 * Deduce flash Size
	 */
	if (ReadBuffer[3] == FLASH_SIZE_ID_8M) {
		QspiFlashSize = FLASH_SIZE_8M;
		fsbl_printf(DEBUG_INFO, "8M Bits\r\n");
	} else if (ReadBuffer[3] == FLASH_SIZE_ID_16M) {
		QspiFlashSize = FLASH_SIZE_16M;
		fsbl_printf(DEBUG_INFO, "16M Bits\r\n");
	} else if (ReadBuffer[3] == FLASH_SIZE_ID_32M) {
		QspiFlashSize = FLASH_SIZE_32M;
		fsbl_printf(DEBUG_INFO, "32M Bits\r\n");
	} else if (ReadBuffer[3] == FLASH_SIZE_ID_64M) {
		QspiFlashSize = FLASH_SIZE_64M;
		fsbl_printf(DEBUG_INFO, "64M Bits\r\n");
	} else if (ReadBuffer[3] == FLASH_SIZE_ID_128M) {
		QspiFlashSize = FLASH_SIZE_128M;
		fsbl_printf(DEBUG_INFO, "128M Bits\r\n");
	} else if (ReadBuffer[3] == FLASH_SIZE_ID_256M) {
		QspiFlashSize = FLASH_SIZE_256M;
		fsbl_printf(DEBUG_INFO, "256M Bits\r\n");
	} else if ((ReadBuffer[3] == FLASH_SIZE_ID_512M)
			|| (ReadBuffer[3] == MACRONIX_FLASH_1_8_V_MX66_ID_512)
			|| (ReadBuffer[3] == MACRONIX_FLASH_SIZE_ID_512M)) {
		QspiFlashSize = FLASH_SIZE_512M;
		fsbl_printf(DEBUG_INFO, "512M Bits\r\n");
	} else if ((ReadBuffer[3] == FLASH_SIZE_ID_1G)
			|| (ReadBuffer[3] == MACRONIX_FLASH_SIZE_ID_1G)) {
		QspiFlashSize = FLASH_SIZE_1G;
		fsbl_printf(DEBUG_INFO, "1G Bits\r\n");
	} else if ((ReadBuffer[3] == FLASH_SIZE_ID_2G)
			|| (ReadBuffer[3] == MACRONIX_FLASH_SIZE_ID_2G)) {
		QspiFlashSize = FLASH_SIZE_2G;
		fsbl_printf(DEBUG_INFO, "2G Bits\r\n");
	}
	return XST_SUCCESS;
}


/******************************************************************************
*
* This function reads from the  serial FLASH connected to the
* QSPI interface.
*
* @param	Address contains the address to read data from in the FLASH.
* @param	ByteCount contains the number of bytes to read.
*
* @return	None.
*
* @note		None.
*
******************************************************************************/
void FlashRead(u32 Address, u32 ByteCount)
{
	/*
	 * Setup the write command with the specified address and data for the
	 * FLASH
	 */
	u32 LqspiCrReg;
	u8  ReadCommand;

	LqspiCrReg = XQspiPs_GetLqspiConfigReg(QspiInstancePtr);
	ReadCommand = (u8) (LqspiCrReg & XQSPIPS_LQSPI_CR_INST_MASK);
	WriteBuffer[COMMAND_OFFSET]   = ReadCommand;
	WriteBuffer[ADDRESS_1_OFFSET] = (u8)((Address & 0xFF0000) >> 16);
	WriteBuffer[ADDRESS_2_OFFSET] = (u8)((Address & 0xFF00) >> 8);
	WriteBuffer[ADDRESS_3_OFFSET] = (u8)(Address & 0xFF);

	ByteCount += DUMMY_SIZE;

	/*
	 * Send the read command to the FLASH to read the specified number
	 * of bytes from the FLASH, send the read command and address and
	 * receive the specified number of bytes of data in the data buffer
	 */
	XQspiPs_PolledTransfer(QspiInstancePtr, WriteBuffer, ReadBuffer,
				ByteCount + OVERHEAD_SIZE);
}

/******************************************************************************/
/**
*
* This function provides the QSPI FLASH interface for the Simplified header
* functionality.
*
* @param	SourceAddress is address in FLASH data space
* @param	DestinationAddress is address in DDR data space
* @param	LengthBytes is the length of the data in Bytes
*
* @return
*		- XST_SUCCESS if the write completes correctly
*		- XST_FAILURE if the write fails to completes correctly
*
* @note	none.
*
****************************************************************************/
u32 QspiAccess( u32 SourceAddress, u32 DestinationAddress, u32 LengthBytes)
{
	u8	*BufferPtr;
	u32 Length = 0;
	u32 BankSel = 0;
	u32 LqspiCrReg;
	u32 Status;
	u8 BankSwitchFlag = 1;

	/*
	 * Linear access check
	 */
	if (LinearBootDeviceFlag == 1) {
		/*
		 * Check for non-word tail, add bytes to cover the end
		 */
		if ((LengthBytes%4) != 0){
			LengthBytes += (4 - (LengthBytes & 0x00000003));
		}

		memcpy((void*)DestinationAddress,
		      (const void*)(SourceAddress + FlashReadBaseAddress),
		      (size_t)LengthBytes);
	} else {
		/*
		 * Non Linear access
		 */
		BufferPtr = (u8*)DestinationAddress;

		/*
		 * Dual parallel connection actual flash is half
		 */
		if (QSPI_CONNECTION_MODE == DUAL_PARALLEL_CONNECTION) {
			SourceAddress = SourceAddress/2;
		}

		while(LengthBytes > 0) {
			/*
			 * Local of DATA_SIZE size used for read/write buffer
			 */
			if(LengthBytes > DATA_SIZE) {
				Length = DATA_SIZE;
			} else {
				Length = LengthBytes;
			}

			/*
			 * Dual stack connection
			 */
			if (QSPI_CONNECTION_MODE == DUAL_STACK_CONNECTION) {
				/*
				 * Get the current LQSPI configuration value
				 */
				LqspiCrReg = XQspiPs_GetLqspiConfigReg(QspiInstancePtr);

				/*
				 * Select lower or upper Flash based on sector address
				 */
				if (SourceAddress >= (QspiFlashSize/2)) {
					/*
					 * Set selection to U_PAGE
					 */
					XQspiPs_SetLqspiConfigReg(QspiInstancePtr,
							LqspiCrReg | XQSPIPS_LQSPI_CR_U_PAGE_MASK);

					/*
					 * Subtract first flash size when accessing second flash
					 */
					SourceAddress = SourceAddress - (QspiFlashSize/2);

					fsbl_printf(DEBUG_INFO, "stacked - upper CS \n\r");

					/*
					 * Assert the FLASH chip select.
					 */
					XQspiPs_SetSlaveSelect(QspiInstancePtr);
				}
			}

			/*
			 * Select bank
			 */
			if ((SourceAddress >= FLASH_SIZE_16MB) && (BankSwitchFlag == 1)) {
				BankSel = SourceAddress/FLASH_SIZE_16MB;

				fsbl_printf(DEBUG_INFO, "Bank Selection %lu\n\r", BankSel);

				Status = SendBankSelect(BankSel);
				if (Status != XST_SUCCESS) {
					fsbl_printf(DEBUG_INFO, "Bank Selection Failed\n\r");
					return XST_FAILURE;
				}

				BankSwitchFlag = 0;
			}

			/*
			 * If data to be read spans beyond the current bank, then
			 * calculate length in current bank else no change in length
			 */
			if (QSPI_CONNECTION_MODE == DUAL_PARALLEL_CONNECTION) {
				/*
				 * In dual parallel mode, check should be for half
				 * the length.
				 */
				if((SourceAddress & BANKMASK) != ((SourceAddress + (Length/2)) & BANKMASK))
				{
					Length = (SourceAddress & BANKMASK) + FLASH_SIZE_16MB - SourceAddress;
					/*
					 * Above length calculated is for single flash
					 * Length should be doubled since dual parallel
					 */
					Length = Length * 2;
					BankSwitchFlag = 1;
				}
			} else {
				if((SourceAddress & BANKMASK) != ((SourceAddress + Length) & BANKMASK))
				{
					Length = (SourceAddress & BANKMASK) + FLASH_SIZE_16MB - SourceAddress;
					BankSwitchFlag = 1;
				}
			}

			/*
			 * Copying the image to local buffer
			 */
			FlashRead(SourceAddress, Length);

			/*
			 * Moving the data from local buffer to DDR destination address
			 */
			memcpy(BufferPtr, &ReadBuffer[DATA_OFFSET + DUMMY_SIZE], Length);

			/*
			 * Updated the variables
			 */
			LengthBytes -= Length;

			/*
			 * For Dual parallel connection address increment should be half
			 */
			if (QSPI_CONNECTION_MODE == DUAL_PARALLEL_CONNECTION) {
				SourceAddress += Length/2;
			} else {
				SourceAddress += Length;
			}

			BufferPtr = (u8*)((u32)BufferPtr + Length);
		}

		/*
		 * Reset Bank selection to zero
		 */
		Status = SendBankSelect(0);
		if (Status != XST_SUCCESS) {
			fsbl_printf(DEBUG_INFO, "Bank Selection Reset Failed\n\r");
			return XST_FAILURE;
		}

		if (QSPI_CONNECTION_MODE == DUAL_STACK_CONNECTION) {

			/*
			 * Reset selection to L_PAGE
			 */
			XQspiPs_SetLqspiConfigReg(QspiInstancePtr,
					LqspiCrReg & (~XQSPIPS_LQSPI_CR_U_PAGE_MASK));

			fsbl_printf(DEBUG_INFO, "stacked - lower CS \n\r");

			/*
			 * Assert the FLASH chip select.
			 */
			XQspiPs_SetSlaveSelect(QspiInstancePtr);
		}
	}

	return XST_SUCCESS;
}



/******************************************************************************
*
* This functions selects the current bank
*
* @param	BankSel is the bank to be selected in the flash device(s).
*
* @return	XST_SUCCESS if bank selected
*			XST_FAILURE if selection failed
* @note		None.
*
******************************************************************************/
u32 SendBankSelect(u8 BankSel)
{
	u32 Status;

	/*
	 * bank select commands for Micron and Spansion are different
	 * Macronix bank select is same as Micron
	 */
	if (QspiFlashMake == MICRON_ID || QspiFlashMake == MACRONIX_ID)	{
		/*
		 * For micron command WREN should be sent first
		 * except for some specific feature set
		 */
		WriteBuffer[COMMAND_OFFSET] = WRITE_ENABLE_CMD;
		Status = XQspiPs_PolledTransfer(QspiInstancePtr, WriteBuffer, NULL,
				WRITE_ENABLE_CMD_SIZE);
		if (Status != XST_SUCCESS) {
			return XST_FAILURE;
		}

		/*
		 * Send the Extended address register write command
		 * written, no receive buffer required
		 */
		WriteBuffer[COMMAND_OFFSET]   = EXTADD_REG_WR;
		WriteBuffer[ADDRESS_1_OFFSET] = BankSel;
		Status = XQspiPs_PolledTransfer(QspiInstancePtr, WriteBuffer, NULL,
				BANK_SEL_SIZE);
		if (Status != XST_SUCCESS) {
			return XST_FAILURE;
		}
	}

	if (QspiFlashMake == SPANSION_ID) {
		WriteBuffer[COMMAND_OFFSET]   = BANK_REG_WR;
		WriteBuffer[ADDRESS_1_OFFSET] = BankSel;

		/*
		 * Send the Extended address register write command
		 * written, no receive buffer required
		 */
		Status = XQspiPs_PolledTransfer(QspiInstancePtr, WriteBuffer, NULL,
				BANK_SEL_SIZE);
		if (Status != XST_SUCCESS) {
			return XST_FAILURE;
		}
	}

	/*
	 * For testing - Read bank to verify
	 */
	if (QspiFlashMake == SPANSION_ID) {
		WriteBuffer[COMMAND_OFFSET]   = BANK_REG_RD;
		WriteBuffer[ADDRESS_1_OFFSET] = 0x00;

		/*
		 * Send the Extended address register write command
		 * written, no receive buffer required
		 */
		Status = XQspiPs_PolledTransfer(QspiInstancePtr, WriteBuffer, ReadBuffer,
				BANK_SEL_SIZE);
		if (Status != XST_SUCCESS) {
			return XST_FAILURE;
		}
	}

	if (QspiFlashMake == MICRON_ID || QspiFlashMake == MACRONIX_ID) {
		WriteBuffer[COMMAND_OFFSET]   = EXTADD_REG_RD;
		WriteBuffer[ADDRESS_1_OFFSET] = 0x00;

		/*
		 * Send the Extended address register write command
		 * written, no receive buffer required
		 */
		Status = XQspiPs_PolledTransfer(QspiInstancePtr, WriteBuffer, ReadBuffer,
				BANK_SEL_SIZE);
		if (Status != XST_SUCCESS) {
			return XST_FAILURE;
		}
	}

	if (ReadBuffer[1] != BankSel) {
		fsbl_printf(DEBUG_INFO, "BankSel %d != Register Read %d\n\r", BankSel,
				ReadBuffer[1]);
		return XST_FAILURE;
	}

	return XST_SUCCESS;
}


// helper functions for supporting QSPI I/O

///*****************************************************************************/
/**
*
* This function switches and keeps QSPI flash in I/O mode
* Call directltly after InitQspi() from within ImageMover.c, this way FIFOs/Queues are empty
*
* @param	 
*
* @return	XST_SUCCESS or XST_FAILURE
*
* @note		None
*
****************************************************************************/

u32 QspiSetIOMode(void)
{
	u32 ConfigReg;
	u32 ConfigBase = QspiInstancePtr->Config.BaseAddress;

	// Print contents of LQSPI CR register before change
	ConfigReg = XQspiPs_GetLqspiConfigReg(QspiInstancePtr);
	fsbl_printf(DEBUG_INFO, "LQSPI Config Register before I/O mode change: 0x%08X\r\n",
		ConfigReg);

	// Disable the controller
	XQspiPs_Disable(QspiInstancePtr);

	// Drop only the linear-mode bit; keep opcode/dummy/two-mem fields intact
	ConfigReg &= ~XQSPIPS_LQSPI_CR_LINEAR_MASK;
	XQspiPs_SetLqspiConfigReg(QspiInstancePtr, ConfigReg);

	// We are no longer using linear addressing; force non-linear flow in QspiAccess
	LinearBootDeviceFlag = 0;

	// Enable the controller
	XQspiPs_Enable(QspiInstancePtr);

	// Print contents of LQSPI CR register after change
	fsbl_printf(DEBUG_INFO, "LQSPI Config Register after I/O mode change: 0x%08X\r\n",
		XQspiPs_GetLqspiConfigReg(QspiInstancePtr));

	return XST_SUCCESS;
}

///*****************************************************************************/
/**
*
* This function should set write enable latch bit (required before page program or sector erases) 
*
* @param	None
*
* @return	XST_SUCCESS or XST_FAILURE
*
* @note		None
*
****************************************************************************/
u32 SendWriteEnable(void)
{
	WriteBuffer[0] = XQSPIPS_FLASH_OPCODE_WREN;

	//set write enable and return success status of command
	u32 Status = XQspiPs_PolledTransfer(QspiInstancePtr, WriteBuffer, NULL, 1);
	if (Status != XST_SUCCESS) 
	{
		return XST_FAILURE;
	}

	// check if Write Enable Latch is set (Bit 1 of Status Register must be 1)
	Status = PollStatusReg(0x02, 0x02);  // Wait until Write Enable Latch bit is set
	if (Status != XST_SUCCESS) 
	{
		fsbl_printf(DEBUG_GENERAL, "Write Enable Latch not set\r\n");
		return XST_FAILURE;
	}
	
	return XST_SUCCESS;
}

///*****************************************************************************/
/**
*
* This function waits after flash write/erase until the device is ready
*
* @param	None
*
* @return	XST_SUCCESS or XST_FAILURE
*
* @note		None
*
****************************************************************************/
u32 WaitForFlashReady(void)
{
    // Check Status Register's WIP bit (bit 0) until it is 0
	u32 Status;
	Status = PollStatusReg(0x00, 0x01);  // Wait until WIP bit is 0
	if (Status != XST_SUCCESS) 
	{
		fsbl_printf(DEBUG_GENERAL, "Flash still not ready\r\n");
		return XST_FAILURE;
	}
    
    return XST_SUCCESS;
}

u32 PollStatusReg(u8 ExpectedValue, u8 Mask)
{
	u32 Status;
	u32 Timeout = 10000;  // Timeout counter
	u8 StatusReg;
	
	do 
	{
		// Read Status Register
		WriteBuffer[0] = 0x05;  // Read Status Register command
		WriteBuffer[1] = 0x00;  // Dummy byte for response
		
		Status = XQspiPs_PolledTransfer(QspiInstancePtr, WriteBuffer, ReadBuffer, 2);
		if (Status != XST_SUCCESS) 
		{
			return XST_FAILURE;
		}
		
		StatusReg = ReadBuffer[1];  // Status register is in second byte
		
		// Check masked bits
		if ((StatusReg & Mask) == ExpectedValue) 
		{
			break;  // Condition met
		}
		
		Timeout--;
	} while (Timeout > 0);
	
	if (Timeout == 0) 
	{
		fsbl_printf(DEBUG_GENERAL, "Flash status register polling timeout\r\n");
		return XST_FAILURE;
	}
	
	return XST_SUCCESS;
}

///*****************************************************************************/
/**
*
* This function erases a subsector (4 KiB) - required before writing a page (256 bytes)
* Erase sets bits to 1, programming can only change bits from 1 to 0
* TODO: May potentially require unlocking subsector-level protection first - don't think this is enabled by default though?
*
* @param	SectorAddress: Address of the sector to erase - must belong to the 4 KiB sectors defined in the flash datasheet

*
* @return	XST_SUCCESS or XST_FAILURE
*
* @note		None
*
****************************************************************************/
u32 EraseSector(u32 SectorAddress) 
{
	u8 iterator;
    u32 Status;
    u32 BankSel = 0;
    
    // For >16MB flash, check if we need bank switching - not required for Arty flash chip but likely for Zedboard and Payload
    if (SectorAddress >= FLASH_SIZE_16MB) 
	{
        BankSel = SectorAddress / FLASH_SIZE_16MB;
        Status = SendBankSelect(BankSel);
        if (Status != XST_SUCCESS) {
            return XST_FAILURE;
        }
        SectorAddress = SectorAddress % FLASH_SIZE_16MB;
    }
    
    // Send Write Enable
    Status = SendWriteEnable();
    if (Status != XST_SUCCESS) 
	{
        fsbl_printf(DEBUG_GENERAL, "Error: Write Enable failed\r\n");
        return XST_FAILURE;
    }
    
    // Send Sector Erase command (4KiB sectors)
    WriteBuffer[COMMAND_OFFSET]   = XQSPIPS_FLASH_OPCODE_BE_4K;  // Sector Erase (4KiB)
    WriteBuffer[ADDRESS_1_OFFSET] = (u8)((SectorAddress >> 16) & 0xFF);
    WriteBuffer[ADDRESS_2_OFFSET] = (u8)((SectorAddress >> 8) & 0xFF);
    WriteBuffer[ADDRESS_3_OFFSET] = (u8)(SectorAddress & 0xFF);
    
    Status = XQspiPs_PolledTransfer(QspiInstancePtr, WriteBuffer, NULL, 4);
    if (Status != XST_SUCCESS) 
	{
		fsbl_printf(DEBUG_GENERAL, "Error: Sector Erase failed\r\n");
        return XST_FAILURE;
    }
    
    // Wait for erase completion - MT25Q spepcific typ 50ms subsector erase time, max 400ms
	fsbl_printf(DEBUG_INFO, "Erasing sector at address 0x%08X\r\n", SectorAddress);
	for (iterator = 0; iterator < 10; iterator++)
	{
		usleep(50000);  // Wait 50ms before polling status
		Status = WaitForFlashReady();
		if (Status == XST_SUCCESS) 
		{
			break;  // Erase completed
		}
	}
    
    if (Status != XST_SUCCESS) 
	{
        return XST_FAILURE;
    }
    
    // Reset bank selection if needed
    if (BankSel > 0) 
	{
        Status = SendBankSelect(0);
    }
    
    return Status;
}


///*****************************************************************************/
/**
*
* This function writes content of WriteBufferPtr array to addressed page (address at start of WriteBufferPtr)
*
* @param	SectorAddress: Address of the sector to erase
*
* @return	XST_SUCCESS or XST_FAILURE
*
* @note		None
*
****************************************************************************/
u32 WritePage(u8 *WriteBufferPtr, u32 BufferSize) 
{
	u8 iterator;
    u32 Status;

	if(BufferSize > 260)
	{
		fsbl_printf(DEBUG_GENERAL, "Error: WritePage buffer size too large\r\n");
		return XST_FAILURE;
	}

    // Send Write Enable
    Status = SendWriteEnable();
    if (Status != XST_SUCCESS) 
	{
        fsbl_printf(DEBUG_GENERAL, "Error: Write Enable failed\r\n");
        return XST_FAILURE;
    }
    
    // First byte of WriteBufferPtr should be Page Program
	WriteBufferPtr[0] = XQSPIPS_FLASH_OPCODE_PP;
    
	fsbl_printf(DEBUG_INFO, "Writing page now\r\n");
    Status = XQspiPs_PolledTransfer(QspiInstancePtr, WriteBufferPtr, NULL, BufferSize);
    if (Status != XST_SUCCESS) 
	{
		fsbl_printf(DEBUG_GENERAL, "Error: Page Program failed\r\n");
        return XST_FAILURE;
    }
    
    // Wait for page program completion - 
	// MT25Q spepcific typ 18 + 2.5 * (NUM_BYTES/6 )ms subsector erase time, max 1800us
	// struct size may change so use max wait time
	for (iterator = 0; iterator < 3; iterator++)
	{
		usleep(1000);  // Wait 1ms before polling status
		Status = WaitForFlashReady();
		if (Status == XST_SUCCESS) 
		{
			break;  // Program completed
		}
	}

    if (Status != XST_SUCCESS) 
	{
        return XST_FAILURE;
    }
    
    return Status;
}

#endif

