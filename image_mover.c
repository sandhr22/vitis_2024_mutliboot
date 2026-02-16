/******************************************************************************
* Copyright (c) 2011 - 2022 Xilinx, Inc.  All rights reserved.
* Copyright (c) 2024 Advanced Micro Devices, Inc. All Rights Reserved.
* SPDX-License-Identifier: MIT
******************************************************************************/

/*****************************************************************************/
/**
*
* @file image_mover.c
*
* Move partitions to either DDR to execute or to program FPGA.
* It performs partition walk.
*
* <pre>
* MODIFICATION HISTORY:
*
* Ver	Who	Date		Changes
* ----- ---- -------- -------------------------------------------------------
* 1.00a jz	05/24/11	Initial release
* 2.00a jz	06/30/11	Updated partition header defs for 64-byte
*			 			alignment change in data2mem tool
* 2.00a mb	05/25/12	Updated for standalone based bsp FSBL
* 			 			Nand/SD encryption and review comments
* 3.00a np	08/30/12	Added FSBL user hook calls
* 						(before and after bitstream download.)
* 4.00a sgd	02/28/13	Fix for CR#691148 Secure bootmode error in devcfg test
*						Fix for CR#695578 FSBL failed to load standalone 
*						application in secure bootmode
*
* 4.00a sgd	04/23/13	Fix for CR#710128 FSBL failed to load standalone 
*						application in secure bootmode
* 5.00a kc	07/30/13	Fix for CR#724165 Partition Header used by FSBL 
*						is not authenticated
* 						Fix for CR#724166 FSBL doesn�t use PPK authenticated 
*						by Boot ROM for authenticating the Partition images 
* 						Fix for CR#732062 FSBL fails to build if UART not 
*						available 
* 7.00a kc  10/30/13    Fix for CR#755245 FSBL does not load partition
*                       if eMMC has only one partition
* 8.00a kc  01/16/13    Fix for CR#767798  FSBL MD5 Checksum failure
* 						for encrypted images
*						Fix for CR#761895 FSBL should authenticate image
*						only if partition owner was not set to u-boot
* 9.00a kc  04/16/14    Fix for CR#785778  FSBL takes 8 seconds to 
* 						authenticate (RSA) a bitstream on zc706
* 10.00a kc 07/15/14	Fix for CR#804595 Zynq FSBL - Issues with
* 						fallback image offset handling using MD5
* 						Fix for PR#782309 Fallback support for AES
* 						encryption with E-Fuse - Enhancement
* 11.00a ka 10/12/18    Fix for CR#1006294 Zynq FSBL - Zynq FSBL does not check
* 						USE_AES_ONLY eFuse
* 12.0  vns 03/18/22    Fixed CR#1125470 to authenticate the parition header buffer
*                       which is being used instead of one from DDR.
*                       Deleted GetImageHeaderAndSignature() and added
*                       GetNAuthImageHeader()
* 21.2  ng  03/09/24   Fix format specifier for 32 bit variables
*
* </pre>
*
* @note
*	A partition is either an executable or a bitstream to program FPGA
*
******************************************************************************/

/***************************** Include Files *********************************/
#include "fsbl.h"
#include "image_mover.h"
#include "xil_printf.h"
#include "xreg_cortexa9.h"
#include "pcap.h"
#include "fsbl_hooks.h"
#include "md5.h"
#include "qspi.h"

#ifdef XPAR_XWDTPS_0_BASEADDR
#include "xwdtps.h"
#endif

#ifdef RSA_SUPPORT
#include "rsa.h"
#include "xil_cache.h"
#include "xilrsa.h"
#endif
/************************** Constant Definitions *****************************/

/* We are 32-bit machine */
#define MAXIMUM_IMAGE_WORD_LEN 0x40000000
#define MD5_CHECKSUM_SIZE   16

/************************** User-Defined Constant Definitions *****************************/
#define FSBL_ADDRESS1 0x8000 // Address in QSPI where FSBL boot image 1 is stored - 32 KiB = 0.25 Mib
#define FSBL_ADDRESS2 0x00030000 // Address in QSPI where FSBL boot image 2 is stored - 192 KiB = 1.5 Mib
#define FSBL_ADDRESS3 0x00058000 // Address in QSPI where FSBL boot image 3 is stored - 352 KiB = 2.75 Mib

#define BITSTREAM_ADDRESS1 0x004C0000 // Address in QSPI where bitstream image 1 is stored - 38 Mib
#define BITSTREAM_ADDRESS2 0x008C0000 // Address in QSPI where bitstream image 2 is stored - 70 Mib

#define APPLICATION_ADDRESS1 0x000C0000 // Address in QSPI where application image A is stored - 6 Mib
#define APPLICATION_ADDRESS2 0x001C0000 // Address in QSPI where application image B is stored - 14 Mib
#define APPLICATION_ADDRESS3 0x002C0000 // Address in QSPI where application image Golden is stored - 22 Mib

#define APP_IMAGE_NUMBER 3 // Number of application images available
#define BITSTREAM_IMAGE_NUMBER 2 // Number of bitstream images available
#define FSBL_IMAGE_NUMBER 3 // Number of FSBL boot images available

#define SLOT_MAGIC_NUMBER 0xA1B2C3D4 // Magic number to for XIP metadata struct

// TODO: Adjust addresses to be at bottom of memory at address 0x0 of flash chip (separate by flash subsector size)
#define SLOT_METADATA_ADDRESS1 0x1000 // Second 4 KiB sector of flash memory
#define SLOT_METADATA_ADDRESS2 0x3000 // Fourth 4 KiB sector of flash memory

#define PAGE_PROGRAM_CMD 0x02 // Page Program command for QSPI flash (equivalent to XQSPIPS_FLASH_OPCODE_PP)
#define COMMAND_OFFSET 0 // command byte in write buffer of XQspiPs_PolledTransfer
#define ADDRESS_1_OFFSET 1 // MSB of address in 16 MB sized QSPI flash chip in XQspiPs_PolledTransfer
#define ADDRESS_2_OFFSET 2 // Middle byte of address
#define ADDRESS_3_OFFSET 3 // LSB of address 
#define WRITE_BUFFER_DATA_OFFSET 4	// start byte for data in write buffer of XQspiPs_PolledTransfer()

#define CHUNK_SIZE		4096 //Max amount of data to move at a time with FlashRead (4KB)

#define BOOT_HDR_CHECKSUM_WORD_COUNT 10 // Number of words in FSBL boot header to calculate checksum over (0x20 to 0x44, checksum at 0x48))
#define BOOT_HDR_SIGNATURE_WORD_OFFSET 1 // second word in boot header checksum word array (address 0x24)
#define BOOT_HDR_START_OFFSET 0x20 // Start offset of boot header checksum calculation
#define BOOT_HDR_SIGNATURE 0x584C4E58 // 'XNLX' signature in FSBL boot header (little endian)
#define BOOT_HDR_FSBL_SOURCE_WORD_OFFSET 4 // Location of FSBL offset from base of boot image (4th word - 0x30)
#define BOOT_HDR_FSBL_LENGTH_WORD_OFFSET 8 // Location of FSBL's Total length (from FSBL_SOURCE_OFFSET to end of image) (8th word - 0x40)

#define SLOT_FSBL_MD5_1 0x0 // Offset of First Copy of FSBL MD5 Checksum
#define SLOT_FSBL_MD5_2 0x2000 // Offset of Second Copy of FSBL MD5 Checksum
#define SLOT_FSBL_MD5_3 0x4000 // Offset of Third Copy of FSBL MD5 Checksum

/**************************** Type Definitions *******************************/

/***************** Macros (Inline Functions) Definitions *********************/

/************************** Function Prototypes ******************************/
u32 ValidateParition(u32 StartAddr, u32 Length, u32 ChecksumOffset);
u32 GetPartitionChecksum(u32 ChecksumOffset, u8 *Checksum);
u32 CalcPartitionChecksum(u32 SourceAddr, u32 DataLength, u8 *Checksum);

/************************** Variable Definitions *****************************/
/*
 * Partition information flags
 */
u8 EncryptedPartitionFlag;
u8 PLPartitionFlag;
u8 PSPartitionFlag;
u8 SignedPartitionFlag;
u8 PartitionChecksumFlag;
u8 BitstreamFlag;
u8 ApplicationFlag;
u8 ExecutionAddressFlag;

u32 ExecutionAddress;
ImageMoverType MoveImage;

/*
 * Header array
 */
PartHeader PartitionHeader[MAX_PARTITION_NUMBER]; // will be redundant in this FSBL implementation (every boot image has 1 partition only)
u32 PartitionCount;
u32 FsblLength;

#ifdef XPAR_XWDTPS_0_BASEADDR
extern XWdtPs Watchdog;	/* Instance of WatchDog Timer	*/
#endif

extern u32 Silicon_Version;
extern u32 FlashReadBaseAddress;
extern u8 LinearBootDeviceFlag;
extern XDcfg *DcfgInstPtr;


// add all logic for METADATA here
// could make fsbl_images into u16 to support up to 16 FSBL boot images
typedef union 
{
    u32 imageStatusWord;  // packed 32-bit view
    struct 
	{
        u8 fsbl_images;      // byte 0 (LSB)
		u8 bitstream_images; // byte 1
        u8 app_images;       // byte 2
        u8 reserved;         // byte 3
    } bytes;
} ImageStatusTable;


/*
TODO: 
1) Add an array of fixed size with part headers for each boot image - separate app, bitstream, fsbl images
2) Validate each image first and have a corresponding struct for indicating if an image is valid or not
3) The target image (for now, the top one) will then run if it is valid
	3a) Check App and Bitstream for checksums in partition header, in partition payload, md5 attribute flag, and PS/PL attribute flag
	3b) Check each FSBL image's boot image entirely (as that is what BOOTROM does)

4) Go following priority of each image (loaded newest -> golden), and load the first valid one
5) Requires LoadAppImage and LoadBitstreamImage to be reworked to just load the image if valid, not validate it
    5a) Or validate one more time before loading - this time, just call the function that validates
*/
///*****************************************************************************/
/**
*
* This function loads both app and bitstream partitions (both partitions separate from FSBL boot image)
*
* @param	 
*
* @return	- Execution address of the application partition
*
* @note		None
*
****************************************************************************/
u32 LoadBootImage(void)
{
	u32 PartitionNum;
	u32 Status;

	u32 FsblImageStartAddress = 0; 
    u32 MultiBootReg = 0;

	u8 FsblChecksum[MD5_CHECKSUM_SIZE];

	//Array of Boot Image Start Addresses
	u32 FsblStartAddress[] = {FSBL_ADDRESS1, FSBL_ADDRESS2, FSBL_ADDRESS3};
	u32 BitstreamStartAddress[] = {BITSTREAM_ADDRESS1, BITSTREAM_ADDRESS2};
	u32 ApplicationStartAddress[] = {APPLICATION_ADDRESS1, APPLICATION_ADDRESS2, APPLICATION_ADDRESS3};

	PartHeader BitstreamHeaders[BITSTREAM_IMAGE_NUMBER];
	PartHeader ApplicationHeaders[APP_IMAGE_NUMBER];

	ImageStatusTable ImageStatus = {0};

	// Resetting the Flags for which partition type is loaded
	BitstreamFlag = 0;
	ApplicationFlag = 0;
	// Resetting execution address flag
	ExecutionAddressFlag = 0;

    MultiBootReg =  XDcfg_ReadReg(DcfgInstPtr->Config.BaseAddr, XDCFG_MULTIBOOT_ADDR_OFFSET);
    fsbl_printf(DEBUG_INFO,"Multiboot Register: 0x%08x\r\n",MultiBootReg);

    //Compute the image start address
    //0x8000 bytes = 256 Kb = 32 KB
    FsblImageStartAddress = (MultiBootReg & PCAP_MBOOT_REG_REBOOT_OFFSET_MASK) * GOLDEN_IMAGE_OFFSET;
	fsbl_printf(DEBUG_INFO,"FSBL Boot Image Start Address: 0x%08x\r\n",FsblImageStartAddress);

	// Ensure QSPI Controller is in I/O mode
	Status = QspiSetIOMode();
	if (Status != XST_SUCCESS)
	{
		fsbl_printf(DEBUG_GENERAL, "QspiSetIOMode Failed\r\n");
	}

	//TODO: Figure out order of images - if golden image is higher in address space or lower!!!!

	// Validate FSBL Boot Images First
	Status = FetchFsblChecksum(FsblChecksum); 
	if (Status != XST_SUCCESS) 
	{
		fsbl_printf(DEBUG_GENERAL, "Fetch FSBL Checksum Failed\r\n");
		return XST_FAILURE; // if FSBL Checksum fetch fails, what should be done???
	}
	for (PartitionNum = 0; PartitionNum < FSBL_IMAGE_NUMBER; PartitionNum++)
	{
		// NOTE: Currently only validating fsbl at offset 0!!!
		fsbl_printf(DEBUG_INFO, "Validating FSBL Boot Image %d at address 0x%08x\r\n", PartitionNum + 1, FsblStartAddress[PartitionNum]);
		Status = ValidateFsblImage(FsblStartAddress[PartitionNum], FsblChecksum); // validate all FBSL boot images (not just partition)
		if (Status != XST_SUCCESS) 
		{
			fsbl_printf(DEBUG_GENERAL, "FSBL Boot Image %d Validation Failed\r\n", PartitionNum + 1);
		}
		else
		{
			fsbl_printf(DEBUG_GENERAL, "FSBL Boot Image %d Validation Successful\r\n", PartitionNum + 1);
			ImageStatus.bytes.fsbl_images |= (1U << PartitionNum); 
		}	
	}

	// Validate Bitstreams
	for (PartitionNum = 0; PartitionNum < BITSTREAM_IMAGE_NUMBER; PartitionNum++)
	{
		fsbl_printf(DEBUG_INFO, "Validating Bitstream Image %d at address 0x%08x\r\n", PartitionNum + 1, BitstreamStartAddress[PartitionNum]);

		Status = ValidatePartitionImage(BitstreamStartAddress[PartitionNum], 0, &(BitstreamHeaders[PartitionNum]));
		if (Status != XST_SUCCESS) 
		{
			fsbl_printf(DEBUG_GENERAL, "Bitstream Image %d Validation Failed\r\n", PartitionNum + 1);
		}
		else
		{
			fsbl_printf(DEBUG_GENERAL, "Bitstream Image %d Validation Successful\r\n", PartitionNum + 1);
			ImageStatus.bytes.bitstream_images |= (1U << PartitionNum);
		}
		
	}

	// Validate Applications
	for (PartitionNum = 0; PartitionNum < APP_IMAGE_NUMBER; PartitionNum++)
	{
		fsbl_printf(DEBUG_INFO, "Validating Application Image %d at address 0x%08x\r\n", PartitionNum + 1, ApplicationStartAddress[PartitionNum]);

		Status = ValidatePartitionImage(ApplicationStartAddress[PartitionNum], 1, &(ApplicationHeaders[PartitionNum]));
		if (Status != XST_SUCCESS) 
		{
			fsbl_printf(DEBUG_GENERAL, "Application Image %d Validation Failed\r\n", PartitionNum + 1);
		}
		else
		{
			fsbl_printf(DEBUG_GENERAL, "Application Image %d Validation Successful\r\n", PartitionNum + 1);
			ImageStatus.bytes.app_images |= (1U << PartitionNum);
		}
		
	}

	fsbl_printf(DEBUG_INFO, "Image Status Words:\r\n");
	fsbl_printf(DEBUG_INFO, "FSBL Status Words:0x%02x\r\n", ImageStatus.bytes.fsbl_images);
	fsbl_printf(DEBUG_INFO, "Bitstream Status Words:0x%02x\r\n", ImageStatus.bytes.bitstream_images);
	fsbl_printf(DEBUG_INFO, "Application Status Words:0x%02x\r\n", ImageStatus.bytes.app_images);

	// Load Bitstream Image First - only 2 images for now
	for (PartitionNum = 0; PartitionNum < BITSTREAM_IMAGE_NUMBER; PartitionNum++)
	{
		fsbl_printf(DEBUG_INFO, "Attempting to Load Bitstream Image %d at address 0x%08x\r\n", PartitionNum + 1, BitstreamStartAddress[PartitionNum]);

		if(ImageStatus.bytes.bitstream_images & (1U << PartitionNum))
		{
			fsbl_printf(DEBUG_GENERAL, "Bitstream Image %d is valid, attempting to load\r\n", PartitionNum + 1);
			Status = LoadBitstreamImage(BitstreamStartAddress[PartitionNum], &(BitstreamHeaders[PartitionNum]));

			if (Status != XST_SUCCESS) 
			{
				fsbl_printf(DEBUG_GENERAL, "Bitstream Image %d Load Failed\r\n", PartitionNum + 1);
				BitstreamFlag = 0; // Reset flag if load failed
				PLPartitionFlag = 0; // Reset flag if load failed
				PartitionChecksumFlag = 0; // Reset flag if load failed
			}
			else
			{
				fsbl_printf(DEBUG_GENERAL, "Bitstream Image %d Load Successful\r\n", PartitionNum + 1);
				break; // Exit for loop if bitstream loaded successfully
			}
		}

		else
		{
			fsbl_printf(DEBUG_GENERAL, "Bitstream Image %d is invalid, skipping load\r\n", PartitionNum + 1);
		}
	}
	

	if (PartitionNum >= BITSTREAM_IMAGE_NUMBER && Status != XST_SUCCESS)
	{
		fsbl_printf(DEBUG_GENERAL, "Bitstream failed to Load, inform CDH\r\n");

        //DO NOT Fallback - see if application still loads
		//With XIP from BRAM, FSBL would not be able to load application if bitstream load fails
		//FsblFallback();
	}

	// Load Application Image Second - only 3 images for now
	for (PartitionNum = 0; PartitionNum < APP_IMAGE_NUMBER; PartitionNum++)
	{
		fsbl_printf(DEBUG_INFO, "Attempting to Load Application Image %d at address 0x%08x\r\n", PartitionNum + 1, ApplicationStartAddress[PartitionNum]);
		if(ImageStatus.bytes.app_images & (1U << PartitionNum))
		{
			fsbl_printf(DEBUG_GENERAL, "Application Image %d is valid, attempting to load\r\n", PartitionNum + 1);
			Status = LoadApplicationImage(ApplicationStartAddress[PartitionNum], &(ApplicationHeaders[PartitionNum]));

			if (Status != XST_SUCCESS) 
			{
				fsbl_printf(DEBUG_GENERAL, "Application Image %d Load Failed\r\n", PartitionNum + 1);
				ApplicationFlag = 0; // Reset flag if load failed
				ExecutionAddressFlag = 0; // Reset flag if load failed
				ExecutionAddress = 0; // Reset execution address if load failed
				PSPartitionFlag = 0; // Reset flag if load failed
				PartitionChecksumFlag = 0; // Reset flag if load failed
			}
			else
			{
				fsbl_printf(DEBUG_GENERAL, "Application Image %d Load Successful\r\n", PartitionNum + 1);
				break; // Exit for loop if application loaded successfully
			}
		}

		else
		{
			fsbl_printf(DEBUG_GENERAL, "Application Image %d is invalid, skipping load\r\n", PartitionNum + 1);
		}
	}

	// If all 3 application images failed to load, then fallback
	if ((PartitionNum >= APP_IMAGE_NUMBER && Status != XST_SUCCESS) || (ExecutionAddressFlag == 0))
	{
		fsbl_printf(DEBUG_GENERAL, "Application failed to Load, inform CDH\r\n");
		FsblFallback(); // will require fallback in this case
		// NOTHING CAN BE DONE IF APPLICATION DOES NOT LOAD
	}

    fsbl_printf(DEBUG_INFO, "Returning execution address 0x%08x\r\n", ExecutionAddress);
	return (ExecutionAddress);
}

///*****************************************************************************/
/**
*
* This function loads the bitstream partition into fabric
*
* @param	 
*
* @return	- XST_SUCCESS or XST_FAILURE
*
* @note		None
*
****************************************************************************/

u32 LoadBitstreamImage(u32 ImageBaseAddress, PartHeader *HeaderPtr)
{
	//HeaderPtr already populated with partition header info
	u32 Status;
	u32 PartitionDataLength;
	u32 PartitionImageLength;
	u32 PartitionTotalSize;
	u32 PartitionAttr;
	u32 PartitionLoadAddr;
	u32 PartitionStartAddr;
	u32 PartitionChecksumOffset;

	// print partition header information
	fsbl_printf(DEBUG_INFO, "Chosen Bitstream's Partition Header Information:\r\n");
	HeaderDump(HeaderPtr);

	// Load partition header information in to local variables (convert words to bytes)
	PartitionDataLength = (HeaderPtr->DataWordLen); //this is in words!!
	PartitionImageLength = (HeaderPtr->ImageWordLen); //this is in words!!
	PartitionAttr = HeaderPtr->PartitionAttr;
	PartitionLoadAddr = HeaderPtr->LoadAddr;	//pcap transfer uses words for load address (this is in words!!)
	PartitionChecksumOffset = (HeaderPtr->CheckSumOffset) << WORD_LENGTH_SHIFT; // now in bytes
	PartitionStartAddr = (HeaderPtr->PartitionStart) << WORD_LENGTH_SHIFT; // now in bytes
	PartitionTotalSize = (HeaderPtr->PartitionWordLen) << WORD_LENGTH_SHIFT; // now in bytes

	//since validation already completed, just set flags accordingly
	PLPartitionFlag = 1;
	PSPartitionFlag = 0;
	BitstreamFlag = 1;
	PartitionChecksumFlag = 1;

	// will not check for encryption/RSA in bitstream
	EncryptedPartitionFlag = 0;
	SignedPartitionFlag = 0;

	//TODO: Change logic below to stream bitstream directly to fabric (or first staging in OCM if needed and moving in chunks)

	// move bitstream to FPGA (or first thru DDR for checksum if needed - will change this behaviour for XIP later)
	// likely stream as chunks to OCM for checksum and if valid, stread to OCM again and pipe to FPGA
	// for now, move entire partition to DDR first, if checksum needed
	Status = PartitionMove(ImageBaseAddress, HeaderPtr);
		if (Status != XST_SUCCESS) 
		{
			fsbl_printf(DEBUG_GENERAL,"PARTITION_MOVE_FAIL\r\n");
			OutputStatus(PARTITION_MOVE_FAIL);
			return XST_FAILURE;
		}

	if (PartitionChecksumFlag && PLPartitionFlag)
	{
		//PL partition loaded in to DDR temporary address for checksum verification
		PartitionStartAddr = DDR_TEMP_START_ADDR;

		// Validate the partition data with checksum
		Status = ValidateParition(PartitionStartAddr, PartitionTotalSize, (ImageBaseAddress + PartitionChecksumOffset));
		if (Status != XST_SUCCESS) {
			fsbl_printf(DEBUG_GENERAL,"PARTITION_CHECKSUM_FAIL\r\n");
			OutputStatus(PARTITION_CHECKSUM_FAIL);
			return XST_FAILURE;
		}

		fsbl_printf(DEBUG_INFO, "Partition Validation Done\r\n");

		// Load bitstream to FPGA (if currently in DDR) - encryption will always be 0
		Status = PcapLoadPartition((u32*)PartitionStartAddr, (u32*)PartitionLoadAddr,
					PartitionImageLength, PartitionDataLength, EncryptedPartitionFlag);

		if (Status != XST_SUCCESS) 
		{
			fsbl_printf(DEBUG_GENERAL,"BITSTREAM_DOWNLOAD_FAIL\r\n");
			OutputStatus(BITSTREAM_DOWNLOAD_FAIL);
			return XST_FAILURE;
		}
	}

	fsbl_printf(DEBUG_INFO, "Bitstream Load Done\r\n");
	return XST_SUCCESS;
}

u32 LoadApplicationImage(u32 ImageBaseAddress, PartHeader *HeaderPtr)
{
	//HeaderPtr already populated with partition header info
	u32 Status;

	// may delete below and access fields directly from HeaderPtr
	u32 PartitionDataLength;
	u32 PartitionImageLength;
	u32 PartitionTotalSize;
	u32 PartitionExecAddr;
	u32 PartitionAttr;
	u32 PartitionLoadAddr;
	u32 PartitionStartAddr;
	u32 PartitionChecksumOffset;


	
	// print partition header information
	fsbl_printf(DEBUG_INFO, "Chosen Application's Partition Header Information:\r\n");
	HeaderDump(HeaderPtr);

	// Load partition header information in to local variables (convert words to bytes)
	PartitionDataLength = (HeaderPtr->DataWordLen) << WORD_LENGTH_SHIFT; // now in bytes
	PartitionImageLength = (HeaderPtr->ImageWordLen) << WORD_LENGTH_SHIFT; // now in bytes
	PartitionExecAddr = HeaderPtr->ExecAddr;
	PartitionAttr = HeaderPtr->PartitionAttr;
	PartitionLoadAddr = HeaderPtr->LoadAddr;
	PartitionChecksumOffset = (HeaderPtr->CheckSumOffset) << WORD_LENGTH_SHIFT; // now in bytes
	PartitionStartAddr = (HeaderPtr->PartitionStart) << WORD_LENGTH_SHIFT; // now in bytes
	PartitionTotalSize = (HeaderPtr->PartitionWordLen) << WORD_LENGTH_SHIFT; // now in bytes

	// since validation already completed, just set flags accordingly
	PSPartitionFlag = 1;
	PLPartitionFlag = 0;
	ApplicationFlag = 1;
	PartitionChecksumFlag = 1;

	// will not check for encryption/RSA in images (app or bitstream)
	EncryptedPartitionFlag = 0;
	SignedPartitionFlag = 0;


	// Continue staging application to DDR Load address for now
	//TODO: Change to load to BRAM eventually

	/*
	* Load address check
	* Loop will break when PS load address zero and partition is
	* un-signed or un-encrypted
	*/
	// Will need to revamp for XIP later
	if ((PSPartitionFlag == 1) && (PartitionLoadAddr < DDR_START_ADDR)) {
		if ((PartitionLoadAddr == 0) &&
				(!((SignedPartitionFlag == 1) ||
						(EncryptedPartitionFlag == 1)))) {
		} else {
			fsbl_printf(DEBUG_GENERAL,
					"INVALID_LOAD_ADDRESS_FAIL, less than DDR_START_ADDR\r\n");
			OutputStatus(INVALID_LOAD_ADDRESS_FAIL);
		}
		return XST_FAILURE;
	}

	if (PSPartitionFlag && (PartitionLoadAddr > DDR_END_ADDR))
	{
		fsbl_printf(DEBUG_GENERAL,
				"INVALID_LOAD_ADDRESS_FAIL, greater than DDR_END_ADDR\r\n");
		OutputStatus(INVALID_LOAD_ADDRESS_FAIL);
		return XST_FAILURE;
	}

	//load execution address of first PS partition
	if (PSPartitionFlag && !ExecutionAddressFlag) {
		ExecutionAddressFlag = 1;
        // for XIP, must set to image address in flash + PartitionExecAddr
		ExecutionAddress = PartitionExecAddr; // LoadAddr and ExecAddr identical unless specified otherwise
	}

	//moves application to DDR Load address - moves to final destination regardless of checksum presence
	Status = PartitionMove(ImageBaseAddress, HeaderPtr);
	if (Status != XST_SUCCESS) 
	{
		fsbl_printf(DEBUG_GENERAL,"PARTITION_MOVE_FAIL\r\n");
		OutputStatus(PARTITION_MOVE_FAIL);
		FsblFallback();
	}

	// Validate partition data with checksum if needed
	if (PartitionChecksumFlag && PSPartitionFlag) 
	{
		PartitionStartAddr = PartitionLoadAddr;
	
		// Validate the partition data with checksum
		// **check if checksum is over entire partition or just data payload**
		Status = ValidateParition(PartitionStartAddr, PartitionTotalSize, (ImageBaseAddress + PartitionChecksumOffset));
		if (Status != XST_SUCCESS) {
			fsbl_printf(DEBUG_GENERAL,"PARTITION_CHECKSUM_FAIL\r\n");
			OutputStatus(PARTITION_CHECKSUM_FAIL);
			return XST_FAILURE;
		}

		fsbl_printf(DEBUG_INFO, "Partition Validation Done\r\n");
	}

	// If we reach here, then application loaded successfully
	fsbl_printf(DEBUG_INFO, "Application Load Done\r\n");
	return XST_SUCCESS;
}

u32 ValidateFsblImage(u32 ImageBaseAddress, u8 *FsblChecksum)
{
	u32 Status;
	u32 BootHeaderChecksum;
	u32 Count;
	u32 PartitionHeaderOffset;
	u32 BootHeaderWords[BOOT_HDR_CHECKSUM_WORD_COUNT + 1]; // +1 for checksum word

	PartHeader LocalHeader; // looks redundant - see if can be removed later

	BootHeaderChecksum = 0;
	PartHeader *HeaderPtr = &LocalHeader;

	Status = MoveImage(ImageBaseAddress + BOOT_HDR_START_OFFSET, BootHeaderWords, (BOOT_HDR_CHECKSUM_WORD_COUNT + 1) << WORD_LENGTH_SHIFT);
	if (Status != XST_SUCCESS) 
	{
		fsbl_printf(DEBUG_GENERAL, "FSBL Boot Header Read Failed\r\n");
		return XST_FAILURE;
	}

	// Check for Boot Header Signature ('XNLX' - 0x584c4e58) at offset 0x24 (little endian)
	if (BootHeaderWords[BOOT_HDR_SIGNATURE_WORD_OFFSET] != BOOT_HDR_SIGNATURE) 
	{
		fsbl_printf(DEBUG_GENERAL, "FSBL Boot Header Signature Invalid\r\n");
		return XST_FAILURE;
	}
	fsbl_printf(DEBUG_INFO, "FSBL Boot Header Signature Valid\r\n");

	// Perform boot header addition checksum validation (from words at offset 0x20 to 0x44(including 0x45-0x47)) - correct inverted checksum at 0x48
	for (Count = 0; Count < BOOT_HDR_CHECKSUM_WORD_COUNT; Count++) {
		// Read the word from the header
		BootHeaderChecksum += BootHeaderWords[Count];
	}

	// Invert checksum, last bit of error checking
	BootHeaderChecksum ^= 0xFFFFFFFF;
	/*
	 * Validate the checksum
	 */
	if (BootHeaderWords[BOOT_HDR_CHECKSUM_WORD_COUNT] != BootHeaderChecksum) 
	{
	    fsbl_printf(DEBUG_GENERAL, "Error: Checksum 0x%8.8lx != 0x%8.8lx\r\n",
			BootHeaderChecksum, BootHeaderWords[BOOT_HDR_CHECKSUM_WORD_COUNT]);
		return XST_FAILURE;
	}
	fsbl_printf(DEBUG_INFO, "FSBL Boot Header Checksum Valid\r\n");

	// Validate FSBL partition header
	// get partition's header table offset (relative to ImageBaseAddress)
	Status = GetPartitionHeaderStartAddr(ImageBaseAddress, &PartitionHeaderOffset);
	if (Status != XST_SUCCESS) 
	{
		fsbl_printf(DEBUG_GENERAL, "Get Header Start Address Failed\r\n");
		OutputStatus(GET_HEADER_INFO_FAIL);
		return XST_FAILURE;
	}

	// Header offset on flash (relative to base of flash memory)
	PartitionHeaderOffset += ImageBaseAddress;

	// Load Partition Header Information to HeaderPtr
	Status = LoadSinglePartitionHeaderInfo(PartitionHeaderOffset, HeaderPtr);
	if (Status != XST_SUCCESS) 
	{
		fsbl_printf(DEBUG_GENERAL, "Load Partition Header Info Failed\r\n");
		OutputStatus(GET_HEADER_INFO_FAIL);
		return XST_FAILURE;
	}

	// print partition header information
	fsbl_printf(DEBUG_INFO, "FSBL Partition Header Info:\r\n");
	HeaderDump(HeaderPtr);

	// Validate partition header
	Status = ValidateHeader(HeaderPtr);
	if (Status != XST_SUCCESS) 
	{
		fsbl_printf(DEBUG_GENERAL, "INVALID_HEADER_FAIL\r\n");
		OutputStatus(INVALID_HEADER_FAIL);
		return XST_FAILURE;
	}
	
	fsbl_printf(DEBUG_INFO, "FSBL Partition Header Valid\r\n");

	// Validate entire boot image with MD5 checksum, fields storing correct MD5 must be at bottom of memory 
	// follow triple modular redundancy to get FSBL checksums
	fsbl_printf(DEBUG_INFO, "Validate entire Boot Image\r\n");
	fsbl_printf(DEBUG_INFO, "FSBL Source Offset from boot image: 0x%08x, FSBL Length: 0x%08x\r\n", BootHeaderWords[BOOT_HDR_FSBL_SOURCE_WORD_OFFSET], BootHeaderWords[BOOT_HDR_FSBL_LENGTH_WORD_OFFSET]);
	Status = ValidateFsblImageMd5(ImageBaseAddress, BootHeaderWords[BOOT_HDR_FSBL_SOURCE_WORD_OFFSET], BootHeaderWords[BOOT_HDR_FSBL_LENGTH_WORD_OFFSET], FsblChecksum);
	if (Status != XST_SUCCESS) 
	{
		fsbl_printf(DEBUG_GENERAL, "FSBL Image MD5 Validation Failed\r\n");
		return XST_FAILURE;
	}

	return XST_SUCCESS;
}

u32 ValidatePartitionImage(u32 ImageBaseAddress, u32 IsApplication, PartHeader *HeaderPtr)
{
	// u32 PartitionDataLength;
	// u32 PartitionImageLength;
	// u32 PartitionTotalSize;
	// u32 PartitionExecAddr;
	// u32 PartitionAttr;
	// u32 PartitionLoadAddr;
	// u32 PartitionStartAddr;
	// u32 PartitionChecksumOffset;
	u32 Status;
	u32 PartitionHeaderOffset;
	u32 PartitionStartAddr;
	u32 PartitionTotalSize;
	u32 PartitionChecksumOffset;

	// get partition's header table offset (relative to ImageBaseAddress)
	
	Status = GetPartitionHeaderStartAddr(ImageBaseAddress, &PartitionHeaderOffset);
	if (Status != XST_SUCCESS) 
	{
		fsbl_printf(DEBUG_GENERAL, "Get Header Start Address Failed\r\n");
		OutputStatus(GET_HEADER_INFO_FAIL);
		return XST_FAILURE;
	}

	// Header offset on flash (relative to base of flash memory)
	PartitionHeaderOffset += ImageBaseAddress;

	// Load Partition Header Information to HeaderPtr
	Status = LoadSinglePartitionHeaderInfo(PartitionHeaderOffset, HeaderPtr);
	if (Status != XST_SUCCESS) 
	{
		fsbl_printf(DEBUG_GENERAL, "Load Partition Header Info Failed\r\n");
		OutputStatus(GET_HEADER_INFO_FAIL);
		return XST_FAILURE;
	}

	// print partition header information
	HeaderDump(HeaderPtr);

	// Validate partition header
	Status = ValidateHeader(HeaderPtr);
	if (Status != XST_SUCCESS) 
	{
		fsbl_printf(DEBUG_GENERAL, "INVALID_HEADER_FAIL\r\n");
		OutputStatus(INVALID_HEADER_FAIL);
		return XST_FAILURE;
	}
	
	// TODO: Only init local variables for what you need, like PartitionAttr, PartitionStartAddr, 
	// PartitionTotalSize, PartitionChecksumOffset
	PartitionStartAddr = (HeaderPtr->PartitionStart) << WORD_LENGTH_SHIFT; // now in bytes
	PartitionStartAddr += ImageBaseAddress; // absolute address in flash

	PartitionChecksumOffset = (HeaderPtr->CheckSumOffset) << WORD_LENGTH_SHIFT; // now in bytes
	PartitionChecksumOffset += ImageBaseAddress; // absolute address in flash

	PartitionTotalSize = (HeaderPtr->PartitionWordLen) << WORD_LENGTH_SHIFT; // now in bytes

	// // Load partition header information in to local variables (convert words to bytes)
	// PartitionDataLength = (HeaderPtr->DataWordLen) << WORD_LENGTH_SHIFT; // now in bytes
	// PartitionImageLength = (HeaderPtr->ImageWordLen) << WORD_LENGTH_SHIFT; // now in bytes
	// PartitionExecAddr = HeaderPtr->ExecAddr;
	// PartitionAttr = HeaderPtr->PartitionAttr;
	// PartitionLoadAddr = HeaderPtr->LoadAddr;

	if (IsApplication)
	{
		// check if partition is PS image
		if (HeaderPtr->PartitionAttr & ATTRIBUTE_PS_IMAGE_MASK)
		{
			fsbl_printf(DEBUG_INFO, "Application\r\n");
		}
		else 
		{
			fsbl_printf(DEBUG_INFO, "Application Mask not set in Application Partition, BAD!\r\n");
			OutputStatus(INVALID_HEADER_FAIL);
			return XST_FAILURE;
		}
	}
	else
	{
		// check if partition is PL image
		if (HeaderPtr->PartitionAttr & ATTRIBUTE_PL_IMAGE_MASK) 
		{
			fsbl_printf(DEBUG_INFO, "Bitstream\r\n");
		}
		else 
		{
			fsbl_printf(DEBUG_INFO, "Bitstream Mask not set in Bitstream Partition, BAD!\r\n");
			OutputStatus(INVALID_HEADER_FAIL);
			return XST_FAILURE;
		}
	}

	// ensure partition has checksum enabled
	// check for partition checksum
	if (HeaderPtr->PartitionAttr & ATTRIBUTE_CHECKSUM_TYPE_MASK) 
	{
		fsbl_printf(DEBUG_INFO, "Checksum Present\r\n");
		PartitionChecksumFlag = 1;
	} 
	else 
	{
		PartitionChecksumFlag = 0;
		fsbl_printf(DEBUG_INFO, "No Checksum Present in Partition, BAD!\r\n");
		OutputStatus(INVALID_HEADER_FAIL);
		return XST_FAILURE;
	}

	// validate partition data with checksum
	Status = ValidateChecksum(PartitionStartAddr, PartitionTotalSize, PartitionChecksumOffset);
	if (Status != XST_SUCCESS) 
	{
		fsbl_printf(DEBUG_GENERAL,"PARTITION_CHECKSUM_FAIL\r\n");
		OutputStatus(PARTITION_CHECKSUM_FAIL);
		return XST_FAILURE;
	}

	fsbl_printf(DEBUG_INFO, "Partition Validation Done Successfully\r\n");
	return XST_SUCCESS;
}

/*****************************************************************************/
/**
*
* This function
*
* @param
*
* @return
*
*
* @note		None
*
****************************************************************************/
u32 LoadBootImage_OLD(void)
{
	u32 RebootStatusRegister = 0;
	u32 MultiBootReg = 0;
	u32 ImageStartAddress = 0;
	u32 PartitionNum;
	u32 PartitionDataLength;
	u32 PartitionImageLength;
	u32 PartitionTotalSize;
	u32 PartitionExecAddr;
	u32 PartitionAttr;
	u32 ExecAddress = 0;
	u32 PartitionLoadAddr;
	u32 PartitionStartAddr;
	u32 PartitionChecksumOffset;
	u8 ExecAddrFlag = 0 ;
	u32 Status;
	PartHeader *HeaderPtr;
	u32 EfuseStatusRegValue;
#ifdef RSA_SUPPORT
	u8 Hash[SHA_VALBYTES];
	u8 *Ac;
#endif
#ifndef FORCE_USE_AES_EXCLUDE
	u32 EncOnly;
#endif
	/*
	 * Resetting the Flags
	 */
	BitstreamFlag = 0;
	ApplicationFlag = 0;

	RebootStatusRegister = Xil_In32(REBOOT_STATUS_REG);
	fsbl_printf(DEBUG_INFO,
			"Reboot status register: 0x%08x\r\n",RebootStatusRegister);

	if (Silicon_Version == SILICON_VERSION_1) {
		/*
		 * Clear out fallback mask from previous run
		 * We start from the first partition again
		 */
		if ((RebootStatusRegister & FSBL_FAIL_MASK) ==
				FSBL_FAIL_MASK) {
			fsbl_printf(DEBUG_INFO,
					"Reboot status shows previous run falls back\r\n");
			RebootStatusRegister &= ~(FSBL_FAIL_MASK);
			Xil_Out32(REBOOT_STATUS_REG, RebootStatusRegister);
		}

		/*
		 * Read the image start address
		 */
		ImageStartAddress = *(u32 *)BASEADDR_HOLDER;
	} else {
		/*
		 * read the multiboot register
		 */
		MultiBootReg =  XDcfg_ReadReg(DcfgInstPtr->Config.BaseAddr,
				XDCFG_MULTIBOOT_ADDR_OFFSET);

		fsbl_printf(DEBUG_INFO,"Multiboot Register: 0x%08x\r\n",MultiBootReg);

		/*
		 * Compute the image start address
		 */
		ImageStartAddress = (MultiBootReg & PCAP_MBOOT_REG_REBOOT_OFFSET_MASK)
									* GOLDEN_IMAGE_OFFSET;
	}

	fsbl_printf(DEBUG_INFO,"Image Start Address: 0x%08x\r\n",ImageStartAddress);

	/*
	 * Get partitions header information
	 */
	// Not required anymore - change this
	Status = GetPartitionHeaderInfo(ImageStartAddress);
	if (Status != XST_SUCCESS) {
		fsbl_printf(DEBUG_GENERAL, "Partition Header Load Failed\r\n");
		OutputStatus(GET_HEADER_INFO_FAIL);
		FsblFallback();
	}

	/*
	 * RSA is not implemented in 1.0 and 2.0
	 * silicon
	 */
	if ((Silicon_Version != SILICON_VERSION_1) &&
			(Silicon_Version != SILICON_VERSION_2)) {
		/*
		 * Read Efuse Status Register
		 */
		EfuseStatusRegValue = Xil_In32(EFUSE_STATUS_REG);
		if (EfuseStatusRegValue & EFUSE_STATUS_RSA_ENABLE_MASK) {
			fsbl_printf(DEBUG_GENERAL,"RSA enabled for Chip\r\n");
#ifdef RSA_SUPPORT
			/*
			 * Set the Ppk
			 */
			SetPpk();

			/*
			 * Read image header table, image headers and partition header
			 * with signature
			 */
			Status = GetNAuthImageHeader(ImageStartAddress);
			if (Status != XST_SUCCESS) {
				fsbl_printf(DEBUG_GENERAL,
						"Header signature verification Failed\r\n");
				OutputStatus(GET_HEADER_INFO_FAIL);
				FsblFallback();
			}
			fsbl_printf(DEBUG_GENERAL,
				"Header authentication is Success\r\n");
#else
			/*
			 * In case user not enabled RSA authentication feature
			 */
			fsbl_printf(DEBUG_GENERAL,"RSA_SUPPORT_NOT_ENABLED_FAIL\r\n");
			OutputStatus(RSA_SUPPORT_NOT_ENABLED_FAIL);
			FsblFallback();
#endif
		}
	}

#ifdef MMC_SUPPORT
	/*
	 * In case of MMC support
	 * boot image preset in MMC will not have FSBL partition
	 */
	PartitionNum = 0;
#else
	/*
	 * First partition header was ignored by FSBL
	 * As it contain FSBL partition information
	 */
	PartitionNum = 1;
#endif

	while (PartitionNum < PartitionCount) {

		fsbl_printf(DEBUG_INFO, "Partition Number: %lu\r\n", PartitionNum);

		HeaderPtr = &PartitionHeader[PartitionNum];

		/*
		 * Print partition header information
		 */
		HeaderDump(HeaderPtr);

		/*
		 * Validate partition header
		 */
		Status = ValidateHeader(HeaderPtr);
		if (Status != XST_SUCCESS) {
			fsbl_printf(DEBUG_GENERAL, "INVALID_HEADER_FAIL\r\n");
			OutputStatus(INVALID_HEADER_FAIL);
			FsblFallback();
		}

		/*
		 * Load partition header information in to local variables
		 */
		PartitionDataLength = HeaderPtr->DataWordLen;
		PartitionImageLength = HeaderPtr->ImageWordLen;
		PartitionExecAddr = HeaderPtr->ExecAddr;
		PartitionAttr = HeaderPtr->PartitionAttr;
		PartitionLoadAddr = HeaderPtr->LoadAddr;
		PartitionChecksumOffset = HeaderPtr->CheckSumOffset;
		PartitionStartAddr = HeaderPtr->PartitionStart;
		PartitionTotalSize = HeaderPtr->PartitionWordLen;

		/*
		 * Partition owner should be FSBL to validate the partition
		 */
		if ((PartitionAttr & ATTRIBUTE_PARTITION_OWNER_MASK) !=
				ATTRIBUTE_PARTITION_OWNER_FSBL) {
			/*
			 * if FSBL is not the owner of partition,
			 * skip this partition, continue with next partition
			 */
			 fsbl_printf(DEBUG_INFO, "Skipping partition %0lx\r\n",
			 							PartitionNum);
			/*
			 * Increment partition number
			 */
			PartitionNum++;
			continue;
		}

		if (PartitionAttr & ATTRIBUTE_PL_IMAGE_MASK) {
			fsbl_printf(DEBUG_INFO, "Bitstream\r\n");
			PLPartitionFlag = 1;
			PSPartitionFlag = 0;
			BitstreamFlag = 1;
			if (ApplicationFlag == 1) {
#ifdef STDOUT_BASEADDRESS
				xil_printf("\r\nFSBL Warning !!!"
						"Bitstream not loaded into PL\r\n");
                xil_printf("Partition order invalid\r\n");
#endif
				break;
			}
		}
		//paritition attribute field indicates if destination for image will be PL/PS depending on image type
		if (PartitionAttr & ATTRIBUTE_PS_IMAGE_MASK) {
			fsbl_printf(DEBUG_INFO, "Application\r\n");
			PSPartitionFlag = 1;
			PLPartitionFlag = 0;
			ApplicationFlag = 1;
		}

		/*
		 * Encrypted partition will have different value
		 * for Image length and data length
		 */
		if (PartitionDataLength != PartitionImageLength) {
			fsbl_printf(DEBUG_INFO, "Encrypted\r\n");
			EncryptedPartitionFlag = 1;
		} else {
			EncryptedPartitionFlag = 0;
		}

#ifndef FORCE_USE_AES_EXCLUDE
		EncOnly = XDcfg_ReadReg(DcfgInstPtr->Config.BaseAddr,
                                XDCFG_STATUS_OFFSET) &
				XDCFG_STATUS_EFUSE_SEC_EN_MASK;
		if ((EncOnly != 0) &&
			(EncryptedPartitionFlag == 0)) {
			fsbl_printf(DEBUG_GENERAL,"EFUSE_SEC_EN bit is set,"
                                        " Encryption is mandatory\r\n");
			OutputStatus(PARTITION_LOAD_FAIL);
			FsblFallback();
		}
#endif
		/*
		 * Check for partition checksum check
		 */
		if (PartitionAttr & ATTRIBUTE_CHECKSUM_TYPE_MASK) {
			fsbl_printf(DEBUG_INFO, "Checksum Present\r\n");
			PartitionChecksumFlag = 1;
		} else {
			PartitionChecksumFlag = 0;
		}

		/*
		 * RSA signature check
		 */
		if (PartitionAttr & ATTRIBUTE_RSA_PRESENT_MASK) {
			fsbl_printf(DEBUG_INFO, "RSA Signed\r\n");
			SignedPartitionFlag = 1;
		} else {
			SignedPartitionFlag = 0;
		}

		/*
		 * Load address check
		 * Loop will break when PS load address zero and partition is
		 * un-signed or un-encrypted
		 */
		if ((PSPartitionFlag == 1) && (PartitionLoadAddr < DDR_START_ADDR)) {
			if ((PartitionLoadAddr == 0) &&
					(!((SignedPartitionFlag == 1) ||
							(EncryptedPartitionFlag == 1)))) {
				break;
			} else {
				fsbl_printf(DEBUG_GENERAL,
						"INVALID_LOAD_ADDRESS_FAIL\r\n");
				OutputStatus(INVALID_LOAD_ADDRESS_FAIL);
				FsblFallback();
			}
		}

		if (PSPartitionFlag && (PartitionLoadAddr > DDR_END_ADDR)) {
			fsbl_printf(DEBUG_GENERAL,
					"INVALID_LOAD_ADDRESS_FAIL\r\n");
			OutputStatus(INVALID_LOAD_ADDRESS_FAIL);
			FsblFallback();
		}

        /*
         * Load execution address of first PS partition
         */
        if (PSPartitionFlag && (!ExecAddrFlag)) {
        	ExecAddrFlag++;
        	ExecAddress = PartitionExecAddr;
        }

		/*
		 * FSBL user hook call before bitstream download
		 */
		if (PLPartitionFlag) {
			Status = FsblHookBeforeBitstreamDload();
			if (Status != XST_SUCCESS) {
				fsbl_printf(DEBUG_GENERAL,"FSBL_BEFORE_BSTREAM_HOOK_FAIL\r\n");
				OutputStatus(FSBL_BEFORE_BSTREAM_HOOK_FAIL);
				FsblFallback();
			}
		}

		/*
		 * Move partitions from boot device
		 */
		Status = PartitionMove(ImageStartAddress, HeaderPtr);
		if (Status != XST_SUCCESS) {
			fsbl_printf(DEBUG_GENERAL,"PARTITION_MOVE_FAIL\r\n");
			OutputStatus(PARTITION_MOVE_FAIL);
			FsblFallback();
		}

		if ((SignedPartitionFlag) || (PartitionChecksumFlag)) {
			if(PLPartitionFlag) {
				/*
				 * PL partition loaded in to DDR temporary address
				 * for authentication and checksum verification
				 */
				PartitionStartAddr = DDR_TEMP_START_ADDR;
			} else {
				PartitionStartAddr = PartitionLoadAddr;
			}

			if (PartitionChecksumFlag) {
				/*
				 * Validate the partition data with checksum
				 */
				Status = ValidateParition(PartitionStartAddr,
						(PartitionTotalSize << WORD_LENGTH_SHIFT),
						ImageStartAddress  +
						(PartitionChecksumOffset << WORD_LENGTH_SHIFT));
				if (Status != XST_SUCCESS) {
					fsbl_printf(DEBUG_GENERAL,"PARTITION_CHECKSUM_FAIL\r\n");
					OutputStatus(PARTITION_CHECKSUM_FAIL);
					FsblFallback();
				}

				fsbl_printf(DEBUG_INFO, "Partition Validation Done\r\n");
			}

			/*
			 * Authentication Partition
			 */
			if (SignedPartitionFlag == 1 ) {
#ifdef RSA_SUPPORT
				Xil_DCacheEnable();
				sha_256((u8 *)PartitionStartAddr,
						((PartitionTotalSize << WORD_LENGTH_SHIFT) -
							RSA_PARTITION_SIGNATURE_SIZE),
						Hash);
				FsblPrintArray(Hash, 32,
						"Partition Hash Calculated");
				Ac = (u8 *)(PartitionStartAddr +
						(PartitionTotalSize << WORD_LENGTH_SHIFT) -
							RSA_SIGNATURE_SIZE);
				Status = AuthenticatePartition((u8*)Ac, Hash);
				if (Status != XST_SUCCESS) {
					Xil_DCacheFlush();
		        	Xil_DCacheDisable();
					fsbl_printf(DEBUG_GENERAL,"AUTHENTICATION_FAIL\r\n");
					OutputStatus(AUTHENTICATION_FAIL);
					FsblFallback();
				}
				fsbl_printf(DEBUG_INFO,"Authentication Done\r\n");
				Xil_DCacheFlush();
                Xil_DCacheDisable();
#else
				/*
				 * In case user not enabled RSA authentication feature
				 */
				fsbl_printf(DEBUG_GENERAL,"RSA_SUPPORT_NOT_ENABLED_FAIL\r\n");
				OutputStatus(RSA_SUPPORT_NOT_ENABLED_FAIL);
				FsblFallback();
#endif
			}

			/*
			 * Decrypt PS partition
			 */
			if (EncryptedPartitionFlag && PSPartitionFlag) {
				Status = DecryptPartition(PartitionStartAddr,
						PartitionDataLength,
						PartitionImageLength);
				if (Status != XST_SUCCESS) {
					fsbl_printf(DEBUG_GENERAL,"DECRYPTION_FAIL\r\n");
					OutputStatus(DECRYPTION_FAIL);
					FsblFallback();
				}
			}

			/*
			 * Load Signed PL partition in Fabric
			 */
			if (PLPartitionFlag) {
				Status = PcapLoadPartition((u32*)PartitionStartAddr,
						(u32*)PartitionLoadAddr,
						PartitionImageLength,
						PartitionDataLength,
						EncryptedPartitionFlag);
				if (Status != XST_SUCCESS) {
					fsbl_printf(DEBUG_GENERAL,"BITSTREAM_DOWNLOAD_FAIL\r\n");
					OutputStatus(BITSTREAM_DOWNLOAD_FAIL);
					FsblFallback();
				}
			}
		}


		/*
		 * FSBL user hook call after bitstream download
		 */
		if (PLPartitionFlag) {
			Status = FsblHookAfterBitstreamDload();
			if (Status != XST_SUCCESS) {
				fsbl_printf(DEBUG_GENERAL,"FSBL_AFTER_BSTREAM_HOOK_FAIL\r\n");
				OutputStatus(FSBL_AFTER_BSTREAM_HOOK_FAIL);
				FsblFallback();
			}
		}
		/*
		 * Increment partition number
		 */
		PartitionNum++;
	}

	return ExecAddress;
}

/*****************************************************************************/
/**
*
* This function loads all partition header information in global array
*
* @param	ImageAddress is the start address of the image
*
* @return	- XST_SUCCESS if Get partition Header information successful
*			- XST_FAILURE if Get Partition Header information failed
*
* @note		None
*
****************************************************************************/
u32 GetPartitionHeaderInfo(u32 ImageBaseAddress)
{
    u32 PartitionHeaderOffset;
    u32 Status;


    /*
     * Get the length of the FSBL from BootHeader
     */
    Status = GetFsblLength(ImageBaseAddress, &FsblLength);
    if (Status != XST_SUCCESS) {
    	fsbl_printf(DEBUG_GENERAL, "Get Header Start Address Failed\r\n");
    	return XST_FAILURE;
    }

    /*
    * Get the start address of the partition header table
    */
    Status = GetPartitionHeaderStartAddr(ImageBaseAddress,
    				&PartitionHeaderOffset);
    if (Status != XST_SUCCESS) {
    	fsbl_printf(DEBUG_GENERAL, "Get Header Start Address Failed\r\n");
    	return XST_FAILURE;
    }

    /*
     * Header offset on flash
     */
    PartitionHeaderOffset += ImageBaseAddress;

    fsbl_printf(DEBUG_INFO,"Partition Header Offset:0x%08x\r\n",
    		PartitionHeaderOffset);

    /*
     * Load all partitions header data in to global variable
     */
    Status = LoadPartitionsHeaderInfo(PartitionHeaderOffset,
    				&PartitionHeader[0]);
    if (Status != XST_SUCCESS) {
    	fsbl_printf(DEBUG_GENERAL, "Header Information Load Failed\r\n");
    	return XST_FAILURE;
    }

    /*
     * Get partitions count from partitions header information
     */
	PartitionCount = GetPartitionCount(&PartitionHeader[0]);

    fsbl_printf(DEBUG_INFO, "Partition Count: %lu\r\n", PartitionCount);

    /*
     * Partition Count check
     */
    if (PartitionCount >= MAX_PARTITION_NUMBER) {
        fsbl_printf(DEBUG_GENERAL, "Invalid Partition Count\r\n");
		return XST_FAILURE;
#ifndef MMC_SUPPORT
    } else if (PartitionCount <= 1) {
        fsbl_printf(DEBUG_GENERAL, "There is no partition to load\r\n");
		return XST_FAILURE;
#endif
	}

    return XST_SUCCESS;
}


/*****************************************************************************/
/**
*
* This function goes to the partition header of the specified partition
*
* @param	ImageAddress is the start address of the image
*
* @return	Offset Partition header address of the image
*
* @return	- XST_SUCCESS if Get Partition Header start address successful
* 			- XST_FAILURE if Get Partition Header start address failed
*
* @note		None
*
****************************************************************************/
u32 GetPartitionHeaderStartAddr(u32 ImageAddress, u32 *Offset)
{
	u32 Status;

	Status = MoveImage(ImageAddress + IMAGE_PHDR_OFFSET, (u32)Offset, 4);
	if (Status != XST_SUCCESS) {
		fsbl_printf(DEBUG_GENERAL,"Move Image failed\r\n");
		return XST_FAILURE;
	}

	return XST_SUCCESS;
}

/*****************************************************************************/
/**
*
* This function goes to the partition header of the specified partition
*
* @param	ImageAddress is the start address of the image
*
* @return	Offset to Image header table address of the image
*
* @return	- XST_SUCCESS if Get Partition Header start address successful
* 			- XST_FAILURE if Get Partition Header start address failed
*
* @note		None
*
****************************************************************************/
u32 GetImageHeaderStartAddr(u32 ImageAddress, u32 *Offset)
{
	u32 Status;

	Status = MoveImage(ImageAddress + IMAGE_HDR_OFFSET, (u32)Offset, 4);
	if (Status != XST_SUCCESS) {
		fsbl_printf(DEBUG_GENERAL,"Move Image failed\r\n");
		return XST_FAILURE;
	}

	return XST_SUCCESS;
}
/*****************************************************************************/
/**
*
* This function gets the length of the FSBL
*
* @param	ImageAddress is the start address of the image
*
* @return	FsblLength is the length of the fsbl
*
* @return	- XST_SUCCESS if fsbl length reading is successful
* 			- XST_FAILURE if fsbl length reading failed
*
* @note		None
*
****************************************************************************/
u32 GetFsblLength(u32 ImageAddress, u32 *FsblLength)
{
	u32 Status;

	Status = MoveImage(ImageAddress + IMAGE_TOT_BYTE_LEN_OFFSET,
							(u32)FsblLength, 4);
	if (Status != XST_SUCCESS) {
		fsbl_printf(DEBUG_GENERAL,"Move Image failed reading FsblLength\r\n");
		return XST_FAILURE;
	}

	return XST_SUCCESS;
}

#ifdef RSA_SUPPORT
/*****************************************************************************/
/**
*
* This function goes to read the image headers and its signature and authenticates.
* the image header Image header consists of image header table, image headers,
* partition headers
*
* @param	ImageBaseAddress is the start address of the image header
*
* @return	- XST_SUCCESS if image header authentication is successful
* 			- XST_FAILURE if image header authentication is failed
*
* @note		None
*
****************************************************************************/
u32 GetNAuthImageHeader(u32 ImageBaseAddress)
{
	u32 Status;
	u32 Offset;
	u8 *HdrTmpPtr = (u8 *) DDR_TEMP_START_ADDR;
	u32 Size;
	u8 *Ac;
	u8 Hash[SHA_VALBYTES];
	sha2_context Sha2Instance;

	/*
	 * Get the start address of the image header table
	 */
	Status = GetImageHeaderStartAddr(ImageBaseAddress, &Offset);
	if (Status != XST_SUCCESS) {
		fsbl_printf(DEBUG_GENERAL, "Get Header Start Address Failed\r\n");
		return XST_FAILURE;
	}
	Size = IMAGE_HEADER_TABLE_SIZE + TOTAL_IMAGE_HEADER_SIZE;
	/* Read image header table and all image headers */
	Status = MoveImage(ImageBaseAddress + Offset, (u32)HdrTmpPtr,
							Size);
	if (Status != XST_SUCCESS) {
		fsbl_printf(DEBUG_GENERAL,"Move IHT and IHs failed\r\n");
		return XST_FAILURE;
	}
	/* Update SHA */
	sha2_starts(&Sha2Instance);
	sha2_update(&Sha2Instance, (u8 *)HdrTmpPtr, Size);
	sha2_update(&Sha2Instance, (u8 *)&PartitionHeader[0],
				TOTAL_PARTITION_HEADER_SIZE);

	/*
	 * Get the start address of the partition header table
	 */
	Status = GetPartitionHeaderStartAddr(ImageBaseAddress, &Offset);
	if (Status != XST_SUCCESS) {
		fsbl_printf(DEBUG_GENERAL, "Get Header Start Address Failed\r\n");
		return XST_FAILURE;
	}
	Offset = Offset + TOTAL_PARTITION_HEADER_SIZE;
	Size = TOTAL_HEADER_SIZE + RSA_SIGNATURE_SIZE - (Size + TOTAL_PARTITION_HEADER_SIZE);

	/* Read RSA signature */
	Status = MoveImage(ImageBaseAddress + Offset, (u32)HdrTmpPtr, Size);
	if (Status != XST_SUCCESS) {
		fsbl_printf(DEBUG_GENERAL,"Move image header signature is failed\r\n");
		return XST_FAILURE;
	}
	sha2_update(&Sha2Instance, (u8 *)(HdrTmpPtr),
				Size - RSA_PARTITION_SIGNATURE_SIZE);
	sha2_finish(&Sha2Instance, Hash);
	FsblPrintArray(Hash, 32,"Header Hash Calculated");

	/* Authentication of image header */
	Ac = (u8 *)(HdrTmpPtr + 64);
	Status = AuthenticatePartition((u8 *)Ac, Hash);
	if (Status != XST_SUCCESS) {
		fsbl_printf(DEBUG_GENERAL,"Image header authentication is failed\r\n");
		return XST_FAILURE;
	}

	return XST_SUCCESS;
}
#endif
/*****************************************************************************/
/**
*
* This function get the header information of the all the partitions and load into
* global array
*
* @param	PartHeaderOffset Offset address where the header information present
*
* @param	Header Partition header pointer
*
* @return	- XST_SUCCESS if Load Partitions Header information successful
*			- XST_FAILURE if Load Partitions Header information failed
*
* @note		None
*
****************************************************************************/
u32 LoadPartitionsHeaderInfo(u32 PartHeaderOffset,  PartHeader *Header)
{
	u32 Status;

	Status = MoveImage(PartHeaderOffset, (u32)Header, sizeof(PartHeader)*MAX_PARTITION_NUMBER);
	if (Status != XST_SUCCESS) {
		fsbl_printf(DEBUG_GENERAL,"Move Image failed\r\n");
		return XST_FAILURE;
	}

	return XST_SUCCESS;
}

u32 LoadSinglePartitionHeaderInfo(u32 PartHeaderOffset,  PartHeader *Header)
{
	u32 Status;

	Status = MoveImage(PartHeaderOffset, (u32)Header, sizeof(PartHeader));
	if (Status != XST_SUCCESS) 
	{
		fsbl_printf(DEBUG_GENERAL,"Move Image failed\r\n");
		return XST_FAILURE;
	}

	return XST_SUCCESS;
}


/*****************************************************************************/
/**
*
* This function dumps the partition header.
*
* @param	Header Partition header pointer
*
* @return	None
*
* @note		None
*
******************************************************************************/
void HeaderDump(PartHeader *Header)
{
	fsbl_printf(DEBUG_INFO, "Header Dump\r\n");
	fsbl_printf(DEBUG_INFO, "Image Word Len: 0x%08x\r\n", Header->ImageWordLen);
	fsbl_printf(DEBUG_INFO, "Data Word Len: 0x%08x\r\n", Header->DataWordLen);
	fsbl_printf(DEBUG_INFO, "Partition Word Len:0x%08x\r\n", Header->PartitionWordLen);
	fsbl_printf(DEBUG_INFO, "Load Addr: 0x%08x\r\n", Header->LoadAddr);
	fsbl_printf(DEBUG_INFO, "Exec Addr: 0x%08x\r\n", Header->ExecAddr);
	fsbl_printf(DEBUG_INFO, "Partition Start: 0x%08x\r\n", Header->PartitionStart);
	fsbl_printf(DEBUG_INFO, "Partition Attr: 0x%08x\r\n", Header->PartitionAttr);
	fsbl_printf(DEBUG_INFO, "Partition Checksum Offset: 0x%08x\r\n", Header->CheckSumOffset);
	fsbl_printf(DEBUG_INFO, "Section Count: 0x%08x\r\n", Header->SectionCount);
	fsbl_printf(DEBUG_INFO, "Checksum: 0x%08x\r\n", Header->CheckSum);
}


/******************************************************************************/
/**
*
* This function calculates the partitions count from header information
*
* @param	Header Partition header pointer
*
* @return	Count Partition count
*
* @note		None
*
*******************************************************************************/
u32 GetPartitionCount(PartHeader *Header)
{
    u32 Count=0;
    struct HeaderArray *Hap;

    for(Count = 0; Count < MAX_PARTITION_NUMBER; Count++) {
        Hap = (struct HeaderArray *)&Header[Count];
        if(IsLastPartition(Hap)!=XST_FAILURE)
            break;
    }

	return Count;
}

/******************************************************************************/
/**
* This function check whether the current partition is the end of partitions
*
* The partition is the end of the partitions if it looks like this:
*	0x00000000
*	0x00000000
*	....
*	0x00000000
*	0x00000000
*	0xFFFFFFFF
*
* @param	H is a pointer to struct HeaderArray
*
* @return
*		- XST_SUCCESS if it is the last partition
*		- XST_FAILURE if it is not last partition
*
****************************************************************************/
u32 IsLastPartition(struct HeaderArray *H)
{
	int Index;

	if (H->Fields[PARTITION_HDR_CHECKSUM_WORD_COUNT] != 0xFFFFFFFF) {
		return	XST_FAILURE;
	}

	for (Index = 0; Index < PARTITION_HDR_WORD_COUNT - 1; Index++) {

        if (H->Fields[Index] != 0x0) {
			return XST_FAILURE;
		}
	}

    return XST_SUCCESS;
}


/******************************************************************************/
/**
*
* This function validates the partition header.
*
* @param	Header Partition header pointer
*
* @return
*		- XST_FAILURE if bad header.
* 		- XST_SUCCESS if successful.
*
* @note		None
*
*******************************************************************************/
u32 ValidateHeader(PartHeader *Header)
{
	struct HeaderArray *Hap;

    Hap = (struct HeaderArray *)Header;

	/*
	 * If there are no partitions to load, fail
	 */
	if (IsEmptyHeader(Hap) == XST_SUCCESS) {
		fsbl_printf(DEBUG_GENERAL, "IMAGE_HAS_NO_PARTITIONS\r\n");
	    return XST_FAILURE;
	}

	/*
	 * Validate partition header checksum
	 */
	if (ValidatePartitionHeaderChecksum(Hap) != XST_SUCCESS) {
		fsbl_printf(DEBUG_GENERAL, "PARTITION_HEADER_CORRUPTION\r\n");
		return XST_FAILURE;
	}

    /*
     * Validate partition data size
     */
	if (Header->ImageWordLen > MAXIMUM_IMAGE_WORD_LEN) {
		fsbl_printf(DEBUG_GENERAL, "INVALID_PARTITION_LENGTH\r\n");
		return XST_FAILURE;
	}

	return XST_SUCCESS;
}


/******************************************************************************/
/**
* This function check whether the current partition header is empty.
* A partition header is considered empty if image word length is 0 and the
* last word is 0.
*
* @param	H is a pointer to struct HeaderArray
*
* @return
*		- XST_SUCCESS , If the partition header is empty
*		- XST_FAILURE , If the partition header is NOT empty
*
* @note		Caller is responsible to make sure the address is valid.
*
*
****************************************************************************/
u32 IsEmptyHeader(struct HeaderArray *H)
{
	int Index;

	for (Index = 0; Index < PARTITION_HDR_WORD_COUNT; Index++) {
		if (H->Fields[Index] != 0x0) {
			return XST_FAILURE;
		}
	}

	return XST_SUCCESS;
}


/******************************************************************************/
/**
*
* This function checks the header checksum If the header checksum is not valid
* XST_FAILURE is returned.
*
* @param	H is a pointer to struct HeaderArray
*
* @return
*		- XST_SUCCESS is header checksum is ok
*		- XST_FAILURE if the header checksum is not correct
*
* @note		None.
*
****************************************************************************/
u32 ValidatePartitionHeaderChecksum(struct HeaderArray *H)
{
	u32 Checksum;
	u32 Count;

	Checksum = 0;

	for (Count = 0; Count < PARTITION_HDR_CHECKSUM_WORD_COUNT; Count++) {
		/*
		 * Read the word from the header
		 */
		Checksum += H->Fields[Count];
	}

	/*
	 * Invert checksum, last bit of error checking
	 */
	Checksum ^= 0xFFFFFFFF;

	/*
	 * Validate the checksum
	 */
	if (H->Fields[PARTITION_HDR_CHECKSUM_WORD_COUNT] != Checksum) {
	    fsbl_printf(DEBUG_GENERAL, "Error: Checksum 0x%8.8lx != 0x%8.8lx\r\n",
			Checksum, H->Fields[PARTITION_HDR_CHECKSUM_WORD_COUNT]);
		return XST_FAILURE;
	}

	return XST_SUCCESS;
}


/******************************************************************************/
/**
*
* This function load the partition from boot device
*
* @param	ImageBaseAddress Base address on flash
* @param	Header Partition header pointer
*
* @return
*		- XST_SUCCESS if partition move successful
*		- XST_FAILURE if check failed move failed
*
* @note		None
*
*******************************************************************************/
u32 PartitionMove(u32 ImageBaseAddress, PartHeader *Header)
{
    u32 SourceAddr;
    u32 Status;
    u8 SecureTransferFlag = 0;
    u32 LoadAddr;
    u32 ImageWordLen;
    u32 DataWordLen;

	SourceAddr = ImageBaseAddress;
	SourceAddr += Header->PartitionStart<<WORD_LENGTH_SHIFT;
	LoadAddr = Header->LoadAddr;
	ImageWordLen = Header->ImageWordLen;
	DataWordLen = Header->DataWordLen;

	/*
	 * Add flash base address for linear boot devices
	 */
	if (LinearBootDeviceFlag) {
		// should be equal to XPS_QSPI_LINEAR_BASEADDR
		SourceAddr += FlashReadBaseAddress;
	}

	/*
	 * Partition encrypted
	 */
	if(EncryptedPartitionFlag) {
		SecureTransferFlag = 1;
	}

	/*
	 * For Signed or checksum enabled partition, 
	 * Total partition image need to copied to DDR
	 */
	if (SignedPartitionFlag || PartitionChecksumFlag) {
		ImageWordLen = Header->PartitionWordLen;
		DataWordLen = Header->PartitionWordLen;
	}

	/*
	 * Encrypted and Signed PS partition need to be loaded on to DDR
	 * without decryption
	 */
	if (PSPartitionFlag &&
			(SignedPartitionFlag || PartitionChecksumFlag) &&
			EncryptedPartitionFlag) {
		SecureTransferFlag = 0;
	}

	/*
	 * CPU is used for data transfer in case of non-linear
	 * boot device
	 */
	if (!LinearBootDeviceFlag) {
		/*
		 * PL partition copied to DDR temporary location
		 */
		if (PLPartitionFlag) {
			LoadAddr = DDR_TEMP_START_ADDR;
		}

		Status = MoveImage(SourceAddr,
						LoadAddr,
						(ImageWordLen << WORD_LENGTH_SHIFT));
		if(Status != XST_SUCCESS) {
			fsbl_printf(DEBUG_GENERAL, "Move Image Failed\r\n");
			return XST_FAILURE;
		}

		/*
		 * As image present at load address
		 */
		SourceAddr = LoadAddr;
	}

	if ((LinearBootDeviceFlag && PLPartitionFlag &&
			(SignedPartitionFlag || PartitionChecksumFlag)) ||
				(LinearBootDeviceFlag && PSPartitionFlag) ||
				((!LinearBootDeviceFlag) && PSPartitionFlag && SecureTransferFlag)) {
		/*
		 * PL signed partition copied to DDR temporary location
		 * using non-secure PCAP for linear boot device
		 */
		if(PLPartitionFlag){
			SecureTransferFlag = 0;
			LoadAddr = DDR_TEMP_START_ADDR;
		}

		/*
		 * Data transfer using PCAP
		 */
		fsbl_printf(DEBUG_INFO, "Starting PCAP Data Transfer\r\n");
		Status = PcapDataTransfer((u32*)SourceAddr,
						(u32*)LoadAddr,
						ImageWordLen,
						DataWordLen,
						SecureTransferFlag);
		if(Status != XST_SUCCESS) {
			fsbl_printf(DEBUG_GENERAL, "PCAP Data Transfer Failed\r\n");
			return XST_FAILURE;
		}

		/*
		 * As image present at load address
		 */
		SourceAddr = LoadAddr;
	}

	/*
	 * Load Bitstream partition in to fabric only
	 * IF checksum and authentication bits are not set
	 */
	if (PLPartitionFlag && (!(SignedPartitionFlag || PartitionChecksumFlag))) {
        fsbl_printf(DEBUG_INFO, "Load Bitstream to FPGA if no checksum\r\n");
		Status = PcapLoadPartition((u32*)SourceAddr,
					(u32*)Header->LoadAddr,
					Header->ImageWordLen,
					Header->DataWordLen,
					EncryptedPartitionFlag);
		if(Status != XST_SUCCESS) {
			fsbl_printf(DEBUG_GENERAL, "PCAP Bitstream Download Failed\r\n");
			return XST_FAILURE;
		}
	}

	return XST_SUCCESS;
}


/******************************************************************************/
/**
*
* This function load the decrypts partition
*
* @param	StartAddr Source start address
* @param	DataLength Data length in words
* @param	ImageLength Image length in words
*
* @return
*		- XST_SUCCESS if decryption successful
*		- XST_FAILURE if decryption failed
*
* @note		None
*
*******************************************************************************/
u32 DecryptPartition(u32 StartAddr, u32 DataLength, u32 ImageLength)
{
	u32 Status;
	u8 SecureTransferFlag =1;

	/*
	 * Data transfer using PCAP
	 */
	Status = PcapDataTransfer((u32*)StartAddr,
					(u32*)StartAddr,
					ImageLength,
					DataLength,
					SecureTransferFlag);
	if (Status != XST_SUCCESS) {
		fsbl_printf(DEBUG_GENERAL,"PCAP Data Transfer failed \r\n");
		return XST_FAILURE;
	}

	return XST_SUCCESS;
}

/******************************************************************************/
/**
*
* This function Validate Partition Data by using checksum preset in image
*
* @param	Partition header pointer
* @param	Partition check sum offset
* @return
*		- XST_SUCCESS if partition data is ok
*		- XST_FAILURE if partition data is corrupted
*
* @note		None
*
*******************************************************************************/
u32 ValidateParition(u32 StartAddr, u32 Length, u32 ChecksumOffset)
{
    u8  Checksum[MD5_CHECKSUM_SIZE];
    u8  CalcChecksum[MD5_CHECKSUM_SIZE];
    u32 Status;
    u32 Index;

#ifdef	XPAR_XWDTPS_0_BASEADDR
	/*
	 * Prevent WDT reset
	 */
	XWdtPs_RestartWdt(&Watchdog);
#endif

    /*
     * Get checksum from flash
     */
    Status = GetPartitionChecksum(ChecksumOffset, &Checksum[0]);
    if(Status != XST_SUCCESS) {
            return XST_FAILURE;
    }

    fsbl_printf(DEBUG_INFO, "Actual checksum\r\n");

    for (Index = 0; Index < MD5_CHECKSUM_SIZE; Index++) {
    	fsbl_printf(DEBUG_INFO, "0x%0x ",Checksum[Index]);
    }

    fsbl_printf(DEBUG_INFO, "\r\n");

    /*
     * Calculate checksum for the partition
     */
    Status = CalcPartitionChecksum(StartAddr, Length, &CalcChecksum[0]);
	if(Status != XST_SUCCESS) {
        return XST_FAILURE;
    }

    fsbl_printf(DEBUG_INFO, "Calculated checksum\r\n");

    for (Index = 0; Index < MD5_CHECKSUM_SIZE; Index++) {
        	fsbl_printf(DEBUG_INFO, "0x%0x ",CalcChecksum[Index]);
    }

    fsbl_printf(DEBUG_INFO, "\r\n");

    /*
     * Compare actual checksum with the calculated checksum
     */
	for (Index = 0; Index < MD5_CHECKSUM_SIZE; Index++) {
        if(Checksum[Index] != CalcChecksum[Index]) {
            fsbl_printf(DEBUG_GENERAL, "Error: "
            		"Partition DataChecksum 0x%0x!= 0x%0x\r\n",
			Checksum[Index], CalcChecksum[Index]);
		    return XST_FAILURE;
        }
    }

    return XST_SUCCESS;
}


/******************************************************************************/
/**
*
* This function gets partition checksum from flash
*
* @param	Check sum offset
* @param	Checksum pointer
* @return
*		- XST_SUCCESS if checksum read success
*		- XST_FAILURE if unable get checksum
*
* @note		None
*
*******************************************************************************/
u32 GetPartitionChecksum(u32 ChecksumOffset, u8 *Checksum)
{
    u32 Status;

    Status = MoveImage(ChecksumOffset, (u32)Checksum, MD5_CHECKSUM_SIZE);
    if(Status != XST_SUCCESS) {
        return XST_FAILURE;
    }

    return XST_SUCCESS;
}


/******************************************************************************/
/**
*
* This function calculates the checksum preset in image
*
* @param 	Start address
* @param 	Length of the data
* @param 	Checksum pointer
*
* @return
*		- XST_SUCCESS if Checksum calculate successful
*		- XST_FAILURE if Checksum calculate failed
*
* @note		None
*
*******************************************************************************/
u32 CalcPartitionChecksum(u32 SourceAddr, u32 DataLength, u8 *Checksum)
{
	/*
	 * Calculate checksum using MD5 algorithm
	 */
	md5((u8*)SourceAddr, DataLength, Checksum, 0 );

    return XST_SUCCESS;
}


/******************************************************************************/
/**
*
* User-defined function to calculate image checksum using MD5 algorithm
* Streams chunks of 4KB data to OCM to hash partition without copying all to active memory
*
* @param 	Start address
* @param 	Length of the data
* @param 	Checksum pointer
*
* @return
*		- XST_SUCCESS if Checksum calculate successful
*		- XST_FAILURE if Checksum calculate failed
*
* @note		None
*
*******************************************************************************/
u32 CalculateMd5(u32 sourceAddr, u32 DataLength, u8 *Checksum)
{
	u32 Status;
	u32 ChunkSize;
	u32 remainingBytes = DataLength;
	u8 Datapiece[CHUNK_SIZE]; // allocate chunk size buffer in OCM

	MD5Context context;

	MD5Init(&context);
	
	while (remainingBytes > 0) {
		ChunkSize = (remainingBytes > CHUNK_SIZE) ? CHUNK_SIZE : remainingBytes;

		// Move chunk from source address to OCM buffer
		Status = MoveImage(sourceAddr, (u32)Datapiece, ChunkSize);
		if (Status != XST_SUCCESS) {
			fsbl_printf(DEBUG_GENERAL, "Move Image failed\r\n");
			return XST_FAILURE;
		}

		// Update MD5 with the chunk data
		MD5Update(&context, Datapiece, ChunkSize, 0);

		sourceAddr += ChunkSize;
		remainingBytes -= ChunkSize;
	}

	fsbl_printf(DEBUG_INFO, "MD5 Calculation Done - remaining bytes = %d\r\n", remainingBytes);

	MD5Final(&context, Checksum, 0);
	return XST_SUCCESS;
}

/******************************************************************************/
/**
*
* This function Validate given Partition/Image by using checksum preset in image
* User-defined version of ValidateParition to use CalculateMd5 function
* @param	Partition header pointer
* @param	Partition check sum offset realtive to flash base address
* @return
*		- XST_SUCCESS if partition data is ok
*		- XST_FAILURE if partition data is corrupted
*
* @note		None
*
*******************************************************************************/

u32 ValidateChecksum(u32 sourceAddr, u32 DataLength, u32 ChecksumOffset)
{
    u8  Checksum[MD5_CHECKSUM_SIZE];
    u8  CalcChecksum[MD5_CHECKSUM_SIZE];
    u32 Status;
    u32 Index;

#ifdef	XPAR_XWDTPS_0_BASEADDR
	/*
	 * Prevent WDT reset
	 */
	XWdtPs_RestartWdt(&Watchdog);
#endif

    /*
     * Get checksum from flash
     */
    Status = GetPartitionChecksum(ChecksumOffset, &Checksum[0]);
    if(Status != XST_SUCCESS) {
            return XST_FAILURE;
    }

    fsbl_printf(DEBUG_INFO, "Actual checksum\r\n");

    for (Index = 0; Index < MD5_CHECKSUM_SIZE; Index++) 
	{
    	fsbl_printf(DEBUG_INFO, "0x%0x ", Checksum[Index]);
    }

    fsbl_printf(DEBUG_INFO, "\r\n");

    /*
     * Calculate checksum for the given data
     */
	Status = CalculateMd5(sourceAddr, DataLength, &CalcChecksum[0]);
	if(Status != XST_SUCCESS) 
	{
        return XST_FAILURE;
    }

    fsbl_printf(DEBUG_INFO, "Calculated checksum\r\n");

    for (Index = 0; Index < MD5_CHECKSUM_SIZE; Index++) 
	{
		fsbl_printf(DEBUG_INFO, "0x%0x ",CalcChecksum[Index]);
    }

    fsbl_printf(DEBUG_INFO, "\r\n");

    /*
     * Compare actual checksum with the calculated checksum
     */
	Status = CompareChecksums(Checksum, CalcChecksum);
	return Status;
}

/******************************************************************************/
/**
*
* This function validates the given FSBL boot image by performing MD5 across entire image 
* MD5 validated against checksum stored at start of flash (decided by triple modular redundancy)
* @param	sourceAddr Start address of the FSBL boot image in flash
* @param	FsblStartAddr Start address of the FSBL relative to the sourceAddr
* @param	FsblLength Length of the FSBL boot image
* @return
*		- XST_SUCCESS if FSBL boot image data is ok
*		- XST_FAILURE if FSBL boot image data is corrupted
*
* @note		None
*
*******************************************************************************/
u32 ValidateFsblImageMd5(u32 sourceAddr, u32 FsblStartAddr, u32 FsblLength, u8 *Checksum)
{
	// u8  Checksum[MD5_CHECKSUM_SIZE];
	u8  CalcChecksum[MD5_CHECKSUM_SIZE];
	u32 Status;
	u32 Index;
	u32 BootImageSize = FsblStartAddr + FsblLength; // total size of an FSBL boot image

	// Get MD5 Checksum of FSBL boot image
	Status = CalculateMd5(sourceAddr, BootImageSize, &CalcChecksum[0]);
	if(Status != XST_SUCCESS) 
	{
        return XST_FAILURE;
    }

    fsbl_printf(DEBUG_INFO, "Calculated boot image checksum\r\n");

	for (Index = 0; Index < MD5_CHECKSUM_SIZE; Index++) 
	{
		fsbl_printf(DEBUG_INFO, "0x%0x ", CalcChecksum[Index]);
    }

    fsbl_printf(DEBUG_INFO, "\r\n");

    /*
     * Compare actual checksum with the calculated checksum
     */
	Status = CompareChecksums(Checksum, CalcChecksum);
	return Status;
}

u32 CompareChecksums(u8 *Checksum1, u8 *Checksum2)
{
	u32 Index;
	for (Index = 0; Index < MD5_CHECKSUM_SIZE; Index++) 
	{
        if(Checksum1[Index] != Checksum2[Index]) 
		{
            fsbl_printf(DEBUG_GENERAL, "Error: Checksum 0x%0x!= 0x%0x\r\n", Checksum1[Index], Checksum2[Index]);
		    return XST_FAILURE;
        }
    }
    return XST_SUCCESS;
}

/******************************************************************************/
/**
*
* This function fetches the 3 checksums stored in flash for validating FSBL boot image
* Triple modular redundancy used to determine checksum value (best 2 of 3)
* @param	Checksum Pointer to the fetched checksum of size MD5_CHECKSUM_SIZE
* @return
*		- XST_SUCCESS if true checksum exists
*		- XST_FAILURE if FSBL boot image checksum corrupted
*
* @note		None
*
*******************************************************************************/
u32 FetchFsblChecksum(u8 *Checksum)
{
//	u8 Checksum[MD5_CHECKSUM_SIZE]; ALLOCATE IN MAIN LOAD BOOT IMAGE FUNCTION
	u32 Status;
	u32 Index;

	u8 FsblChecksumValues[3][MD5_CHECKSUM_SIZE] = {0};
	u32 FsblChecksumSlotAddresses[3] = {SLOT_FSBL_MD5_1, SLOT_FSBL_MD5_2, SLOT_FSBL_MD5_3};

	// fetch the 3 checksum values
	for (Index = 0; Index < 3; Index++) 
	{
		Status = MoveImage(FsblChecksumSlotAddresses[Index], (u32)&FsblChecksumValues[Index][0], MD5_CHECKSUM_SIZE);
		if (Status != XST_SUCCESS) 
		{
			fsbl_printf(DEBUG_GENERAL, "Move Image failed for slot %d\r\n", Index + 1);
		}
	}

	// Print fetched checksum values - delete later!!
	fsbl_printf(DEBUG_INFO, "FSBL Checksum Slot 1:");
	for (Index = 0 ; Index < MD5_CHECKSUM_SIZE; Index++) 
	{
		fsbl_printf(DEBUG_INFO, " 0x%0x ", FsblChecksumValues[0][Index]);
	}
	fsbl_printf(DEBUG_INFO, "\r\n");
	fsbl_printf(DEBUG_INFO, "FSBL Checksum Slot 2:");
	for (Index = 0 ; Index < MD5_CHECKSUM_SIZE; Index++)
	{
		fsbl_printf(DEBUG_INFO, " 0x%0x ", FsblChecksumValues[1][Index]);
	}
	fsbl_printf(DEBUG_INFO, "\r\n");
	fsbl_printf(DEBUG_INFO, "FSBL Checksum Slot 3:");
	for (Index = 0 ; Index < MD5_CHECKSUM_SIZE; Index++) 
	{
		fsbl_printf(DEBUG_INFO, " 0x%0x ", FsblChecksumValues[2][Index]);
	}
	fsbl_printf(DEBUG_INFO, "\r\n");


	// Majority voting to determine the correct checksum value
	if (CompareChecksums(FsblChecksumValues[0], FsblChecksumValues[1]) == XST_SUCCESS) 
	{
		memcpy(Checksum, FsblChecksumValues[0], MD5_CHECKSUM_SIZE);
		fsbl_printf(DEBUG_INFO, "FSBL Checksum values from slot 1 and slot 2 are consistent\r\n");
	} 
	else if (CompareChecksums(FsblChecksumValues[0], FsblChecksumValues[2]) == XST_SUCCESS) 
	{
		memcpy(Checksum, FsblChecksumValues[0], MD5_CHECKSUM_SIZE);
		fsbl_printf(DEBUG_INFO, "FSBL Checksum values from slot 1 and slot 3 are consistent\r\n");
	} 
	else if (CompareChecksums(FsblChecksumValues[1], FsblChecksumValues[2]) == XST_SUCCESS) 
	{
		memcpy(Checksum, FsblChecksumValues[1], MD5_CHECKSUM_SIZE);
		fsbl_printf(DEBUG_INFO, "FSBL Checksum values from slot 2 and slot 3 are consistent\r\n");
	} 
	else 
	{
		fsbl_printf(DEBUG_GENERAL, "FSBL Checksum values are inconsistent\r\n");
		return XST_FAILURE;
	}

	return XST_SUCCESS;
}