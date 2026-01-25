/******************************************************************************
* Copyright (c) 2012 - 2020 Xilinx, Inc.  All rights reserved.
* SPDX-License-Identifier: MIT
******************************************************************************/

/*****************************************************************************/
/**
*
* @file image_mover.h
*
* This file contains the interface for moving the image from FLASH to OCM

*
* <pre>
* MODIFICATION HISTORY:
*
* Ver	Who	Date		Changes
* ----- ---- -------- -------------------------------------------------------
* 1.00a jz	03/04/11	Initial release
* 2.00a jz	06/04/11	partition header expands to 12 words
* 5.00a kc	07/30/13	Added defines for image header information
* 8.00a kc	01/16/13	Added defines for partition owner attribute
* 9.0   vns	03/21/22	Deleted GetImageHeaderAndSignature() and added
*				GetNAuthImageHeader()
* </pre>
*
* @note
*
******************************************************************************/
#ifndef ___IMAGE_MOVER_H___
#define ___IMAGE_MOVER_H___


#ifdef __cplusplus
extern "C" {
#endif

/***************************** Include Files *********************************/
#include "fsbl.h"

/************************** Constant Definitions *****************************/
#define PARTITION_NUMBER_SHIFT	24
#define MAX_PARTITION_NUMBER	(0xE)

/* Boot Image Header defines */
#define IMAGE_HDR_OFFSET			0x098	/* Start of image header table */
#define IMAGE_PHDR_OFFSET			0x09C	/* Start of partition headers */
#define IMAGE_HEADER_SIZE			(64)
#define IMAGE_HEADER_TABLE_SIZE		(64)
#define TOTAL_PARTITION_HEADER_SIZE	(MAX_PARTITION_NUMBER * IMAGE_HEADER_SIZE)
#define TOTAL_IMAGE_HEADER_SIZE		(MAX_PARTITION_NUMBER * IMAGE_HEADER_SIZE)
#define TOTAL_HEADER_SIZE			(IMAGE_HEADER_TABLE_SIZE + \
									 TOTAL_IMAGE_HEADER_SIZE + \
									 TOTAL_PARTITION_HEADER_SIZE + 64)

/* Partition Header defines */
#define PARTITION_IMAGE_WORD_LEN_OFFSET	0x00	/* Word length of image */
#define PARTITION_DATA_WORD_LEN_OFFSET	0x04	/* Word length of data */
#define PARTITION_WORD_LEN_OFFSET		0x08	/* Word length of partition */
#define PARTITION_LOAD_ADDRESS_OFFSET	0x0C	/* Load addr in DDR	*/
#define PARTITION_EXEC_ADDRESS_OFFSET	0x10	/* Addr to start executing */
#define PARTITION_ADDR_OFFSET			0x14	/* Partition word offset */
#define PARTITION_ATTRIBUTE_OFFSET		0x18	/* Partition type */
#define PARTITION_HDR_CHECKSUM_OFFSET	0x3C	/* Header Checksum offset */
#define PARTITION_HDR_CHECKSUM_WORD_COUNT 0xF	/* Checksum word count */
#define PARTITION_HDR_WORD_COUNT		0x10	/* Header word len */
#define PARTITION_HDR_TOTAL_LEN			0x40	/* One partition hdr length*/

/* Attribute word defines */
#define ATTRIBUTE_IMAGE_TYPE_MASK		0xF0	/* Destination Device type */
#define ATTRIBUTE_PS_IMAGE_MASK			0x10	/* Code partition */
#define ATTRIBUTE_PL_IMAGE_MASK			0x20	/* Bit stream partition */
#define ATTRIBUTE_CHECKSUM_TYPE_MASK	0x7000	/* Checksum Type */
#define ATTRIBUTE_RSA_PRESENT_MASK		0x8000	/* RSA Signature Present */
#define ATTRIBUTE_PARTITION_OWNER_MASK	0x30000	/* Partition Owner */

#define ATTRIBUTE_PARTITION_OWNER_FSBL	0x00000	/* FSBL Partition Owner */

//TODO: Should a boot image header checksum be performed????
// Don't see how it adds value, since each partition header and the payload is checksummed

/**************************** Type Definitions *******************************/
typedef u32 (*ImageMoverType)( u32 SourceAddress,
				u32 DestinationAddress,
				u32 LengthBytes);

typedef struct StructPartHeader {
	u32 ImageWordLen;	/* 0x0 */	// length of the ENCRYPTED image in words
	u32 DataWordLen;	/* 0x4 */	// length of the DECRYPTED data in words (should be same as image won't be encrypted)
	u32 PartitionWordLen;	/* 0x8 */	// length of the partition in words (includes header, image, padding) (if no encryption or authentication, should be same as the above two)
	u32 LoadAddr;		/* 0xC */	// Load addr with respect to DDR
	u32 ExecAddr;		/* 0x10 */ 	// Addr to start executing (with respect to DDR???)
	u32 PartitionStart;	/* 0x14 */ // Partition start offset (in words) with respect to start of bootimage
	u32 PartitionAttr;	/* 0x18 */	// Partition attributes like destination device (PS/PL), checksum type, RSA present etc.
	u32 SectionCount;	/* 0x1C */	//Number of loadable sections in this partition
	u32 CheckSumOffset;	/* 0x20 */	// Offset to checksum in words of the partition image
	u32 Pads1[1];
	u32 ACOffset;	/* 0x28 */	//word offset to the RSA signature/authentication code
	u32 Pads2[4];
	u32 CheckSum;		/* 0x3C */	// Header Checksum (for 15 words above)
}PartHeader;

struct HeaderArray {
	u32 Fields[16]; 
};

/**************************** User-Defined Type Definitions *******************************/
typedef struct {
	u32 MagicNumber; 
	u32 ImageStatus; // use union to represent ImageStatus bits!
	u32 ActiveApp; // use another (or same) union to represent ActiveApp bits
	u8 MD5CheckSum[16];	// MD5_CHECKSUM_SIZE
} XipMetaData;


/***************** Macros (Inline Functions) Definitions *********************/
#define MoverIn32		Xil_In32
#define MoverOut32		Xil_Out32

/************************** Function Prototypes ******************************/
u32 LoadBootImage_OLD(void);
u32 GetPartitionHeaderInfo(u32 ImageBaseAddress);
u32 PartitionMove(u32 ImageBaseAddress, PartHeader *Header);
u32 ValidatePartitionHeaderChecksum(struct HeaderArray *H);
u32 GetPartitionHeaderStartAddr(u32 ImageAddress, u32 *Offset);
u32 GetNAuthImageHeader(u32 ImageAddress);
u32 GetFsblLength(u32 ImageAddress, u32 *FsblLength);
u32 LoadPartitionsHeaderInfo(u32 PartHeaderOffset,  PartHeader *Header);
u32 IsEmptyHeader(struct HeaderArray *H);
u32 IsLastPartition(struct HeaderArray *H);
void HeaderDump(PartHeader *Header);
u32 GetPartitionCount(PartHeader *Header);
u32 ValidateHeader(PartHeader *Header);
u32 DecryptPartition(u32 StartAddr, u32 DataLength, u32 ImageLength);

/************************** User-Defined Function Prototypes ******************************/
u32 LoadBootImage(void);
u32 LoadBitstreamImage(u32 ImageBaseAddress);
u32 LoadApplicationImage(u32 ImageBaseAddress);
u32 LoadSinglePartitionHeaderInfo(u32 PartHeaderOffset,  PartHeader *Header);

u32 WriteXipMetadata(u32 Address, XipMetaData *MetaDataInstance);
u32 UpdateMetaData(XipMetaData *MetaDataInstance); // first complete checksum with new fields and then update both metadata locations
u32 CheckMetaData(XipMetaData *MetaDataInstance); // check metadata struct for correct checksum and magic number

//TODO: Pass ImageStartAddress and partition header info to the 
u32 ValidatePartitionImage(u32 ImageBaseAddress, u32 IsApplication, u32 isBootloader); //decouple the validation from final image loading
																					//always fail an image if not valid or doesn't contain md5 flag or app/bitstream flag
u32 ValidateFsblImage(u32 ImageAddress); // validate all FBSL boot images, including their bootheaders. 
									     // either perform a similar validation structure, checking partition image/header along with bootheader
										// or check to see if each image is a duplicate of the current image that was picked by BOOTROM (and is in OCM)

u32 CalculateMd5(u32 SourceAddr, u32 DataLength, u8 *Checksum);
u32 ValidateChecksum(u32 sourceAddr, u32 DataLength, u32 ChecksumOffset)

/************************** Variable Definitions *****************************/

#ifdef __cplusplus
}
#endif


#endif /* ___IMAGE_MOVER_H___ */




