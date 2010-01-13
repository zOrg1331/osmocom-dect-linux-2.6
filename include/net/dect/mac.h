/*
 * DECT MAC Layer - Header and global definitions
 *
 * Copyright (c) 2009 Patrick McHardy <kaber@trash.net>
 */

#ifndef _NET_DECT_MAC_H
#define _NET_DECT_MAC_H

#include <net/dect/identities.h>

/*
 * A-Field
 */

#define DECT_A_FIELD_SIZE	8

#define DECT_RA_FIELD_SIZE	2
#define DECT_RA_FIELD_OFF	6

/*
 * Header field
 */

#define DECT_HDR_FIELD_SIZE	1
#define DECT_HDR_FIELD_OFF	0

#define DECT_HDR_TA_OFF		0
#define DECT_HDR_TA_MASK	0xe0
#define DECT_HDR_TA_SHIFT	5

#define DECT_HDR_Q1_OFF		0
#define DECT_HDR_Q1_FLAG	0x10

#define DECT_HDR_BA_OFF		0
#define DECT_HDR_BA_MASK	0x0e
#define DECT_HDR_BA_SHIFT	1

#define DECT_HDR_Q2_OFF		0
#define DECT_HDR_Q2_FLAG	0x01

/*
 * T-Field
 */

#define DECT_T_FIELD_OFF	1
#define DECT_T_FIELD_SIZE	5

/**
 * dect_tail_identification - MAC layer T-Field identification
 *
 * @DECT_TI_CT_PKT_0:		C_T data packet number 0
 * @DECT_TI_CT_PKT_1:		C_T data packet number 1
 * @DECT_TI_NT_CL:		Identities information on connectionless bearer
 * @DECT_TI_NT:			Identities information
 * @DECT_TI_QT:			Multiframe synchronisation und system information
 * @DECT_TI_RESERVED:		Reserved
 * @DECT_TI_MT:			MAC layer control
 * @DECT_TI_PT:			Paging tail (RFP only)
 * @DECT_TI_MT_PKT_0:		MAC layer control (first PP transmission, PP only)
 */
enum dect_tail_identifications {
	DECT_TI_CT_PKT_0	= 0x0 << DECT_HDR_TA_SHIFT,
	DECT_TI_CT_PKT_1	= 0x1 << DECT_HDR_TA_SHIFT,
	DECT_TI_NT_CL		= 0x2 << DECT_HDR_TA_SHIFT,
	DECT_TI_NT		= 0x3 << DECT_HDR_TA_SHIFT,
	DECT_TI_QT		= 0x4 << DECT_HDR_TA_SHIFT,
	DECT_TI_RESERVED	= 0x5 << DECT_HDR_TA_SHIFT,
	DECT_TI_MT		= 0x6 << DECT_HDR_TA_SHIFT,
	DECT_TI_PT		= 0x7 << DECT_HDR_TA_SHIFT,
	DECT_TI_MT_PKT_0	= 0x7 << DECT_HDR_TA_SHIFT,
};

struct dect_skb_a_cb {
	enum dect_tail_identifications	id;
};

#define DECT_A_CB(skb)		((struct dect_skb_a_cb *)(skb)->cb)

/*
 * Identities channel (N-channel)
 */

/* Identities information */
#define DECT_NT_ID_RFPI_LEN	5

/**
 * @e:		indicates whether SARIs are available
 * @pari:	primary access rights identifier
 * @rpn:	radio part number
 */
struct dect_idi {
	bool		e;
	struct dect_ari	pari;
	u8		rpn;
};

/*
 * System information and multiframe marker (Q-channel)
 */

/* RFP Q-channel T-MUX rules: only frame 8 */
#define DECT_Q_CHANNEL_FRAME	8

/* System information header */
#define DECT_QT_H_MASK		0xf000000000000000ULL
#define DECT_QT_H_SHIFT		60

/**
 * dect_system_information_types - codes for system information messages
 *
 * @DECT_QT_SI_SSI:		static system information
 * @DECT_QT_SI_ERFC:		extended RF carriers
 * @DECT_QT_SI_FPC:		fixed part capabilities
 * @DECT_QT_SI_EFPC:		extended fixed part capabilities
 * @DECT_QT_SI_SARI:		SARI list contents
 * @DECT_QT_SI_MFN:		multi-frame number
 * @DECT_QT_SI_ESC:		escape
 * @DECT_QT_SI_ERFC2:		extended RF carriers part 2
 * @DECT_QT_SI_TXI		transmit information
 * @DECT_QT_SI_EFPC2:		extended fixed part capabilities part 2
 */
enum dect_mac_system_information_types {
	DECT_QT_SI_SSI		= 0x0ULL << DECT_QT_H_SHIFT,
	DECT_QT_SI_SSI2		= 0x1ULL << DECT_QT_H_SHIFT,
	DECT_QT_SI_ERFC		= 0x2ULL << DECT_QT_H_SHIFT,
	DECT_QT_SI_FPC		= 0x3ULL << DECT_QT_H_SHIFT,
	DECT_QT_SI_EFPC		= 0x4ULL << DECT_QT_H_SHIFT,
	DECT_QT_SI_SARI		= 0x5ULL << DECT_QT_H_SHIFT,
	DECT_QT_SI_MFN		= 0x6ULL << DECT_QT_H_SHIFT,
	DECT_QT_SI_ESC		= 0x7ULL << DECT_QT_H_SHIFT,
	DECT_QT_SI_ERFC2	= 0x9ULL << DECT_QT_H_SHIFT,
	DECT_QT_SI_TXI		= 0xbULL << DECT_QT_H_SHIFT,
	DECT_QT_SI_EFPC2	= 0xcULL << DECT_QT_H_SHIFT,
};

/*
 * Static system information - repeated every 8 multiframes
 */

#define DECT_QT_SSI_FREQ	8

/* normal reverse */
#define DECT_QT_SSI_NR_FLAG	0x1000000000000000ULL

/* slot number */
#define DECT_QT_SSI_SN_MASK	0x0f00000000000000ULL
#define DECT_QT_SSI_SN_SHIFT	56

/* start position */
#define DECT_QT_SSI_SP_MASK	0x00c0000000000000ULL
#define DECT_QT_SSI_SP_SHIFT	54

/* escape bit */
#define DECT_QT_SSI_ESC_FLAG	0x0020000000000000ULL

/* number of transceivers */
#define DECT_QT_SSI_TXS_MASK	0x0018000000000000ULL
#define DECT_QT_SSI_TXS_SHIFT	51

/* extended RF carrier information available */
#define DECT_QT_SSI_MC_FLAG	0x0004000000000000ULL

/* RF carriers available */
#define DECT_QT_SSI_RFCARS_MASK	0x0003ff0000000000ULL
#define DECT_QT_SSI_RFCARS_SHIFT 40

/* carrier number */
#define DECT_QT_SSI_CN_MASK	0x0000003f00000000ULL
#define DECT_QT_SSI_CN_SHIFT	32

/* primary scan carrier number */
#define DECT_QT_SSI_PSCN_MASK	0x000000003f000000ULL
#define DECT_QT_SSI_PSCN_SHIFT	24

struct dect_ssi {
	bool	nr;
	bool	mc;
	u16	rfcars;
	u8	sn;
	u8	sp;
	u8	txs;
	u8	cn;
	u8	pscn;
};

/*
 * Extended RF carrier information
 */

#define DECT_QT_ERFC_FREQ		8

#define DECT_QT_ERFC_RFCARS_MASK 	0x0fffffe000000000ULL
#define DECT_QT_ERFC_RFCARS_SHIFT	9

#define DECT_QT_ERFC_RFBAND_MASK	0x0000001f00000000ULL
#define DECT_QT_ERFC_RFBAND_SHIFT	32

#define DECT_QT_ERFC_ERFC2_FLAG		0x0000000080000000ULL

#define DECT_QT_ERFC_NUM_RFCARS_MASK	0x000000003f000000ULL
#define DECT_QT_ERFC_NUM_RFCARS_SHIFT	24

struct dect_erfc {
	u32	rfcars;
	u8	band;
	u8	num_rfcars;
	bool	erfc2;
};

/*
 * Fixed Part capabilities
 */

#define DECT_QT_FPC_FREQ		8

#define DECT_QT_FPC_CAPABILITY_MASK	0x0fffff0000000000ULL
#define DECT_QT_FPC_CAPABILITY_SHIFT	40

#define DECT_QT_FPC_HLC_MASK		0x000000ffff000000ULL
#define DECT_QT_FPC_HLC_SHIFT		24

struct dect_fpc {
	u32	fpc;
	u16	hlc;
};

/*
 * Extended Fixed Part capabilities
 */

#define DECT_QT_EFPC_EFPC_MASK		0x0fff800000000000ULL
#define DECT_QT_EFPC_EFPC_SHIFT		47

#define DECT_QT_EFPC_EHLC_MASK		0x00007fffff000000ULL
#define DECT_QT_EFPC_EHLC_SHIFT		24

struct dect_efpc {
	u16	fpc;
	u32	hlc;
};

#define DECT_QT_EFPC2_FPC_MASK		0x0fff000000000000ULL
#define DECT_QT_EFPC2_FPC_SHIFT		48

#define DECT_QT_EFPC2_HLC_MASK		0x0000ffffff000000ULL
#define DECT_QT_EFPC2_HLC_SHIFT		24

struct dect_efpc2 {
	u16	fpc;
	u32	hlc;
};

/*
 * SARI message
 */

#define DECT_QT_SARI_FREQ		4

#define DECT_QT_SARI_LIST_CYCLE_MASK	0x000e000000000000ULL
#define DECT_QT_SARI_LIST_CYCLE_SHIFT	49

#define DECT_QT_SARI_TARI_FLAG		0x0001000000000000ULL

#define DECT_QT_SARI_BLACK_FLAG		0x0000800000000000ULL

#define DECT_QT_SARI_ARI_MASK		0x00007fffffff0000ULL
#define DECT_QT_SARI_ARI_SHIFT		17

struct dect_sari {
	u8		list_cycle;
	bool		tari;
	bool		black;
	struct dect_ari	ari;
};

#define DECT_SARI_CYCLE_MAX		16

/*
 * Multiframe number - repeated every 8 multiframes if supported
 */

#define DECT_QT_MFN_FREQ		8

#define DECT_QT_MFN_MASK		0x0000ffffff000000ULL
#define DECT_QT_MFN_SHIFT		24

struct dect_mfn {
	u32	num;
};

/*
 * Extended RF carrier information part 2
 */

#define DECT_QT_TXI_ERFC2_FREQ		8

#define DECT_QT_ERFC2_RFCARS_MASK	0x0fffffffe0000000ULL
#define DECT_QT_ERFC2_RFCARS_SHIFT	29

struct dect_erfc2 {
	u32	rfcars;
};

/*
 * Transmit Information
 */

#define DECT_QT_TXI_FREQ		8

#define DECT_QT_TXI_TYPE_MASK		0x0f00000000000000ULL
#define DECT_QT_TXI_TYPE_SHIFT		56

#define DECT_QT_TXI_PWL_MASK		0x00ff000000000000ULL
#define DECT_QT_TXI_PWL_SHIFT		48

/*
 * Extended fixed part capabilitiees part 2
 */

/*
 * Paging Tail (P-channel)
 */

#define DECT_PT_HDR_EXTEND_FLAG		0x8000000000000000ULL

#define DECT_PT_HDR_LENGTH_MASK		0x7000000000000000ULL
#define DECT_PT_HDR_LENGTH_SHIFT	60

/**
 * @DECT_PT_ZERO_PAGE:		zero length page
 * @DECT_PT_SHORT_PAGE:		short page
 * @DECT_PT_FULL_PAGE:		full page
 * @DECT_PT_MAX_RESUME_PAGE:	MAC resume and control page
 * @DECT_PT_LONG_PAGE:		not the last 36 bits of a long page
 * @DECT_PT_LONG_PAGE_FIRST:	the first 36 bits of a long page
 * @DECT_PT_LONG_PAGE_LAST:	the last 36 bits of a long page
 * @DECT_PT_LONG_PAGE_ALL:	all of a long page (first and last)
 *
 */
enum dect_page_lengths {
	DECT_PT_ZERO_PAGE		= 0x0ULL << DECT_PT_HDR_LENGTH_SHIFT,
	DECT_PT_SHORT_PAGE		= 0x1ULL << DECT_PT_HDR_LENGTH_SHIFT,
	DECT_PT_FULL_PAGE		= 0x2ULL << DECT_PT_HDR_LENGTH_SHIFT,
	DECT_PT_RESUME_PAGE		= 0x3ULL << DECT_PT_HDR_LENGTH_SHIFT,
	DECT_PT_LONG_PAGE		= 0x4ULL << DECT_PT_HDR_LENGTH_SHIFT,
	DECT_PT_LONG_PAGE_FIRST		= 0x5ULL << DECT_PT_HDR_LENGTH_SHIFT,
	DECT_PT_LONG_PAGE_LAST		= 0x6ULL << DECT_PT_HDR_LENGTH_SHIFT,
	DECT_PT_LONG_PAGE_ALL		= 0x7ULL << DECT_PT_HDR_LENGTH_SHIFT,
};

/* zero length pages */
#define DECT_PT_ZP_RFPI_MASK		0x0fffff0000000000ULL
#define DECT_PT_ZP_RFPI_SHIFT		40

/* short page B_S channel data */
#define DECT_PT_SP_BS_DATA_MASK		0x0fffff0000000000ULL
#define DECT_PT_SP_BS_DATA_SHIFT	40
#define DECT_PT_SP_BS_DATA_SIZE		3

/* long and full page B_S channel data */
#define DECT_PT_LFP_BS_DATA_MASK	0x0fffffffff000000ULL
#define DECT_PT_LFP_BS_DATA_SHIFT	24
#define DECT_PT_LFP_BS_DATA_SIZE	5

struct dect_page {
	bool			extend;
	enum dect_page_lengths	length;
	u32			rfpi;
};

/* MAC layer information */
#define DECT_PT_INFO_TYPE_MASK		0x000000f000000000ULL
#define DECT_PT_INFO_TYPE_SHIFT		36
#define DECT_PT_INFO_TYPE_SIZE		2

/**
 * @DECT_PT_IT_FILL_BITS_OR_BLIND_LONG_SLOTS:	fill bits/blind long slots if bit 47 set
 * @DECT_PT_IT_BLIND_FULL_SLOT:			blind full slot information
 * @DECT_PT_IT_OTHER_BEARER:
 * @DECT_PT_IT_RECOMMENDED_OTHER_BEARER:
 * @DECT_PT_IT_GOOD_RFP_BEARER:
 * @DECT_PT_IT_DUMMY_OR_CL_BEARER_POSITION:
 * @DECT_PT_IT_RFP_IDENTITY:
 * @DECT_PT_IT_ESCAPE:
 * @DECT_PT_IT_DUMMY_OR_CL_BEARER_MARKER:
 * @DECT_PT_IT_BEARER_HANDOVER_INFO:
 * @DECT_PT_IT_RFP_STATUS:
 * @DECT_PT_IT_ACTIVE_CARRIERS:
 * @DECT_PT_IT_CL_BEARER_POSITION:
 * @DECT_PT_IT_RECOMMENDED_POWER_LEVEL:
 * @DECT_PT_IT_BLIND_DOUBLE_SLOT:
 * @DECT_PT_IT_BLIND_FULL_SLOT_PACKET_MODE:
 *
 */
enum dect_pt_info_types {
	DECT_PT_IT_FILL_BITS_OR_BLIND_LONG_SLOTS= 0x0ULL << DECT_PT_INFO_TYPE_SHIFT,
	DECT_PT_IT_BLIND_FULL_SLOT		= 0x1ULL << DECT_PT_INFO_TYPE_SHIFT,
	DECT_PT_IT_OTHER_BEARER			= 0x2ULL << DECT_PT_INFO_TYPE_SHIFT,
	DECT_PT_IT_RECOMMENDED_OTHER_BEARER	= 0x3ULL << DECT_PT_INFO_TYPE_SHIFT,
	DECT_PT_IT_GOOD_RFP_BEARER		= 0x4ULL << DECT_PT_INFO_TYPE_SHIFT,
	DECT_PT_IT_DUMMY_OR_CL_BEARER_POSITION	= 0x5ULL << DECT_PT_INFO_TYPE_SHIFT,
	DECT_PT_IT_RFP_IDENTITY			= 0x6ULL << DECT_PT_INFO_TYPE_SHIFT,
	DECT_PT_IT_ESCAPE			= 0x7ULL << DECT_PT_INFO_TYPE_SHIFT,
	DECT_PT_IT_DUMMY_OR_CL_BEARER_MARKER	= 0x8ULL << DECT_PT_INFO_TYPE_SHIFT,
	DECT_PT_IT_BEARER_HANDOVER_INFO		= 0x9ULL << DECT_PT_INFO_TYPE_SHIFT,
	DECT_PT_IT_RFP_STATUS			= 0xaULL << DECT_PT_INFO_TYPE_SHIFT,
	DECT_PT_IT_ACTIVE_CARRIERS		= 0xbULL << DECT_PT_INFO_TYPE_SHIFT,
	DECT_PT_IT_CL_BEARER_POSITION		= 0xcULL << DECT_PT_INFO_TYPE_SHIFT,
	DECT_PT_IT_RECOMMENDED_POWER_LEVEL	= 0xdULL << DECT_PT_INFO_TYPE_SHIFT,
	DECT_PT_IT_BLIND_DOUBLE_SLOT		= 0xeULL << DECT_PT_INFO_TYPE_SHIFT,
	DECT_PT_IT_BLIND_FULL_SLOT_PACKET_MODE	= 0xfULL << DECT_PT_INFO_TYPE_SHIFT,
};

/* blind full slot information */
#define DECT_PT_BFS_MASK		0x0000000fff000000ULL
#define DECT_PT_BFS_SHIFT		24

struct dect_bfs {
	struct dect_page	page;
	u16			mask;
};

/* Bearer description */
#define DECT_PT_BEARER_SN_MASK		0x0000000f00000000ULL
#define DECT_PT_BEARER_SN_SHIFT		32

#define DECT_PT_BEARER_SP_MASK		0x00000000c0000000ULL
#define DECT_PT_BEARER_SP_SHIFT		30

#define DECT_PT_BEARER_CN_MASK		0x000000003f000000ULL
#define DECT_PT_BEARER_CN_SHIFT		24

struct dect_bearer_desc {
	struct dect_page	page;
	enum dect_pt_info_types	bt;
	u8			sn;
	u8			sp;
	u8			cn;
};

/* RFP identity */
#define DECT_PT_RFP_ID_MASK		0x0000000fff000000ULL
#define DECT_PT_RFP_ID_SHIFT		24

struct dect_rfp_id {
	struct dect_page	page;
	u16			id;
};

/* RFP status */
#define DECT_PT_RFPS_RFP_BUSY_FLAG	0x0000000100000000ULL
#define DECT_PT_RFPS_SYS_BUSY_FLAG	0x0000000200000000ULL

struct dect_rfp_status {
	struct dect_page	page;
	bool			rfp_busy;
	bool			sys_busy;
};

/* Active carriers */
#define DECT_PT_ACTIVE_CARRIERS_MASK	0x0000000ffc000000ULL
#define DECT_PT_ACTIVE_CARRIERS_SHIFT	26

struct dect_active_carriers {
	struct dect_page	page;
	u16			active;
};

/*
 * MAC control (M-channel)
 */

#define DECT_MT_FRAME_RATE		2

#define DECT_MT_HDR_MASK		0xf000000000000000ULL
#define DECT_MT_HDR_SHIFT		60

#define DECT_MT_CMD_MASK		0x0f00000000000000ULL
#define DECT_MT_CMD_SHIFT		56

/**
 * enum dect_mt_hdr_type - MAC tail header types
 */
enum dect_mt_hdr_type {
	DECT_MT_BASIC_CCTRL			= 0x0ULL << DECT_MT_HDR_SHIFT,
	DECT_MT_ADV_CCTRL			= 0x1ULL << DECT_MT_HDR_SHIFT,
	DECT_MT_MAC_TEST			= 0x2ULL << DECT_MT_HDR_SHIFT,
	DECT_MT_QUALITY_CTRL			= 0x3ULL << DECT_MT_HDR_SHIFT,
	DECT_MT_BRD_CL_SERVICE			= 0x4ULL << DECT_MT_HDR_SHIFT,
	DECT_MT_ENC_CTRL			= 0x5ULL << DECT_MT_HDR_SHIFT,
	DECT_MT_XYZ				= 0x6ULL << DECT_MT_HDR_SHIFT,
	DECT_MT_ESC				= 0x7ULL << DECT_MT_HDR_SHIFT,
	DECT_MT_TARI				= 0x8ULL << DECT_MT_HDR_SHIFT,
	DECT_MT_REP_CCTRL			= 0x9ULL << DECT_MT_HDR_SHIFT,
};

/* advanced connection control */
enum dect_cctrl_cmds {
	DECT_CCTRL_ACCESS_REQ			= 0x0ULL << DECT_MT_CMD_SHIFT,
	DECT_CCTRL_BEARER_HANDOVER_REQ		= 0x1ULL << DECT_MT_CMD_SHIFT,
	DECT_CCTRL_CONNECTION_HANDOVER_REQ	= 0x2ULL << DECT_MT_CMD_SHIFT,
	DECT_CCTRL_UNCONFIRMED_ACCESS_REQ	= 0x3ULL << DECT_MT_CMD_SHIFT,
	DECT_CCTRL_BEARER_CONFIRM		= 0x4ULL << DECT_MT_CMD_SHIFT,
	DECT_CCTRL_WAIT				= 0x5ULL << DECT_MT_CMD_SHIFT,
	DECT_CCTRL_ATTRIBUTES_T_REQUEST		= 0x6ULL << DECT_MT_CMD_SHIFT,
	DECT_CCTRL_ATTRIBUTES_T_CONFIRM		= 0x7ULL << DECT_MT_CMD_SHIFT,
	DECT_CCTRL_BANDWIDTH_T_REQUEST		= 0x8ULL << DECT_MT_CMD_SHIFT,
	DECT_CCTRL_BANDWIDTH_T_CONFIRM		= 0x9ULL << DECT_MT_CMD_SHIFT,
	DECT_CCTRL_CHANNEL_LIST			= 0xaULL << DECT_MT_CMD_SHIFT,
	DECT_CCTRL_UNCONFIRMED_DUMMY		= 0xbULL << DECT_MT_CMD_SHIFT,
	DECT_CCTRL_UNCONFIRMED_HANDOVER		= 0xcULL << DECT_MT_CMD_SHIFT,
	DECT_CCTRL_RELEASE			= 0xfULL << DECT_MT_CMD_SHIFT,
};

/* Most messages */
#define DECT_CCTRL_FMID_MASK			0x00fff00000000000ULL
#define DECT_CCTRL_FMID_SHIFT			44

#define DECT_CCTRL_PMID_MASK			0x00000fffff000000ULL
#define DECT_CCTRL_PMID_SHIFT			24

/* Attributes-T request/confirm */
#define DECT_CCTRL_ATTR_ECN_MASK		0x00f0000000000000ULL
#define DECT_CCTRL_ATTR_ECN_SHIFT		52

#define DECT_CCTRL_ATTR_LBN_MASK		0x000f000000000000ULL
#define DECT_CCTRL_ATTR_LBN_SHIFT		48

#define DECT_CCTRL_ATTR_TYPE_MASK		0x0000c00000000000ULL
#define DECT_CCTRL_ATTR_TYPE_SHIFT		46

enum dect_cctrl_connection_types {
	DECT_CCTRL_TYPE_ASYMETRIC_UPLINK	= 0x0,
	DECT_CCTRL_TYPE_ASYMETRIC_DOWNLINK	= 0x1,
	DECT_CCTRL_TYPE_SYMETRIC_MULTIBEARER	= 0x2,
	DECT_CCTRL_TYPE_SYMETRIC_BEARER		= 0x3,
};

#define DECT_CCTRL_ATTR_SERVICE_MASK		0x00003f0000000000ULL
#define DECT_CCTRL_ATTR_SERVICE_SHIFT		40

enum dect_mac_service_types {
	DECT_SERVICE_IN_MIN_DELAY		= 0x0,
	DECT_SERVICE_IPX_ENCODED_PROTECTED	= 0x1,
	DECT_SERVICE_IN_NORM_DELAY		= 0x2,
	DECT_SERVICE_UNKNOWN			= 0x4,
	DECT_SERVICE_C_ONLY			= 0x5,
	DECT_SERVICE_IP_ERROR_DETECTION		= 0x10,
	DECT_SERVICE_IPQ_ERROR_DETECTION	= 0x14,
	/* Lifetime encoded in low three bits */
	DECT_SERVICE_IP_ERROR_CORRECTION	= 0x18,
	DECT_SERVICE_IPQ_ERROR_CORRECTION	= 0x38,
};

#define DECT_SERVICE_LIFETIME_MASK		= 0x7

#define DECT_CCTRL_ATTR_SLOT_MASK		0x000000f000000000ULL
#define DECT_CCTRL_ATTR_SLOT_SHIFT		36

#define DECT_CCTRL_ATTR_CF_FLAG			0x0000000800000000ULL

#define DECT_CCTRL_ATTR_BZ_EXT_MOD_MASK		0x0000000700000000ULL
#define DECT_CCTRL_ATTR_BZ_EXT_MOD_SHIFT	32

#define DECT_CCTRL_ATTR_ACR_MASK		0x00000000f0000000ULL
#define DECT_CCTRL_ATTR_ACR_SHIFT		28

enum dect_adaptive_code_rates {
	DECT_ACR_NONE				= 0x0,
};

#define DECT_CCTRL_ATTR_A_MOD_MASK		0x000000000c000000ULL
#define DECT_CCTRL_ATTR_A_MOD_SHIFT		26

#define DECT_CCTRL_ATTR_BZ_MOD_MASK		0x0000000003000000ULL
#define DECT_CCTRL_ATTR_BZ_MOD_SHIFT		24

enum dect_modulation_type {
	DECT_MODULATION_2_LEVEL			= 0x3,
	DECT_MODULATION_4_LEVEL			= 0x2,
	DECT_MODULATION_8_LEVEL			= 0x1,
};

/* Release */

#define DECT_CCTRL_RELEASE_INFO1_MASK		0x00f0000000000000ULL
#define DECT_CCTRL_RELEASE_INFO1_SHIFT		52

#define DECT_CCTRL_RELEASE_LBN_MASK		0x000f000000000000ULL
#define DECT_CCTRL_RELEASE_LBN_SHIFT		48

#define DECT_CCTRL_RELEASE_REASON_MASK		0x0000f00000000000ULL
#define DECT_CCTRL_RELEASE_REASON_SHIFT		44

enum dect_release_reasons {
	DECT_REASON_UNKNOWN				= 0x0,
	DECT_REASON_BEARER_RELEASE			= 0x1,
	DECT_REASON_CONNECTION_RELEASE			= 0x2,
	DECT_REASON_BEARER_SETUP_OR_HANDOVER_FAILED	= 0x3,
	DECT_REASON_BEARER_HANDOVER_COMPLETED		= 0x4,
	DECT_REASON_BEARER_HANDOVER_CLUSTER		= 0x5,
	DECT_REASON_TIMEOUT_LOST_SIGNAL			= 0x6,
	DECT_REASON_TIMEOUT_LOST_HANDSHAKE		= 0x7,
	DECT_REASON_REQUESTED_UNACCEPTABLE_SLOT_TYPE	= 0x8,
	DECT_REASON_REQUESTED_UNACCEPTABLE_MAC_SERVICE	= 0x9,
	DECT_REASON_BASE_STATION_BUSY			= 0xa,
	DECT_REASON_REVERSE_DIRECTION			= 0xb,
	DECT_REASON_DUPLICATE_PMID			= 0xc,
	DECT_REASON_UNACCEPTABLE_PMID			= 0xd,
	DECT_REASON_STAY_ON_LISTEN			= 0xe,
};

#define DECT_CCTRL_RELEASE_PMID_MASK			0x00000fffff000000ULL
#define DECT_CCTRL_RELEASE_PMID_SHIFT			24

struct dect_cctrl {
	enum dect_cctrl_cmds		cmd;
	union {
		struct {
			u32		pmid;
			u16		fmid;
		};
		struct {
			u8		ecn;
			u8		lbn;
			u8		type;
			u8		service;
			u8		slot;
			bool		cf;
			u8		a_mod;
			u8		bz_mod;
			u8		acr;
		};
		struct {
			u32		pmid;
			u8		lbn;
			u8		reason;
		};
	};
};

/* Encryption Control */

#define DECT_ENCCTRL_FILL_MASK			0x5000000000000000ULL

#define DECT_ENCCTRL_CMD_MASK			0x0f00000000000000ULL
#define DECT_ENCCTRL_CMD_SHIFT			56

enum dect_encctrl_cmds {
	DECT_ENCCTRL_START_REQUEST		= 0x0,
	DECT_ENCCTRL_START_CONFIRM		= 0x1,
	DECT_ENCCTRL_START_GRANT		= 0x2,
	DECT_ENCCTRL_STOP_REQUEST		= 0x8,
	DECT_ENCCTRL_STOP_CONFIRM		= 0x9,
	DECT_ENCCTRL_STOP_GRANT			= 0xa,
};

#define DECT_ENCCTRL_FMID_MASK			0x00fff00000000000ULL
#define DECT_ENCCTRL_FMID_SHIFT			44

#define DECT_ENCCTRL_PMID_MASK			0x00000fffff000000ULL
#define DECT_ENCCTRL_PMID_SHIFT			24

struct dect_encctrl {
	enum dect_encctrl_cmds	cmd;
	u32			pmid;
	u16			fmid;
};

/* marker for T-MUX exceptions */
#define DECT_MT_HIGH_PRIORITY		0x1

/*
 * C_T data
 */

#define DECT_C_S_SDU_SIZE		5

struct dect_ct_data {
	u8				seq;
};

/*
 * Flat representation of tail message contents
 */
enum dect_tail_msg_types {
	DECT_TM_TYPE_INVALID,
	DECT_TM_TYPE_ID,
	DECT_TM_TYPE_SSI,
	DECT_TM_TYPE_ERFC,
	DECT_TM_TYPE_FPC,
	DECT_TM_TYPE_EFPC,
	DECT_TM_TYPE_EFPC2,
	DECT_TM_TYPE_SARI,
	DECT_TM_TYPE_MFN,
	DECT_TM_TYPE_PAGE,
	DECT_TM_TYPE_BFS,
	DECT_TM_TYPE_BD,
	DECT_TM_TYPE_RFP_ID,
	DECT_TM_TYPE_RFP_STATUS,
	DECT_TM_TYPE_ACTIVE_CARRIERS,
	DECT_TM_TYPE_BCCTRL,
	DECT_TM_TYPE_ACCTRL,
	DECT_TM_TYPE_ENCCTRL,
	DECT_TM_TYPE_CT,
};

struct dect_tail_msg {
	enum dect_tail_identifications		ti;
	enum dect_tail_msg_types		type;
	union {
		struct dect_idi			idi;
		struct dect_ssi			ssi;
		struct dect_erfc		erfc;
		struct dect_fpc			fpc;
		struct dect_efpc		efpc;
		struct dect_efpc2		efpc2;
		struct dect_sari		sari;
		struct dect_mfn			mfn;
		struct dect_page		page;
		struct dect_bfs			bfs;
		struct dect_bearer_desc		bd;
		struct dect_rfp_id		rfp_id;
		struct dect_rfp_status		rfp_status;
		struct dect_active_carriers	active_carriers;
		struct dect_cctrl		cctl;
		struct dect_encctrl		encctl;
		struct dect_ct_data		ctd;
	};
};

struct dect_si {
	u32				mask;
	struct dect_ssi			ssi;
	struct dect_erfc		erfc;
	struct dect_fpc			fpc;
	struct dect_efpc		efpc;
	struct dect_efpc2		efpc2;
	struct dect_sari		sari[DECT_SARI_CYCLE_MAX];
	struct dect_mfn			mfn;
	u8				num_saris;
};

/*
 * B-Field
 */

#define DECT_B_FIELD_SIZE	40

/**
 * dect_b_identitifications - MAC layer B-Field Identification
 *
 * @DECT_BI_UTYPE_0:		U-Type, I_N, SI_N, SI_P or I_P packet number 0
 * @DECT_BI_UTYPE_1:		U-Type, I_P error detect or I_P packet number 1
 * @DECT_BI_ETYPE_CF_0:		E-Type, all C_F or CL_F, packet number 0
 * @DECT_BI_ETYPE_CF_1:		E-Type, all C_F, packet number 1
 * @DECT_BI_ETYPE_MAC:		E-Type, all MAC control (unnumbered)
 * @DECT_BI_NONE:		no B-Field
 */
enum dect_b_identifications {
	DECT_BI_UTYPE_0		= 0x0 << DECT_HDR_BA_SHIFT,
	DECT_BI_UTYPE_1		= 0x1 << DECT_HDR_BA_SHIFT,
	DECT_BI_ETYPE_CF_0	= 0x2 << DECT_HDR_BA_SHIFT,
	DECT_BI_ETYPE_CF_1	= 0x3 << DECT_HDR_BA_SHIFT,
	DECT_BI_ETYPE_MAC	= 0x6 << DECT_HDR_BA_SHIFT,
	DECT_BI_NONE		= 0x7 << DECT_HDR_BA_SHIFT,
};

struct dect_skb_b_cb {
	enum dect_b_identifications	id;
};

#define DECT_B_CB(skb)		((struct dect_skb_b_cb *)(skb)->cb)

#define DECT_C_F_SDU_SIZE	8
#define DECT_G_F_SDU_SIZE	8

/**
 * enum dect_mac_channels - internal MAC control channels
 *
 * @DECT_MC_Q:		System information and multiframe marker
 * @DECT_MC_N:		Identities information
 * @DECT_MC_M:		MAC control channel
 * @DECT_MC_P:		MAC Paging channel
 */
enum dect_mac_channels {
	DECT_MC_Q,
	DECT_MC_N,
	DECT_MC_M,
	DECT_MC_P,
};

/**
 * enum dect_data_channels - logical MAC data channels
 *
 * @DECT_MC_G_F:
 * @DECT_MC_C_S:	Higher layer C-Plane channel (slow)
 * @DECT_MC_C_F:	Higher layer C-Plane channel (fast)
 * @DECT_MC_I_N:	Higher layer U-Plane channel (numbered)
 * @DECT_MC_I_P:	Higher layer U-Plane channel (protected)
 * @DECT_MC_SI_N:	Higher layer connectionless U-Plane channel (numbered)
 * @DECT_MC_SI_P:	Higher layer connectionless U-Plane channel (protected)
 */
enum dect_data_channels {
	DECT_MC_G_F,
	DECT_MC_C_S,
	DECT_MC_C_F,
	DECT_MC_I_N,
	DECT_MC_I_P,
	DECT_MC_SI_N,
	DECT_MC_SI_P,
	__DECT_MC_MAX
};
#define DECT_MC_MAX		(__DECT_MC_MAX - 1)

/**
 * enum dect_mac_connection_types - MAC Connection types
 *
 * @DECT_MAC_CONN_BASIC:	Basic connection, always I_N_min_delay service
 * @DECT_MAC_CONN_ADVANCED:	Advanced connection
 * @DECT_MAC_CONN_COMPLEMENT:	Complementary connection
 */
enum dect_mac_connection_types {
	DECT_MAC_CONN_BASIC,
	DECT_MAC_CONN_ADVANCED,
	DECT_MAC_CONN_COMPLEMENT,
};

/**
 * struct dect_mbc_id
 *
 * @mcei:		MAC Connection Endpoint Identifier
 * @type:		Connection Type (Basic/Advanced)
 * @ari:		FT identifier
 * @pmid:		Portable MAC Identity
 * @ecn:		Exchanged Connection Number
 * @service:		Service type
 */
struct dect_mbc_id {
	u32				mcei;
	enum dect_mac_connection_types	type;
	struct dect_ari			ari;
	struct dect_pmid		pmid;
	u8				ecn;
	enum dect_mac_service_types	service;
};

#endif /* _NET_DECT_MAC_H */
