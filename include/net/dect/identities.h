#ifndef _NET_DECT_IDENTITIES_H
#define _NET_DECT_IDENTITIES_H

/*
 * Acess Rights Identity (ARI)
 */

#define DECT_ARI_ARC_MASK	0xe000000000000000ULL
#define DECT_ARI_ARC_SHIFT	61

/* Class A */
#define DECT_ARI_A_EMC_MASK	0x1fffe00000000000ULL
#define DECT_ARI_A_EMC_SHIFT	45

#define DECT_ARI_A_FPN_MASK	0x00001ffff0000000ULL
#define DECT_ARI_A_FPN_SHIFT	28

/* Class B */
#define DECT_ARI_B_EIC_MASK	0x1fffe00000000000ULL
#define DECT_ARI_B_EIC_SHIFT	45

#define DECT_ARI_B_FPN_MASK	0x00001fe000000000ULL
#define DECT_ARI_B_FPN_SHIFT	37

#define DECT_ARI_B_FPS_MASK	0x0000001e00000000ULL
#define DECT_ARI_B_FPS_SHIFT	33

/* Class C */
#define DECT_ARI_C_POC_MASK	0x1fffe00000000000ULL
#define DECT_ARI_C_POC_SHIFT	45

#define DECT_ARI_C_FPN_MASK	0x00001fe000000000ULL
#define DECT_ARI_C_FPN_SHIFT	37

#define DECT_ARI_C_FPS_MASK	0x0000001e00000000ULL
#define DECT_ARI_C_FPS_SHIFT	33

/* Class D */
#define DECT_ARI_D_GOP_MASK	0x1ffffe0000000000ULL
#define DECT_ARI_D_GOP_SHIFT	41

#define DECT_ARI_D_FPN_MASK	0x000001fe00000000ULL
#define DECT_ARI_D_FPN_SHIFT	33

/* Class E */
#define DECT_ARI_E_FIL_MASK	0x1fffe00000000000ULL
#define DECT_ARI_E_FIL_SHIFT	45

#define DECT_ARI_E_FPN_MASK	0x00001ffe00000000ULL
#define DECT_ARI_E_FPN_SHIFT	33

#include <linux/dect_netlink.h>

struct dect_ari {
	enum dect_ari_classes	arc;
	u32			fpn;
	u32			fps;
	union {
		u16		emc;
		u16		eic;
		u16		poc;
		u32		gop;
		u16		fil;
	};
};

enum dect_ari_lengths {
	DECT_ARC_A_LEN		= 36,
	DECT_ARC_B_LEN		= 31,
	DECT_ARC_C_LEN		= 31,
	DECT_ARC_D_LEN		= 31,
	DECT_ARC_E_LEN		= 31,
};

extern bool dect_ari_masked_cmp(const struct dect_ari *a1,
				const struct dect_ari *a2,
				const struct dect_ari *m);
extern bool dect_ari_cmp(const struct dect_ari *a1, const struct dect_ari *a2);
extern u8 dect_parse_ari(struct dect_ari *ari, u64 a);
extern u64 dect_build_ari(const struct dect_ari *ari);

/*
 * RFPI
 */

#define DECT_RFPI_E_FLAG	0x8000000000000000ULL
#define DECT_RFPI_ARI_SHIFT	1
#define DECT_RFPI_RPN_SHIFT	24

struct dect_idi;
extern bool dect_rfpi_cmp(const struct dect_idi *i1, const struct dect_idi *i2);
extern u64 dect_build_rfpi(const struct dect_idi *idi);

/*
 * FMID (Fixed MAC Identifier)
 */

#define DECT_FMID_MASK		0x0fff
#define DECT_FMID_SIZE		12

extern u16 dect_build_fmid(const struct dect_idi *idi);

/*
 * PMID (Portable MAC Identifier)
 */

#define DECT_PMID_MASK			0x000fffff
#define DECT_PMID_SIZE			20

#define DECT_PMID_DEFAULT_ID_MASK	0x000f0000
#define DECT_PMID_DEFAULT_ID		0x000e0000
#define DECT_PMID_DEFAULT_NUM_MASK	0x0000ffff

#define DECT_PMID_EMERGENCY_ID_MASK	0x000ff000
#define DECT_PMID_EMERGENCY_ID		0x000f1000
#define DECT_PMID_EMERGENCY_TPUI_MASK	0x00000fff

#define DECT_PMID_ASSIGNED_TPUI_MASK	0x000fffff

/**
 * @DECT_PMID_DEFAULT:		1110 + arbitrary number (16 bits)
 * @DECT_PMID_ASSIGNED:		Assigned individual TPUI
 * @DECT_PMID_EMERGENCY:	1111 0001 + 12 bits of emergency TPUI
 */
enum dect_pmid_types {
	DECT_PMID_DEFAULT,
	DECT_PMID_ASSIGNED,
	DECT_PMID_EMERGENCY,
};

struct dect_pmid {
	enum dect_pmid_types	type;
	union {
		u32		tpui;
		u32		num;
	};
};

extern void dect_parse_pmid(struct dect_pmid *pmid, u32 p);
extern u32 dect_build_pmid(const struct dect_pmid *pmid);
extern bool dect_pmid_cmp(const struct dect_pmid *p1, const struct dect_pmid *p2);

/*
 * ECN (Exchanged Connection Number)
 */

#define DECT_ECN_MASK		0xf
#define DECT_ECN_SIZE		4

/*
 * LCN (Logical Connection Number)
 */

#define DECT_LCN_MASK		0x7
#define DECT_LCN_SIZE		3

/**
 * struct dect_mci - MAC connection identifier
 *
 * @ari:	DECT ARI
 * @pmid:	Portable MAC Identity
 * @lcn:	Logical Connection Number
 */
struct dect_mci {
	struct dect_ari		ari;
	struct dect_pmid	pmid;
	u8			lcn;
};

extern int dect_parse_mci(struct dect_mci *mci, u64 m);
extern u64 dect_build_mci(const struct dect_mci *mci);

/*
 * Data Link Identifier
 */

/**
 * enum dect_sapis - S SAP Identifier
 *
 * @DECT_SAPI_CO_SIGNALLING: connection oriented signalling
 * @DECT_SAPI_CL_SIGNALLING: connectionless signalling
 */
enum dect_sapis {
	DECT_SAPI_CO_SIGNALLING	= 0,
	DECT_SAPI_CL_SIGNALLING = 3,
};

/**
 * enum dect_llns - Logical Link Numbers
 *
 * @DECT_LLN_CLASS_U:		Class U operation
 * @DECT_LLN_CLASS_A:		Class A operation
 * @DECT_LLN_ASSIGNABLE*:	Assignable LLN (class B operation)
 * @DECT_LLN_UNASSIGNED:	LLN unassigned (class B operation)
 */
enum dect_llns {
	DECT_LLN_CLASS_U	= 0,
	DECT_LLN_CLASS_A	= 1,
	DECT_LLN_ASSIGNABLE_MIN	= 2,
	DECT_LLN_ASSIGNABLE_MAX	= 6,
	DECT_LLN_UNASSIGNED	= 7,
	__DECT_LLN_MAX
};
#define DECT_LLN_MAX		(__DECT_LLN_MAX - 1)

/**
 * struct dect_dlei - DECT Data Link Endpoint Identifier (DLEI)
 *
 */
struct dect_dlei {
	struct dect_mci	mci;
	enum dect_sapis	sapi;
	enum dect_llns	lln;
};

/**
 * struct dect_ulei - DECT U-Plane Link Endpoint Identifier
 */
struct dect_ulei {
	struct dect_mci	mci;
};

#endif /* _NET_DECT_IDENTITIES_H */
