/*
 * DECT MAC Layer - Cell Control Protocol (CCP)
 *
 * Copyright (c) 2009 Patrick McHardy <kaber@trash.net>
 */

#ifndef _NET_DECT_CCP
#define _NET_DECT_CCP

#define DECT_CCP_TIPC_TYPE		TIPC_RESERVED_TYPES
#define DECT_CCP_CELL_PORT		1000
#define DECT_CCP_CLUSTER_PORT_BASE	1000

enum dect_ccp_primitives {
	/* CCF -> CSF */
	DECT_CCP_SET_MODE,
	DECT_CCP_SCAN,
	DECT_CCP_ENABLE,
	DECT_CCP_PRELOAD,
	DECT_CCP_TBC_INITIATE,
	DECT_CCP_TBC_CONFIRM,
	DECT_CCP_TBC_RELEASE,
	/* CSF -> CCF */
	DECT_CCP_MBC_CONN_INDICATE,
	DECT_CCP_MBC_CONN_NOTIFY,
	DECT_CCP_MBC_DATA_INDICATE,
};

struct dect_ccp_msg_hdr {
	u8		primitive;
} __attribute__((packed));

struct dect_ccp_ari {
	__be64		ari;
};

struct dect_ccp_mode_msg {
	u8		mode;
} __attribute__((packed));

struct dect_ccp_scan_msg {
	__be64		ari;
	__be64		ari_mask;
} __attribute__((packed));

struct dect_ccp_sysinfo_msg {
	__be64		pari;
	__be64		sari[DECT_SARI_CYCLE_MAX];
	__be64		fpc;
	__be64		hlc;
	__be64		efpc;
	__be32		mfn;
	u8		num_saris;
	u8		rpn;
} __attribute__((packed));

struct dect_ccp_mbc_msg {
	__be32		mcei;
	__be32		pmid;
	__be64		ari;
	u8		ecn;
} __attribute__((packed));

struct dect_ccp_data_msg {
	u8		channel;
	u8		data[];
} __attribute__((packed));

extern int dect_ccp_cluster_init(struct dect_cluster *cl);
extern void dect_ccp_cluster_shutdown(struct dect_cluster *cl);

extern struct dect_cluster_handle *dect_ccp_cell_init(struct dect_cell *cell,
						      u8 clindex);

#endif /* _NET_DECT_CPP */
