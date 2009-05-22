/*
 * DECT DLC Layer
 *
 * Copyright (c) 2009 Patrick McHardy <kaber@trash.net>
 */

#ifndef _NET_DECT_DLC_H
#define _NET_DECT_DLC_H

#include <linux/timer.h>

/*
 * C-Plane data link service
 */

/*
 * FA-Frame
 */

#define DECT_FA_HDR_SIZE	3

struct dect_fa_hdr {
	u8	addr;
	u8	ctrl;
	u8	li;
};

/*
 * Address field
 */

#define DECT_FA_ADDR_OFF	0

/* New link flag */
#define DECT_FA_ADDR_NLF_FLAG	0x80

/* Logical Link Number */
#define DECT_FA_ADDR_LLN_MASK	0x70
#define DECT_FA_ADDR_LLN_SHIFT	4

/* Service Access Point Identifier */
#define DECT_FA_ADDR_SAPI_MASK	0x0c
#define DECT_FA_ADDR_SAPI_SHIFT	2

/* Command/Response flag */
#define DECT_FA_ADDR_CR_FLAG	0x02

/* Reserved bit */
#define DECT_FA_ADDR_RES_BIT	0x01

/*
 * Control field
 */

#define DECT_FA_CTRL_OFF	1

/*
 * I-Format: numbered information
 */

#define DECT_FA_CTRL_I_FMT_MASK	0x01
#define DECT_FA_CTRL_I_FMT_ID	0x00

/* Receive sequence number */
#define DECT_FA_CTRL_I_NR_MASK	0xe0
#define DECT_FA_CTRL_I_NR_SHIFT	5

/* Poll bit */
#define DECT_FA_CTRL_I_P_FLAG	0x10

/* Send sequence number */
#define DECT_FA_CTRL_I_NS_MASK	0x0e
#define DECT_FA_CTRL_I_NS_SHIFT	1

/* Command */
#define DECT_FA_CTRL_I_CMD_I	(0x0)

/*
 * S-Format: supervisory functions
 */

#define DECT_FA_CTRL_S_FMT_MASK	0x03
#define DECT_FA_CTRL_S_FMT_ID	0x01

/* Receive sequence number */
#define DECT_FA_CTRL_S_NR_MASK	0xe0
#define DECT_FA_CTRL_S_NR_SHIFT	5

/* Poll/final bit */
#define DECT_FA_CTRL_S_PF_FLAG	0x10

/* Command/Response */
#define DECT_FA_CTRL_S_CR_MASK	0x0c

#define DECT_FA_CTRL_S_CR_RR	0x00
#define DECT_FA_CTRL_S_CR_RNR	0x40
#define DECT_FA_CTRL_S_CR_REJ	0x80

/*
 *  U-Format: unnumbered information
 */

#define DECT_FA_CTRL_U_FMT_MASK	0x03
#define DECT_FA_CTRL_U_FMT_ID	0x03

/* Unnumbered function bits */
#define DECT_FA_CTRL_U_U1_MASK	0xec

/* Poll/final bit */
#define DECT_FA_CTRL_U_PF_FLAG	0x10

/* Command/Response */
#define DECT_FA_CTRL_U_CR_MASK	0xef

#define DECT_FA_CTRL_U_CR_SABM	0x2c
#define DECT_FA_CTRL_U_CR_DM	0x0c
#define DECT_FA_CTRL_U_CR_UI	0x00
#define DECT_FA_CTRL_U_CR_DISC	0x40
#define DECT_FA_CTRL_U_CR_UA	0x60

/*
 * Length Indicator
 */

#define DECT_FA_LI_OFF		2

/* Length (octets) */
#define DECT_FA_LI_LENGTH_MASK	0xfc
#define DECT_FA_LI_LENGTH_SHIFT	2

/* More data flag */
#define DECT_FA_LI_M_FLAG	0x02

/* Extended length indicator bit */
#define DECT_FA_LI_EXT_FLAG	0x01

/* maximum length value */
#define DECT_FA_LI_MAX		63

/*
 * Extended Length indicator
 */

#define DECT_FA_ELI_OFF		3

/* Length (octets) */
#define DECT_FA_ELI_LENGTH_MASK	0xfc
#define DECT_FA_ELI_LENGTH_SHIFT 2

struct dect_fa_len {
	u8		len;
	bool		more;
};

/*
 * Fill Field
 */

#define DECT_FA_FILL_PATTERN	0xf0

/*
 * Checksum field
 */

#define DECT_FA_CSUM_SIZE	2

/*
 * Information field
 */

#define DECT_FA_I_MAX		(DECT_FA_LI_MAX - DECT_FA_HDR_SIZE - DECT_FA_CSUM_SIZE)


/**
 * struct dect_dli - DECT Data Link Identifier (DLI)
 *
 * @lln:	Logical Link Number
 * @mci:	Mac Connection Identifier
 */
struct dect_dli {
	enum dect_llns	lln;
	struct dect_mci	mci;
};

/**
 * @DECT_LAPC_ULI:	unassigned link identifier state (class U/A)
 * @DECT_LAPC_ALI:	assigned link identifier state (class B established)
 * @DECT_LAPC_ASM:	assigned Link Identifier/multiple frame state (class B suspended)
 */
enum dect_lapc_states {
	DECT_LAPC_ULI,
	DECT_LAPC_ALI,
	DECT_LAPC_ASM,
};

/**
 * struct dect_lapc - DECT LAPC entity
 *
 * @lc:			Associated Lc entity
 * @dli:		Data Link Identifier
 * @sapi:		Service Access Point Identifier
 * @cmd:		CR bit setting for commands (PT: 1, FT: 0)
 * @nlf:		New link flag
 * @v_s:		Send state Variable V(S): sequence number of next I-frame
 * @v_a:		Acknowledge state Variable V(A): last I-frame that has been acknowledged
 * @v_r:		Receive state Variable V(R): next expected sequence number
 * busy:		LAPC is in receiver busy condition
 * @peer_busy:		Peer is in receiver busy condition
 * @window:		maximum number of oustanding unacknowledged I-frames
 * @mod:		modulus for sequence number calculations
 * @retransmit_cnt:	Retransmission counter
 * @retransmit_queue:	Retransmission queue
 * @timer:		Retransmission timer (DL.04)
 */
struct dect_lapc {
	struct sock		*sk;
	struct dect_lc		*lc;
	struct dect_dli		dli;
	enum dect_sapis		sapi;

	bool			cmd;

	enum dect_lapc_states	state;
	bool			nlf;
	u8			v_s;
	u8			v_a;
	u8			v_r;

	bool			busy;
	bool			peer_busy;

	u8			window;
	u8			mod;

	u8			retransmit_cnt;
	struct sk_buff_head	retransmit_queue;
	struct timer_list	timer;

	struct sk_buff		*rcv_head;
};

/* class A window size and sequence number modulus */
#define DECT_LAPC_CLASS_A_WINDOW		1
#define DECT_LAPC_CLASS_A_MOD			2

/* class B window size and sequence number modulus */
#define DECT_LAPC_CLASS_B_INITIAL_WINDOW	1
#define DECT_LAPC_CLASS_B_WINDOW		3
#define DECT_LAPC_CLASS_B_MOD			8

/* maximum number of retransmissions */
#define DECT_LAPC_RETRANSMIT_MAX		3

/* various timer parameters specified in Annex A */
#define DECT_LAPC_CLASS_A_ESTABLISH_TIMEOUT	(2 * HZ)
#define DECT_LAPC_CLASS_B_ESTABLISH_TIMEOUT	(2 * HZ)
#define DECT_LAPC_RETRANSMISSION_TIMEOUT	(1 * HZ)
#define DECT_LAPC_LINK_RELEASE_TIMEOUT		(2 * HZ)
#define DECT_LAPC_LINK_SUSPEND_TIMEOUT		(2 * HZ)
#define DECT_LAPC_LINK_RESUME_TIMEOUT		(2 * HZ)
#define DECT_LAPC_CONNECTION_HANDOVER_TIMEOUT	(10 * HZ)
#define DECT_LAPC_CONNECTION_HANDOVER_INTERVAL	(4 * HZ)

extern struct dect_lapc *dect_lapc_init(struct sock *sk, const struct dect_dli *dli,
					enum dect_sapis sapi, struct dect_lc *lc,
					gfp_t gfp);
extern void dect_lapc_release(struct dect_lapc *lapc, bool normal);

extern int dect_lapc_transmit(struct dect_lapc *lapc);
extern int dect_lapc_establish(struct dect_lapc *lapc);
extern struct dect_lapc *dect_ssap_rcv_request(struct dect_lc *lc,
					       const struct dect_dli *dli,
					       enum dect_sapis sapi);

/**
 * struct dect_lc - DECT Lc entity
 *
 * @mc:		MAC connection
 * @lsig:	link signature for checksumming (lower 16 bits of PMID or 0)
 * @rx_head:	reassembly queue head
 * @rx_len:	target length of current reassembly buffer
 * @txq:	transmit queue
 * @tx_head:	current TX LAPC frame
 * @tx_len:	TX target fragment length
 * @use:	usage count
 * @lapcs:	LAPC entities associated with the Lc
 * @e_lapc:	LAPC performing establishment procedures
 *
 * The Lc entity is responsible for framing, logical channel selection and
 * fragmenting of LAPC PDUs. There is one Lc entity per MAC connection.
 */
struct dect_lc {
	struct dect_mac_conn	*mc;
	u16			lsig;

	struct sk_buff		*rx_head;
	u8			rx_len;

	struct sk_buff_head	txq;
	struct sk_buff		*tx_head;
	u8			tx_len;

	u8			use;
	struct dect_lapc	*lapcs[DECT_LLN_MAX + 1];
	struct dect_lapc	*elapc;
};

#define DECT_LC_LSIG_MASK	0xffff

extern struct dect_lc *dect_lc_init(struct dect_mac_conn *mc, gfp_t gfp);
extern void dect_lc_bind(struct dect_lc *lc, struct dect_lapc *lapc);

/**
 * struct dect_lb - DECT Lb entity (C-plane broadcast service)
 *
 *
 */
struct dect_lb {
};

#define DECT_LB_SHORT_FRAME_SIZE	3
#define DECT_LB_LONG_FRAME_SIZE		5
#define DECT_LB_EXTENDED_FRAME_SIZE_MAX	(6 * DECT_LB_LONG_FRAME_SIZE)

#include <net/sock.h>

/**
 * struct dect_dlc_fbx_ops - DLC U-plane lower (FBx) entity ops
 *
 */
struct dect_fbx;
struct dect_fbx_ops {
	struct sk_buff			*(*dequeue)(struct dect_fbx *fbx);
	void				(*enqueue)(struct dect_fbx *fbx,
						   struct sk_buff *skb);
};

struct dect_fbx {
	const struct dect_fbx_ops	*ops;
};

extern const struct dect_fbx_ops dect_fbn_ops;

struct dect_lux;
struct dect_lux_ops {
	struct sk_buff			*(*dequeue)(struct dect_lux *lux);
	void				(*enqueue)(struct dect_lux *lux,
						   struct sk_buff *skb);
	void				(*disconnect)(struct dect_lux *lux);
};

/**
 * struct dect_lux - DLC U-plane upper (LUx) entity
 *
 * @fpx:	FBx entity
 */
struct dect_lux {
	const struct dect_lux_ops	*ops;
	struct dect_fbx			fbx;
};

/**
 * dect_mac_connection_states - DECT MAC connection states as viewed by the DLC
 *
 * @DECT_MAC_CONN_CLOSED:
 * @DECT_MAC_CONN_OPEN_PENDING:
 * @DECT_MAC_CONN_OPEN:
 */
enum dect_mac_conn_states {
	DECT_MAC_CONN_CLOSED,
	DECT_MAC_CONN_OPEN_PENDING,
	DECT_MAC_CONN_OPEN,
};

/**
 * struct dect_mac_conn - DECT MAC connection as viewed by the DLC
 *
 * @list:	Cluster connection list node
 * @cl:		Cluster
 * @mcei:	MAC Connection Endpoint Identification
 * @mci:	MAC Connection Identifier (BMCI or AMCI)
 * @state:	Connection state
 * @service:	Service offered by the connection
 */
struct dect_mac_conn {
	struct list_head		list;
	struct dect_cluster		*cl;

	u32				mcei;
	struct dect_mci			mci;
	enum dect_mac_conn_states	state;
	enum dect_mac_service_types	service;

	struct dect_lc			*lc;
	struct dect_fbx			*fbx;
};

extern struct dect_mac_conn *dect_mac_conn_init(struct dect_cluster *cl,
						const struct dect_mci *mci,
						const struct dect_mbc_id *id);
extern struct dect_mac_conn *dect_mac_conn_get_by_mci(const struct dect_cluster *cl,
						      const struct dect_mci *mci);
extern int dect_dlc_mac_conn_establish(struct dect_mac_conn *mc);
extern void dect_dlc_mac_conn_release(struct dect_mac_conn *mc);

extern int dect_dlc_mac_conn_confirm(struct dect_cluster *cl, u32 mcei,
				     enum dect_mac_service_types service);

extern int dect_dlc_mac_conn_indicate(struct dect_cluster *cl,
				      const struct dect_mbc_id *id);

extern void dect_dlc_mac_dis_request(struct dect_mac_conn *mc);
extern int dect_dlc_mac_dis_indicate(struct dect_cluster *cl, u32 mcei,
				     enum dect_release_reasons reason);

extern void dect_cplane_notify_state_change(struct dect_mac_conn *mc);
extern void dect_cplane_rcv(struct dect_mac_conn *mc,
			    enum dect_data_channels chan,
			    struct sk_buff *skb);
extern struct sk_buff *dect_cplane_dtr(struct dect_mac_conn *mc,
				       enum dect_data_channels chan);

extern void dect_uplane_rcv(struct dect_mac_conn *mc,
			    enum dect_data_channels chan,
			    struct sk_buff *skb);
extern struct sk_buff *dect_uplane_dtr(struct dect_mac_conn *mc,
				       enum dect_data_channels chan);

extern void dect_dlc_mac_co_data_indicate(struct dect_cluster *cl, u32 mcei,
					  enum dect_data_channels chan,
					  struct sk_buff *skb);
extern struct sk_buff *dect_dlc_mac_co_dtr_indicate(struct dect_cluster *cl, u32 mcei,
						    enum dect_data_channels chan);

extern void dect_bsap_rcv(const struct dect_cluster *cl, struct sk_buff *skb);
extern void dect_dlc_mac_page_indicate(struct dect_cluster *cl,
				       struct sk_buff *skb);

#endif /* _NET_DECT_DLC_H */
