/*
 * DECT MAC Layer - Cluster Control Functions (CCF)
 *
 * Copyright (c) 2009 Patrick McHardy <kaber@trash.net>
 */

#ifndef _NET_DECT_MAC_CCF_H
#define _NET_DECT_MAC_CCF_H

#include <linux/skbuff.h>
#include <linux/timer.h>
#include <net/dect/mac.h>

/**
 * struct dect_bmc_skb_cb
 *
 * @fast_page:		page message is a fast page
 * @long_page:		page message is a long page
 * @stamp:		multiframe number at time of TX request
 * @repetitions:	number of page repetitions
 */
struct dect_bmc_skb_cb {
	bool				fast_page;
	bool				long_page;
	u32				stamp;
	u8				repetitions;
};
#define DECT_BMC_CB(skb)		((struct dect_bmc_skb_cb *)(skb)->cb)

#define DECT_PAGE_LIFETIME		6	/* multiframes */

/**
 * struct dect_bmc - broadcast message control
 *
 * @bcs:		broadcast controller list
 * @index:		system information round robin index
 */
struct dect_bmc {
	struct list_head		bcs;
	unsigned int			index;
};

struct dect_cmc {

};

struct dect_cs_skb_cb {
	u8				seq;
};
#define DECT_CS_CB(skb)			((struct dect_cs_skb_cb *)(skb)->cb)

/**
 * struct dect_tb - DECT Traffic Bearer
 *
 * @list:		MBC traffic bearer list node
 * @mbc:		MBC controlling the traffic bearer
 * @ch:			Cell handling the traffic bearer
 * @id:			Traffic Bearer Controller ID
 * @handover:		Handover yes/no
 * @handover_timer:	Handover timer
 * @rx_slot:		Receive slot
 * @tx_slot:		Transmit slot
 * @slot_rx_timer:	Receive slot timer
 * @slot_tx_timer:	Transmit slot timer
 * @b_rx_skb:		B-Field receive skb
 */
struct dect_tb {
	struct list_head		list;
	struct dect_mbc			*mbc;
	const struct dect_cell_handle	*ch;
	struct dect_tbc_id		id;
	bool				handover;

	/* FP: handover release timer */
	struct dect_timer		handover_timer;

	/* Slot transmit/receive timers */
	u8				rx_slot;
	u8				tx_slot;
	struct dect_timer		slot_rx_timer;
	struct dect_timer		slot_tx_timer;

	/* I channel data */
	struct sk_buff			*b_rx_skb;
};

struct dect_mbc_stats {
	unsigned int			cs_rx_bytes;
	unsigned int			cs_tx_bytes;
	unsigned int			i_rx_bytes;
	unsigned int			i_tx_bytes;
	unsigned int			handovers;
};

/**
 * struct dect_mbc - DECT Multi-Bearer Control
 *
 * @list:		Cluster connection list node
 * @cl:			Cluster the MBC is contained in
 * @refcnt:		Reference count
 * @id:			MBC identity
 * @state:		MBC state
 * @timer:		Connection setup timer (T200)
 * @setup_cnt:		number of setup attempts (N200)
 * @tbs:		List of traffic bearers
 * @ho_stamp:		Handover token bucket refill timestamp
 * @ho_tokens:		Handover token bucket tokens
 * @normal_rx_timer:	Normal receive half frame timer
 * @onrmal_tx_timer:	Normal transmit half frame timer
 * @ck:			Cipher key
 * @cipher_state:	Ciphering state
 * @cs_rx_seq:		C_S receive sequence number
 * @cs_tx_seq:		C_S transmit sequence number
 * @cs_tx_ok:		C_S segment transmit OK
 * @cs_rx_ok:		C_S segment reception OK
 * @cs_tx_skb:		C_S segment queued for transmission
 * @cs_tx_skb:		C_S segment queued for delivery to DLC
 */
struct dect_mbc {
	struct list_head		list;
	struct dect_cluster		*cl;
	unsigned int			refcnt;

	struct dect_mbc_id		id;
	struct dect_mac_conn_params	mcp;
	enum dect_mbc_state		state;

	struct timer_list		timer;
	u8				setup_cnt;

	struct list_head		tbs;

	/* Handover rate limiting */
	unsigned long			ho_stamp;
	u8				ho_tokens;

	/* Normal transmit/receive timers */
	struct dect_timer		normal_rx_timer;
	struct dect_timer		normal_tx_timer;

	/* Encryption */
	u64				ck;
	enum dect_cipher_states		cipher_state;

	/* C_S channel */
	u8				cs_rx_seq;
	u8				cs_tx_seq;
	bool				cs_tx_ok;
	bool				cs_rx_ok;
	struct sk_buff			*cs_rx_skb;
	struct sk_buff			*cs_tx_skb;

	struct dect_mbc_stats		stats;
};

#define DECT_MBC_SETUP_TIMEOUT		(5 * HZ)	/* T200: 5 seconds */
#define DECT_MBC_SETUP_MAX_ATTEMPTS	10		/* N200: 10 attempts */
#define DECT_MBC_HANDOVER_TIMER		(3 * HZ)	/* T202: 3 seconds */
#define DECT_MBC_TB_HANDOVER_TIMEOUT	16		/* T203: 16 frames */

#define DECT_MBC_HANDOVER_LIMIT		2		/* per N202 seconds */
#define DECT_MBC_HANDOVER_REATTEMPTS	15		/* N201: 15 */

extern u32 dect_mbc_alloc_mcei(struct dect_cluster *cl);
extern int dect_mac_con_req(struct dect_cluster *cl,
			    const struct dect_mbc_id *id,
			    const struct dect_mac_conn_params *mcp);
extern void dect_mac_dis_req(struct dect_cluster *cl, u32 mcei);

extern int dect_mac_enc_key_req(const struct dect_cluster *cl, u32 mcei, u64 ck);
extern int dect_mac_enc_eks_req(const struct dect_cluster *cl, u32 mcei,
				enum dect_cipher_states status);

extern void dect_bmc_mac_page_req(struct dect_cluster *cl, struct sk_buff *skb);

extern u8 dect_b_field_size(enum dect_slot_types slot);

struct dect_llme_req;

/**
 * struct dect_ccf_ops - Cluster Control Ops
 *
 * @bind:			bind cell to cluster
 * @unbind:			unbind cell from cluster
 * @mac_info_indicate:		indicate FP mac layer information (PP only)
 * @mbc_conn_indicate:		indicate a new TBC connection
 * @mbc_conn_notify:		notify MBC of TBC events
 * @mbc_data_indicate:		indicate new data to MBC
 * @bmc_page_indicate:		indicate reception of a page message to the BMC
 */
struct dect_cluster_handle;
struct dect_scan_result;
enum dect_tbc_event;
struct dect_ccf_ops {
	int	(*bind)(struct dect_cluster_handle *,
			struct dect_cell_handle *);
	void	(*unbind)(struct dect_cluster_handle *,
			  struct dect_cell_handle *);

	void	(*time_ind)(struct dect_cluster_handle *,
			    enum dect_timer_bases, u32, u8, u8);

	void	(*scan_report)(const struct dect_cluster_handle *,
			       const struct dect_scan_result *);

	void	(*mac_info_ind)(const struct dect_cluster_handle *,
				const struct dect_idi *,
				const struct dect_si *);

	int	(*tbc_establish_ind)(const struct dect_cluster_handle *,
				     const struct dect_cell_handle *,
				     const struct dect_tbc_id *,
				     const struct dect_mac_conn_params *, bool);
	int	(*tbc_establish_cfm)(const struct dect_cluster_handle *,
				     const struct dect_tbc_id *, bool, u8);
	void	(*tbc_dis_ind)(const struct dect_cluster_handle *,
			       const struct dect_tbc_id *,
			       enum dect_release_reasons);
	int	(*tbc_event_ind)(const struct dect_cluster_handle *,
				 const struct dect_tbc_id *,
				 enum dect_tbc_event);
	void	(*tbc_data_ind)(const struct dect_cluster_handle *,
				const struct dect_tbc_id *,
				enum dect_data_channels chan,
				struct sk_buff *);
	int	(*tbc_handover_req)(const struct dect_cluster_handle *,
				    const struct dect_tbc_id *);

	void	(*bmc_page_ind)(const struct dect_cluster_handle *,
				struct sk_buff *);
};

/**
 * struct dect_cluster_handle - Cell's view of a cluster
 *
 * @ops:		Cluster Control Function ops
 * @index:		Cluster index
 * @tipc_id:		Cluster TIPC user ID
 * @tportref:		Topology Service port reference (remote cluster only)
 * @portref:		Cell Control Protocol port reference (remote cluster only)
 */
struct dect_cluster_handle {
	const struct dect_ccf_ops	*ops;
	u8				index;

	u32				tipc_id;
	u32				tportref;
	u32				portref;
};

#endif /* _NET_DECT_MAC_CCF_H */
