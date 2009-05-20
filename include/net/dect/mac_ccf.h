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
 * @fast:		fast page
 * @stamp:		multiframe number at time of TX request
 * @repetitions:	number of page repetitions
 */
struct dect_bmc_skb_cb {
	bool				fast;
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

enum dect_mbc_state {
	DECT_MBC_NONE,
	DECT_MBC_INITIATED,
	DECT_MBC_ESTABLISHED,
};

/**
 * struct dect_mbc - DECT Multi-Bearer Control
 *
 * @list:		Cluster connection list node
 * @cl:			Cluster the MBC is contained in
 * @type:		connection type
 * @id:			MBC identity
 * @state:		MBC state
 * @timer:		Connection setup timer (T200)
 * @ch:			Cell handling associated traffic bearer
 * @setup_cnt:		number of setup attempts (N200)
 * @cs_rx_seq:		C_S receive sequence number
 * @cs_tx_seq:		C_S transmit sequence number
 */
struct dect_mbc {
	struct list_head		list;
	struct dect_cluster		*cl;

	enum dect_mac_connection_types	type;
	struct dect_mbc_id		id;
	enum dect_mbc_state		state;

	struct timer_list		timer;
	const struct dect_cell_handle	*ch;
	u8				setup_cnt;

	u8				cs_rx_seq;
	u8				cs_tx_seq;
	struct sk_buff			*cs_tx_skb;
};

#define DECT_MBC_SETUP_TIMEOUT		(5 * HZ)	/* seconds */
#define DECT_MBC_SETUP_MAX_ATTEMPTS	10

extern u32 dect_mbc_alloc_mcei(struct dect_cluster *cl);
extern int dect_mbc_con_request(struct dect_cluster *cl,
				const struct dect_mbc_id *id);
extern void dect_mbc_dis_request(struct dect_cluster *cl,
				 const struct dect_mbc_id *id);

extern void dect_bmc_mac_page_request(struct dect_cluster *cl,
				      struct sk_buff *skb, bool expedited);

struct dect_llme_req;
extern int dect_cluster_scan(struct dect_cluster *cl,
			     const struct dect_llme_req *lreq,
			     const struct dect_ari *pari,
			     const struct dect_ari *pari_mask);

/**
 * struct dect_ccf_ops - Cluster Control Ops
 *
 * @bind:			bind cell to cluster
 * @unbind:			unbind cell from cluster
 * @mac_info_indicate:		indicate FP mac layer information (PP only)
 * @mbc_conn_indicate:		indicate a new TBC connection
 * @mbc_conn_notify:		notify MBC of TBC events
 * @mbc_data_indicate:		indicate new data to MBC
 * @mbc_dtr_indicate:		indicate data transmit ready to MBC
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

	void	(*scan_report)(const struct dect_cluster_handle *,
			       const struct dect_scan_result *);

	void	(*mac_info_indicate)(const struct dect_cluster_handle *,
				     const struct dect_idi *,
				     const struct dect_si *);

	int	(*mbc_conn_indicate)(const struct dect_cluster_handle *,
				     const struct dect_cell_handle *,
				     const struct dect_mbc_id *);
	void	(*mbc_dis_indicate)(const struct dect_cluster_handle *,
				    const struct dect_mbc_id *,
				    enum dect_release_reasons);
	int	(*mbc_conn_notify)(const struct dect_cluster_handle *,
				   const struct dect_mbc_id *,
				   enum dect_tbc_event);
	void	(*mbc_data_indicate)(const struct dect_cluster_handle *,
				     const struct dect_mbc_id *,
				     enum dect_data_channels chan,
				     struct sk_buff *);
	void	(*mbc_dtr_indicate)(const struct dect_cluster_handle *,
				    const struct dect_mbc_id *,
				    enum dect_data_channels chan);

	void	(*bmc_page_indicate)(const struct dect_cluster_handle *,
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
