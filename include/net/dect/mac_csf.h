/*
 * DECT MAC Layer - Cell Site Functions (CSF)
 *
 * Copyright (c) 2009 Patrick McHardy <kaber@trash.net>
 */

#ifndef _NET_DECT_MAC_CSF_H
#define _NET_DECT_MAC_CSF_H

#include <net/dect/mac.h>
#include <net/dect/transceiver.h>

/**
 * enum dect_timer_bases - timer bases for DECT timers
 *
 * @DECT_TIMER_RX:	receive time base
 * @DECT_TIMER_TX:	send time base
 */
enum dect_timer_bases {
	DECT_TIMER_RX,
	DECT_TIMER_TX,
	__DECT_TIMER_BASE_MAX
};
#define DECT_TIMER_BASE_MAX	(__DECT_TIMER_BASE_MAX - 1)

/**
 * struct dect_timer_base - timer base
 *
 * @timers:		list of active timers
 * @slot:		slot position
 * @framenum:		frame number
 * @mfn:		multiframe number
 */
struct dect_timer_base {
	struct list_head	timers;
	u8			slot;
	u8			framenum;
	u32			mfn;
};

/**
 * struct dect_timer - DECT TDMA frame timer
 *
 * @list:		timer list node
 * @base:		timer base
 * @mfn:		expiration time: multiframe number
 * @frame:		expiration time: frame number
 * @slot:		expiration time: slot number
 * @func:		timer function
 * @data:		timer data
 */
struct dect_timer {
	struct list_head	list;

	enum dect_timer_bases	base;
	u32			mfn;
	u8			frame;
	u8			slot;

	void			(*func)(struct dect_cell *, void *);
	void			*data;
};

#define DECT_CHANNEL_LIST_DBM_RES	6
#define DECT_CHANNEL_LIST_BINS		(DECT_RSSI_DBM_RANGE / DECT_CHANNEL_LIST_DBM_RES)

/**
 * struct dect_channel_list_entry
 *
 * @list:		channel list bin node
 * @slot:		slot number
 * @carrier:		RF-carrier
 * @rssi:		measured RSSI value
 */
struct dect_channel_list_entry {
	struct list_head	list;
	u8			slot;
	u8			carrier;
	u8			rssi;
};

/**
 * struct dect_channel_list - Basic channel list
 *
 * @list:		cell's channel lists list node
 * @pkt:		packet type used for RSSI measurement
 * @status:		bitmask of completed carriers
 * @timer:		update timer
 * @available:		number of available entries
 * @bins:		channels ordered by RSSI value
 * @entries:		channel list entries
 *
 * A channel list contains channel descriptions of all physical channels
 * able to carry the packet type, sorted into multiple bins based on the
 * maximum RSSI value of the TDD slot pair.
 */
struct dect_channel_list {
	struct list_head		list;
	enum dect_packet_types		pkt;
	u64				status;

	struct dect_timer		timer;
	u16				available;
	struct list_head		bins[DECT_CHANNEL_LIST_BINS];
	struct dect_channel_list_entry	entries[];
};

#define DECT_CHANNEL_LIST_MAX_AGE	30	/* T209: 30 seconds */
#define DECT_CHANNEL_LIST_MAX_DBM	-50	/* dBm */
#define DECT_CHANNEL_LIST_LOW_WATERMARK	20	/* channels */

#define DECT_CHANNEL_MIN_DELAY		2	/* frames */

/**
 * enum dect_bearer_types
 *
 * @DECT_SIMPLEX_BEARER:	simplex bearer, one physical channel
 * @DECT_DUPLEX_BEARER:		two simplex bearers on opposite channels
 * @DECT_DOUBLE_SIMLEX_BEARER:	two simplex bearers in same direction
 * @DECT_DOUBLE_DUPLEX_BEARER:	two duplex bearers
 */
enum dect_bearer_types {
	DECT_SIMPLEX_BEARER,
	DECT_DUPLEX_BEARER,
	DECT_DOUBLE_SIMPLEX_BEARER,
	DECT_DOUBLE_DUPLEX_BEARER,
};

enum dect_bearer_states {
	DECT_DUMMY_BEARER,
	DECT_TRAFFIC_BEARER,
	DECT_CL_BEARER,
};

enum dect_bearer_modes {
	DECT_BEARER_RX,
	DECT_BEARER_TX,
};

/**
 * enum dect_bearer_state - DECT MAC bearer states
 *
 * @DECT_BEARER_INACTIVE:	bearer inactive
 * @DECT_BEARER_SCHEDULED:	bearer is scheduled for activation
 * @DECT_BEARER_RSSI_CONFIRM:	bearer is scheduled for RSSI confirmation
 * @DECT_BEARER_RSSI_CONFIRMED:	RSSI is confirmed, bearer is scheduled for e
 * @DECT_BEARER_ENABLED:	bearer is enabled
 */
enum dect_bearer_state {
	DECT_BEARER_INACTIVE,
	DECT_BEARER_SCHEDULED,
	DECT_BEARER_RSSI_CONFIRM,
	DECT_BEARER_RSSI_CONFIRMED,
	DECT_BEARER_ENABLED,
};

struct dect_bearer;
struct dect_bearer_ops {
	enum dect_bearer_states	state;
	void			(*enable)(struct dect_cell *, struct dect_bearer *);
	void			(*report_rssi)(struct dect_cell *, struct dect_bearer *,
					       u8 slot, u8 rssi);
	void			(*rcv)(struct dect_cell *cell, struct dect_bearer *,
				       struct sk_buff *);
};

/**
 * struct dect_bearer - DECT MAC Bearer
 *
 * @type:		bearer type
 * @state:		operational state
 * @trx:		DECT transceiver
 * @chd:		channel description
 * @mode:		bearer mode (RX/TX)
 * @tx_timer:		TX enable timer
 * @rssi:		last measured RSSI of selected channel
 * @m_tx_queue:		M-channel TX queue
 * @q:			Hdr-field MUX for Q1/Q2 bit settings
 * @union:		bearer type specific data
 */
struct dect_bearer {
	enum dect_bearer_types		type;
	const struct dect_bearer_ops	*ops;
	struct dect_transceiver		*trx;
	struct dect_channel_desc	chd;
	enum dect_bearer_modes		mode;
	enum dect_bearer_state		state;
	struct dect_timer		tx_timer;
	u8				rssi;

	struct sk_buff_head		m_tx_queue;
	u8				q;

	union {
		struct dect_dbc		*dbc;
		struct dect_cbc		*cbc;
		struct dect_tbc		*tbc;
		struct dect_irc		*irc;
		void			*data;
	};
};

/**
 * struct dect_bc - broadcast controller
 *
 * @list:		broadcast message control BC list node
 * @p_rx_skb:		current RX P-channel message
 */
struct dect_bc {
	struct list_head		list;
	struct sk_buff			*p_rx_skb;
};

/*
 * enum dect_bearer_qctrl_state - DECT bearer quality control state
 *
 * @DECT_BEARER_QCTRL_WAIT:	waiting for next quality control event
 * @DECT_BEARER_QCTRL_CONFIRM:	performing quality control
 */
enum dect_bearer_qctrl_state {
	DECT_BEARER_QCTRL_WAIT,
	DECT_BEARER_QCTRL_CONFIRM,
};

#define DECT_BEARER_QCTRL_FRAMENUM	15	/* must not affect paging */
#define DECT_BEARER_QCTRL_PERIOD	256	/* frames */

/**
 * struct dect_dbc - dummy bearer control
 *
 * @list:		cell dbc list node
 * @cell:		DECT cell
 * @bearer:		dummy bearer
 * @qctrl_timer:	quality control timer
 * @qctrl_state:	qaulity control state
 * @bc:			broadcast controller
 */
struct dect_dbc {
	struct list_head		list;
	struct dect_cell		*cell;
	struct dect_bearer		*bearer;
	struct dect_timer		qctrl_timer;
	enum dect_bearer_qctrl_state	qctrl;
	struct dect_bc			bc;
};

/*
 * struct dect_cbc - connectionless bearer control
 *
 * @cell:		DECT cell
 * @dl_bearer:		connectionless downlink bearer
 * @ul_bearer:		connectionless uplink bearer, if present
 * @bc:			broadcast controller
 */
struct dect_cbc {
	struct dect_cell		*cell;
	struct dect_bearer		*dl_bearer;
	struct dect_bearer		*ul_bearer;
	struct dect_bc			bc;
};

/**
 * enum dect_tbc_state - DECT Traffic Bearer Controller state
 *
 * @DECT_TBC_NONE:		Initial state
 * @DECT_TBC_REQ_SENT:		Initiator: bearer request sent
 * @DECT_TBC_WAIT_RCVD:		Initiator: intermediate state
 * @DECT_TBC_CONFIRM_WAIT:	Initiator: waiting for confirmation
 * @DECT_TBC_REQ_RCVD:		Responder: request received
 * @DECT_TBC_RESPONSE_SENT:	Responder: immediate response to request sent
 * @DECT_TBC_OTHER_WAIT:	Waiting for "other" message
 * @DECT_TBC_ESTABLISHED	Established
 * @DECT_TBC_RELEASING		First RELEASE message sent
 * @DECT_TBC_RELEASED:		Second RELEASE message sent
 */
enum dect_tbc_state {
	DECT_TBC_NONE,
	DECT_TBC_REQ_SENT,
	DECT_TBC_WAIT_RCVD,
	DECT_TBC_REQ_RCVD,
	DECT_TBC_RESPONSE_SENT,
	DECT_TBC_OTHER_WAIT,
	DECT_TBC_ESTABLISHED,
	DECT_TBC_RELEASING,
	DECT_TBC_RELEASED,
};

/**
 * enum dect_tbc_enc_state - DECT Traffic Bearer encryption state
 *
 * @DECT_TBC_ENC_DISABLED:	Encryption is disabled
 * @DECT_TBC_ENC_START_REQ_RCVD: Start request received (FP)
 * @DECT_TBC_ENC_START_REQ_SENT: Start request sent (PP)
 * @DECT_TBC_ENC_START_CFM_RCVD: Start confirm received (PP)
 * @DECT_TBC_ENC_START_CFM_SENT: Start confirm sent (FP)
 * @DECT_TBC_ENC_ENABLED:	Encryption is enabled
 */
enum dect_tbc_enc_state {
	DECT_TBC_ENC_DISABLED,
	DECT_TBC_ENC_START_REQ_RCVD,
	DECT_TBC_ENC_START_REQ_SENT,
	DECT_TBC_ENC_START_CFM_RCVD,
	DECT_TBC_ENC_START_CFM_SENT,
	DECT_TBC_ENC_ENABLED,
};

/**
 * enum dect_tbc_event - DECT Traffic Bearer events
 *
 * @DECT_TBC_SETUP_FAILED:	Bearer setup failed
 * @DECT_TBC_SETUP_COMPLETE:	Bearer setup complete
 * @DECT_TBC_ACK_RECEIVED:	Acknowledgement for C_S data received
 * @DECT_TBC_CIPHER_ENABLED:	Ciphering enabled
 * @DECT_TBC_CIPHER_DISABLED:	Ciphering disabled
 */
enum dect_tbc_event {
	DECT_TBC_SETUP_FAILED,
	DECT_TBC_SETUP_COMPLETE,
	DECT_TBC_ACK_RECEIVED,
	DECT_TBC_CIPHER_ENABLED,
	DECT_TBC_CIPHER_DISABLED,
};

/**
 * struct dect_tbc - DECT Traffic Bearer Control
 *
 * @list:		device TBC list node
 * @cell:		DECT cell
 * @id:			ID of associated MBC
 * @lbn:		logical bearer number
 * @txb:		TX bearer
 * @rxb:		RX bearer
 * @state:		Bearer establishment state
 * @tx_timer:		Transmit activation timer
 * @wd_timer:		Receive watchdog timer
 * @release_timer:	Release timer for unacknowledged release procedure
 * @normal_tx_timer:	Normal transmit timer for C-channel/I_N normal delay transmission
 * @normal_rx_timer:	Normal receive timer for C-channel/I_N normal delay delivery
 * @rx_timer:		Mimimum delay receive timer
 * @tx_timer:		Minimum delay transmit timer
 * @ck:			Cipher key
 * @enc_timer:		Encryption TX timer
 * @enc_state:		Encryption state
 * @enc_msg_cnt:	Encryption message retransmit counter
 * @c_rx_skb:		C_S segment for delivery to DLC
 * @c_tx_skb:		C_S segment for transmission in next TDMA frame
 * @c_tx_ok:		C_S segment was successfully transmitted
 * @b_rx_skb:		B-field data segment for delivery to DLC
 * @b_tx_skb:		B-field data segment for transmission in next TDMA frame
 * @bc:			Broadcast Control
 */
struct dect_tbc {
	struct list_head		list;
	struct dect_cell		*cell;

	struct dect_mbc_id		id;
	u8				lbn;

	struct dect_bearer		*txb;
	struct dect_bearer		*rxb;

	enum dect_tbc_state		state;
	struct dect_timer		wait_timer;
	struct dect_timer		wd_timer;
	struct dect_timer		release_timer;

	/* Normal transmit/receive half-frame based and slot based timers */
	struct dect_timer		normal_rx_timer;
	struct dect_timer		normal_tx_timer;
	struct dect_timer		rx_timer;
	struct dect_timer		tx_timer;

	/* Encryption */
	u64				ck;
	struct dect_timer		enc_timer;
	enum dect_tbc_enc_state		enc_state:8;
	u8				enc_msg_cnt;

	/* C_S channel */
	struct sk_buff			*c_rx_skb;
	struct sk_buff			*c_tx_skb;
	bool				c_tx_ok;

	struct sk_buff			*b_rx_skb;
	struct sk_buff			*b_tx_skb;

	struct dect_bc			bc;
};

#define DECT_TBC_RFPI_TIMEOUT		(5 * DECT_FRAMES_PER_SECOND)

enum dect_scan_status {
	DECT_SCAN_FAIL,
	DECT_SCAN_TIMEOUT,
	DECT_SCAN_COMPLETE,
};

/**
 * struct dect_irc - Idle receiver control
 *
 * @cell:		DECT cell
 * @trx:		DECT transceiver
 * @ari:		ARI filter
 * @ari_mask:		ARI filter mask
 * @idi:		identities information
 * @si:			system information
 * @notify:		notification callback
 * @rx_scn:		Scan carrier number (RX time base)
 * @tx_scn:		Scan carrier number (TX time base)
 * @rx_frame_timer:	rx_scn update timer
 * @tx_frame_timer:	tx_scn update timer
 */
struct dect_irc {
	struct dect_cell	*cell;
	struct dect_transceiver	*trx;

	struct dect_llme_req	lreq;

	struct dect_ari		ari;
	struct dect_ari		ari_mask;

	u16			timeout;
	u16			rssi;
	struct dect_idi		idi;
	struct dect_si		si;

	void			(*notify)(struct dect_cell *,
					  struct dect_transceiver *,
					  enum dect_scan_status);

	u8			rx_scn;
	u8			tx_scn;
	struct dect_timer	rx_frame_timer;
	struct dect_timer	tx_frame_timer;
	struct dect_bearer	scan_bearer;
};

#define DECT_IRC_SCN_OFF	3

struct dect_scan_result {
	struct dect_llme_req	lreq;
	struct dect_idi		idi;
	struct dect_si		si;
	u16			rssi;
};

/**
 * struct dect_csf_ops - Cell Site Function ops
 *
 * @set_mode:			set cell to PP/FP mode
 * @scan:			initiate scan for pari/pari_mask
 * @preload:			preload system information
 * @enable:			enable cell
 * @page_request:		deliver paging message
 * @tbc_initiate:		initiate a new connection
 * @tbc_confirm:		confirm an incoming connection
 * @tbc_release:		release a TBC
 * @tbc_enc_key_request:	set encryption key
 * @tbc_enc_eks_request:	enable/disable encryption
 *
 * The CSF ops define the interface in the direction CCF -> CSF.
 */
struct dect_cell_handle;
struct dect_csf_ops {
	int	(*set_mode)(const struct dect_cell_handle *,
			    enum dect_cluster_modes);
	int	(*scan)(const struct dect_cell_handle *,
			const struct dect_llme_req *lreq,
			const struct dect_ari *, const struct dect_ari *);
	int	(*preload)(const struct dect_cell_handle *,
			   const struct dect_ari *, u8,
			   const struct dect_si *);
	int	(*enable)(const struct dect_cell_handle *);

	void	(*page_request)(const struct dect_cell_handle *,
				struct sk_buff *);

	int	(*tbc_initiate)(const struct dect_cell_handle *,
				const struct dect_mbc_id *,
				const struct dect_channel_desc *);
	int	(*tbc_confirm)(const struct dect_cell_handle *,
			       const struct dect_mbc_id *);
	void	(*tbc_release)(const struct dect_cell_handle *,
			       const struct dect_mbc_id *,
			       enum dect_release_reasons);
	int	(*tbc_enc_key_request)(const struct dect_cell_handle *,
				       const struct dect_mbc_id *, u64 ck);
	int	(*tbc_enc_eks_request)(const struct dect_cell_handle *,
				       const struct dect_mbc_id *,
				       enum dect_cipher_states status);
	void	(*tbc_data_request)(const struct dect_cell_handle *,
				    const struct dect_mbc_id *,
				    enum dect_data_channels chan,
				    struct sk_buff *);

};

/**
 * struct dect_cell_handle - DECT cluster view of a cell
 *
 * @list:		cluster cell list node
 * @clh:		bound cluster handle
 * @ops:		cell site function ops
 * @rpn:		assigned radio part number
 * @portref:		cell control protocol port reference (remote cells)
 */
struct dect_cell_handle {
	struct list_head		list;
	struct dect_cluster_handle	*clh;
	const struct dect_csf_ops	*ops;
	u8				rpn;

	u32				portref;
};

enum dect_cell_states {
	DECT_CELL_ENABLED		= 1 << 0,
};

/**
 * struct dect_cell - DECT cell: one radio system
 *
 * @list:		cell list node
 * @name:		cells' name
 * @index:		unique numeric cell identifier
 * @flags:		operational and status flags
 * @handle:		cell handle
 * @lock:		lock
 * @mode:		operational mode (FP/PP)
 * @state:		bitmask of enum dect_cell_states
 * @idi:		FP System Identity
 * @fmid:		FMID (Fixed MAC IDentity)
 * @si:			FP System Information
 * @timer_sync_stamp:	Time (multiframe number) of last multiframe number sync
 * @a_rcv_stamp:	Time (jiffies) of last received A-Field with correct CRC
 * @nt_rcv_stamp:	Time (jiffies) of last received Nt-Tail containing the PARI
 * @bcs:		Broadcast Controllers
 * @cbc:		Connectionless Bearer Controller
 * @dbcs:		Dummy Bearer Controllers
 * @tbcs:		list of Traffic Bearer Controllers
 * @tbc_num_est:	Number of TBCs in ESTABLISHED state
 * @tbc_last_chd:	Channel description of last TBC leaving ESTABLISHED state
 * @chanlists:		list of channel lists for different channel types
 * @timer_base:		RX/TX timer bases
 * @trg:		DECT transceiver group
 */
struct dect_cell {
	struct list_head		list;
	char				name[DECTNAMSIZ];
	u32				index;
	u32				flags;

	struct dect_cell_handle		handle;

	spinlock_t			lock;
	enum dect_cluster_modes		mode;
	u32				state;

	/* identities */
	struct dect_idi			idi;
	u16				fmid;

	/* system information */
	struct dect_si			si;
	u32				blind_full_slots;

	/* PP state maintenance */
	u32				timer_sync_stamp;
	unsigned long			a_rcv_stamp;
	unsigned long			nt_rcv_stamp;

	/* Broadcast controllers and related data */
	struct dect_timer		page_timer;
	struct sk_buff_head		page_queue;
	struct sk_buff_head		page_fast_queue;

	struct sk_buff			*page_sdu;
	struct sk_buff_head		page_tx_queue;

	struct list_head		bcs;
	unsigned int			si_idx;

	struct dect_cbc			cbc;
	struct list_head		dbcs;

	struct list_head		tbcs;
	unsigned int			tbc_num_est;
	struct dect_channel_desc	tbc_last_chd;

	/* channel lists */
	struct list_head		chl_pending;
	struct list_head		chanlists;
	struct dect_channel_list	*chl_next;
	struct dect_channel_list	*chl;

	/* raw transmission queue */
	struct sk_buff_head		raw_tx_queue;

	struct dect_timer_base		timer_base[DECT_TIMER_BASE_MAX + 1];
	struct dect_transceiver_group	trg;
};

#define DECT_CELL_TIMER_RESYNC_TIMEOUT	8		/* T216: 8 multiframes */
#define DECT_CELL_A_RCV_TIMEOUT		(5 * HZ)	/* T207: 5 seconds */
#define DECT_CELL_NT_RCV_TIMEOUT	(20 * HZ)	/* T208: 20 seconds */

static inline u8 dect_normal_transmit_base(const struct dect_cell *cell)
{
	return cell->mode == DECT_MODE_FP ? 0 : DECT_HALF_FRAME_SIZE;
}

static inline u8 dect_normal_receive_base(const struct dect_cell *cell)
{
	return cell->mode == DECT_MODE_FP ? DECT_HALF_FRAME_SIZE : 0;
}

static inline u8 dect_normal_receive_end(const struct dect_cell *cell)
{
	return cell->mode == DECT_MODE_FP ? DECT_FRAME_SIZE - 1 :
					    DECT_HALF_FRAME_SIZE - 1;
}

#define dect_foreach_transmit_slot(slot, end, cell) \
	for ((slot) = dect_normal_transmit_base(cell), \
	     (end) = (slot) + DECT_HALF_FRAME_SIZE; \
	     (slot) < (end); (slot)++)

#define dect_foreach_receive_slot(slot, end, cell) \
	for ((slot) = dect_normal_receive_base(cell), \
	     (end) = (slot) + DECT_HALF_FRAME_SIZE; \
	     (slot) < (end); (slot)++)

extern struct dect_cell *dect_cell_get_by_index(u32 index);

extern void dect_cell_init(struct dect_cell *cell);
extern int dect_cell_bind(struct dect_cell *cell, u8 index);
extern void dect_cell_shutdown(struct dect_cell *cell);

extern int dect_cell_attach_transceiver(struct dect_cell *cell,
					struct dect_transceiver *trx);
extern void dect_cell_detach_transceiver(struct dect_cell *cell,
					 struct dect_transceiver *trx);

extern void dect_mac_rcv(struct dect_transceiver *trx,
			 struct dect_transceiver_slot *ts,
			 struct sk_buff *skb);
extern void dect_mac_report_rssi(struct dect_transceiver *trx,
				 struct dect_transceiver_slot *ts, u8 rssi);
extern void dect_mac_rx_tick(struct dect_transceiver_group *grp, u8 slot);
extern void dect_mac_tx_tick(struct dect_transceiver_group *grp, u8 slot);

extern void dect_mac_irc_rcv(struct dect_transceiver *trx, struct sk_buff *skb);
extern void dect_mac_irc_tick(struct dect_transceiver *trx);

#endif /* _NET_DECT_MAC_CSF_H */
