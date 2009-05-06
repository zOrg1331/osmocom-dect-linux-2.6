/*
 * DECT Transceiver Layer
 *
 * Copyright (c) 2009 Patrick McHardy <kaber@trash.net>
 */

#ifndef _NET_DECT_TRANSCEIVER_H
#define _NET_DECT_TRANSCEIVER_H

#include <linux/interrupt.h>
#include <linux/list.h>
#include <linux/skbuff.h>
#include <linux/dect.h>
#include <linux/dect_netlink.h>

#define DECT_RSSI_RANGE			255
#define DECT_RSSI_DBM_LOW		-93
#define DECT_RSSI_DBM_RANGE		60

static inline u8 dect_dbm_to_rssi_rel(s8 dbm)
{
	return dbm * DECT_RSSI_RANGE / DECT_RSSI_DBM_RANGE;
}

static inline u8 dect_dbm_to_rssi(s8 dbm)
{
	return dect_dbm_to_rssi_rel(dbm - DECT_RSSI_DBM_LOW);
}

#define DECT_RSSI_AVG_SCALE		3

static inline u16 dect_average_rssi(u16 cur, u16 sample)
{
	if (cur == 0)
		cur = sample << DECT_RSSI_AVG_SCALE;
	else {
		cur -= cur >> DECT_RSSI_AVG_SCALE;
		cur += sample;
	}
	return cur;
}

#define DECT_CARRIER_NUM		64

static inline u8 dect_next_carrier(u64 rfcars, u8 carrier)
{
	u64 tmp;

	if (WARN_ON(rfcars == 0))
		return 0;
	tmp = rfcars & ~((1ULL << (carrier + 1)) - 1);
	if (tmp == 0)
		tmp = rfcars;
	return ffs(tmp) - 1;
}

static inline u8 dect_prev_carrier(u64 rfcars, u8 carrier)
{
	u64 tmp;

	if (WARN_ON(rfcars == 0))
		return 0;
	tmp = rfcars & ((1ULL << carrier) - 1);
	if (tmp == 0)
		tmp = rfcars;
	return fls(tmp) - 1;
}

static inline u8 dect_carrier_sub(u64 rfcars, u8 carrier, u8 n)
{
	while (n != 0) {
		carrier = dect_prev_carrier(rfcars, carrier);
		n--;
	}
	return carrier;
}

static inline u8 dect_carrier_distance(u64 rfcars, u8 from, u8 to)
{
	if (from >= to) {
		/* clear bits between to and from */
		rfcars &= ~(((1ULL << (from - to)) - 1) << to);
	} else {
		/* clear bits not between from and to */
		rfcars &= ((1ULL << (to - from)) - 1) << from;
	}
	return hweight64(rfcars);
}

#define DECT_BAND_NUM			32
#define DECT_DEFAULT_BAND		0

#define DECT_FREQUENCY_F0		1897344	/* kHz */
#define DECT_CARRIER_WIDTH		1728	/* kHz */

/**
 * struct dect_band - DECT RF-band
 *
 * @band:		RF-band number
 * @carriers:		number of defined carriers
 * @frequency:		frequency of each carrier in kHz
 */
struct dect_band {
	u8	band;
	u8	carriers;
	u32	frequency[];
};

#define DECT_FRAME_SIZE			24
#define DECT_HALF_FRAME_SIZE		(DECT_FRAME_SIZE / 2)
#define DECT_FRAMES_PER_SECOND		100

#define DECT_SCAN_SLOT			0
#define DECT_SLOT_MASK			0x00ffffff

static inline u8 dect_next_slotnum(u8 slot)
{
	if (++slot == DECT_FRAME_SIZE)
		slot = 0;
	return slot;
}

static inline u8 dect_slot_add(u8 s1, u8 s2)
{
	return (s1 + s2) % DECT_FRAME_SIZE;
}

static inline u8 dect_slot_distance(u8 s1, u8 s2)
{
	return s2 >= s1 ? s2 - s1 : DECT_FRAME_SIZE + s2 - s1;
}

#define dect_foreach_slot(slot) \
	for ((slot) = 0; (slot) < DECT_FRAME_SIZE; (slot)++)

/**
 * enum dect_slot_types - DECT slot types
 *
 * @DECT_HALF_SLOT:	Half-slot format (240 bits)
 * @DECT_FULL_SLOT:	Full-slot format (480 bits)
 * @DECT_DOUBLE_SLOT:	Double-slot format (960 bits)
 */
enum dect_slot_types {
	DECT_HALF_SLOT,
	DECT_FULL_SLOT,
	DECT_DOUBLE_SLOT,
};

/**
 * enum dect_packet_types - DECT Physical Packet Types
 *
 * @DECT_PACKET_P00:	short physical packet P00, 96 bits, A-field only
 * @DECT_PACKET_P08:	low capacity physical packet P08j, 180 bits
 * @DECT_PACKET_P32:	basic physical packet P32, 420 bits
 * @DECT_PACKET_P80:	high capacity physical packet P80, 900 bits
 */
enum dect_packet_types {
	DECT_PACKET_P00,
	DECT_PACKET_P08,
	DECT_PACKET_P32,
	DECT_PACKET_P80,
	__DECT_PACKET_MAX
};
#define DECT_PACKET_MAX		(__DECT_PACKET_MAX - 1)

enum dect_packet_sizes {
	DECT_P00_SIZE		= 12,
	DECT_P08_SIZE		= 23,
	DECT_P32_SIZE		= 53,
	DECT_P80_SIZE		= 113,
};

#define DECT_PREAMBLE_SIZE	4

/**
 * enum dect_b_formats - DECT B-Field formats
 *
 * @DECT_B_NONE:	No B-field
 * @DECT_B_UNPROTECTED:	Unprotected B-field format
 * @DECT_B_PROTECTED:	Protected B-field format
 *
 * The B-Field format can be used by a transceiver for offloading X-CRC
 * calculation.
 */
enum dect_b_formats {
	DECT_B_NONE,
	DECT_B_UNPROTECTED,
	DECT_B_PROTECTED,
	__DECT_B_MAX
};
#define DECT_B_MAX		(__DECT_B_MAX - 1)

/**
 * struct dect_channel_desc - DECT physical channel description
 *
 * @pkt:	Packet type in use
 * @b_fmt:	B-Field format for checksum offloading
 * @slot:	Slot number
 * @carrier:	RF-carrier number
 */
struct dect_channel_desc {
	enum dect_packet_types		pkt;
	enum dect_b_formats		b_fmt;
	u8				slot;
	u8				carrier;
};

/**
 * struct dect_transceiver_slot - Transceiver TDMA slot
 *
 * @state:		current state
 * @desc:		channel description
 * @bearer:		associated bearer
 * @rssi:		averaged RSSI
 * @rx_bytes:		RX byte count
 * @rx_packets:		RX packet count
 * @tx_bytes:		TX byte count
 * @tx_packets:		TX packet count
 */
struct dect_transceiver_slot {
	enum dect_slot_states		state;
	struct dect_channel_desc	chd;
	struct dect_bearer		*bearer;

	u16				rssi;
	u32				rx_bytes;
	u32				rx_packets;
	u32				tx_bytes;
	u32				tx_packets;
};

/**
 * struct dect_transceiver_event - one atomic unit of work for the MAC layer
 *
 * @trx:		transceiver
 * @busy:		synchronizer
 * @list:		transceiver group events list node
 * @rx_queue:		received packets
 * @rssi:		RSSI measurement in scanning slots
 * @rssi_mask:		RSSI measurement positions
 * @slotpos:		transceiver slot position in TDMA frame
 *
 * A transceiver operates asynchronously to the MAC layer, but the MAC layer's
 * timing needs to be strictly synchronized to the receiver.
 *
 * This structure contains the packets from multiple consequitive slots received
 * by the receiver in one unit (up to ops->eventrate frames). Slotpos specifies
 * the transceivers current position in the TDMA frame (== the minimum current
 * time) and is used for timing purposes and slot maintenance operations of the
 * upcoming slots. A transceiver uses a fixed amount of these structure and
 * synchronizes with BH processing through the busy marker. When BH processing
 * is too slow, frames are dropped.
 */
struct dect_transceiver_event {
	struct dect_transceiver	*trx;
	atomic_t		busy;
	struct list_head	list;
	struct sk_buff_head	rx_queue;
	u8			rssi[DECT_HALF_FRAME_SIZE / 2];
	u8			rssi_mask;
	u8			slotpos;
};

struct dect_skb_trx_cb {
	struct dect_transceiver	*trx;
	u32			mfn;
	u8			frame;
	u8			slot;
	u8			rssi;
};

static inline struct dect_skb_trx_cb *DECT_TRX_CB(const struct sk_buff *skb)
{
	BUILD_BUG_ON(sizeof(struct dect_skb_trx_cb) > sizeof(skb->cb));
	return (struct dect_skb_trx_cb *)skb->cb;
}

/**
 * struct dect_transceiver_ops - DECT transceiver operations
 *
 * @disable:		shut the transceiver down
 * @enable:		bring the transceiver to operational state
 * @confirm:		confirm a received signal in slave mode
 * @unlock:		release a confirmed signal again
 * @lock:		lock to a signal
 * @set_mode:		set the mode (RX/TX/SCANNING) for a slot
 * @set_carrier:	set the RF-carrier for a slot
 * @set_band:		set the RF-band
 * @destructor:		destructor
 * @name		transceiver driver name
 * @slotmask:		bitmask of available slots
 * @eventrate:		rate at which slot events are generated, must be integral
 * 			divisor of the number of slots per TDMA half frame
 * @latency:		latency in slots until updates for a slot take effect
 *
 * A transceiver provides frame reception and transmission, signal strength
 * measurement as well as a reference clock for the MAC layer. It can exist
 * in two basic states:
 *
 * - master: doesn't need initial synchronization to a radio signal
 * - slave: needs to synchronize timing with a signal
 *
 * Only the first transceiver of a FP is a master, PPs are always slaves to
 * a FPs timing. Secondary and further transceivers of a FP also start as
 * slaves until they have synchronized to one of the already running
 * transceivers.
 *
 * Locking to a new signal works in multiple phases:
 *
 * 1) The ->enable() callback is invoked. The driver is expected to initiate a
 *    scan for a signal, during which it will pass on any received frame to the
 *    transceiver layer. As no framing has been established, all packets should
 *    indicate a slot number of zero.
 *
 * 2) While scanning for a signal, the ->set_carrier() callback may be invoked
 *    with a slot number of zero. The driver is expected to adjust the carrier
 *    on which it is scanning for a signal.
 *
 * 3) When the MAC layer determines interest in a received signal, the ->confirm()
 *    callback is invoked. The driver is expected to continue to pass frames from
 *    this signal to the MAC layer to establish framing.
 *
 * 3a) When the MAC layer is only collecting information for a scan, it may call
 *     the ->unlock callback to release a previously confirmed signal.
 *
 * 4) Once the MAC layer has determined framing relative to the slot timing, the
 *    ->lock() callback is invoked. At this point, only a single physical channel
 *    is received. The driver should synchronize the hardware to the framing to
 *    make it interrupt at the appropriate times.
 *
 */
struct dect_transceiver;
struct dect_transceiver_ops {
	void		(*disable)(const struct dect_transceiver *trx);
	void		(*enable)(const struct dect_transceiver *trx);

	void		(*confirm)(const struct dect_transceiver *trx);
	void		(*unlock)(const struct dect_transceiver *trx);
	void		(*lock)(const struct dect_transceiver *trx, u8 slot);

	void		(*set_mode)(const struct dect_transceiver *trx,
				    const struct dect_channel_desc *chd,
				    enum dect_slot_states mode);
	void		(*set_carrier)(const struct dect_transceiver *trx,
				       u8 slot, u8 carrier);
	void		(*tx)(const struct dect_transceiver *trx,
			      struct sk_buff *skb);

	u64		(*set_band)(const struct dect_transceiver *trx,
				    const struct dect_band *band);
	void		(*destructor)(struct dect_transceiver *trx);
	const char	*name;

	u32		slotmask;
	u8		eventrate;
	u8		latency;
};

/**
 * enum dect_transceiver_modes - Transceiver synchronization modes
 *
 * @DECT_TRANSCEIVER_MASTER:	Transceiver determines reference time (FP)
 * @DECT_TRANSCEIVER_SLAVE:	Transceiver is slave to foreign reference timing
 */
enum dect_transceiver_modes {
	DECT_TRANSCEIVER_MASTER,
	DECT_TRANSCEIVER_SLAVE,
};

/**
 * enum dect_transceiver_states - transceiver synchronization states
 *
 * @DECT_TRANSCEIVER_STOPPED:		transceiver is inactive
 * @DECT_TRANSCEIVER_UNLOCKED:		transceiver is not synchronized to any RFP
 * @DECT_TRANSCEIVER_LOCK_PENDING:	transceiver is receiving RFP transmissions,
 * 					but has not obtained frame synchonization
 * @DECT_TRANSCEIVER_LOCKED:		the transceiver has achieved frame and
 * 					multiframe lock to an RFP
 *
 * These correspond to the ETS 300 175-3 Annex D PT MAC layer states, but are
 * per transceiver as we also need to synchronize secondary transceivers.
 */
enum dect_transceiver_states {
	DECT_TRANSCEIVER_STOPPED,
	DECT_TRANSCEIVER_UNLOCKED,
	DECT_TRANSCEIVER_LOCK_PENDING,
	DECT_TRANSCEIVER_LOCKED,
};

/**
 * struct dect_transceiver_stats - transceiver statistics
 *
 * @event_busy:		events lost due to MAC layer busy
 * @event_late:		events lost due to transceiver late
 */
struct dect_transceiver_stats {
	u32					event_busy;
	u32					event_late;
};

/**
 * struct dect_transceiver - DECT transceiver
 *
 * @list:		transceiver list node
 * @ops:		transceiver ops
 * @name:		transceiver identity
 * @stats:		transceiver statistics
 * @mode:		synchronization mode
 * @state:		synchronization state
 * @band:		current RF-band
 * @carriers:		bitmask of supported carriers in the current band
 * @slots:		transceiver slot state
 * @index:		cell transceiver index
 * @segno:		transceiver receive sequence number
 * @cell:		cell the transceiver is assigned to
 * @irc:		idle receiver control
 * @event:		dynamic amount of transceiver event structures
 *
 * Following the event structures is the private driver data.
 */
struct dect_transceiver {
	struct list_head			list;
	const struct dect_transceiver_ops	*ops;
	char					name[DECTNAMSIZ];

	struct dect_transceiver_stats		stats;
	enum dect_transceiver_modes		mode;
	enum dect_transceiver_states		state;

	const struct dect_band			*band;
	u64					carriers;

	struct dect_transceiver_slot		slots[DECT_FRAME_SIZE];
	u32					blind_full_slots;

	u8					index;
	u32					seqno;
	struct dect_cell			*cell;
	struct dect_irc				*irc;
	struct dect_transceiver_event		event[];
};

static inline void *dect_transceiver_priv(const struct dect_transceiver *trx)
{
	return (void *)&trx->event[DECT_HALF_FRAME_SIZE / trx->ops->eventrate];
}

static inline bool dect_slot_available(const struct dect_transceiver *trx, u8 slot)
{
	return trx->ops->slotmask & (1 << slot);
}

extern struct dect_transceiver *dect_transceiver_alloc(const struct dect_transceiver_ops *ops,
						       unsigned int priv);
extern void dect_transceiver_free(struct dect_transceiver *trx);
extern int dect_register_transceiver(struct dect_transceiver *trx);
extern void dect_unregister_transceiver(struct dect_transceiver *trx);

extern void dect_transceiver_enable(struct dect_transceiver *trx);
extern void dect_transceiver_disable(struct dect_transceiver *trx);

extern void dect_transceiver_confirm(struct dect_transceiver *trx);
extern void dect_transceiver_unlock(struct dect_transceiver *trx);
extern void dect_transceiver_lock(struct dect_transceiver *trx, u8 slot);

extern int dect_transceiver_set_band(struct dect_transceiver *trx, u8 bandnum);

static inline void dect_set_channel_mode(struct dect_transceiver *trx,
					 const struct dect_channel_desc *chd,
					 enum dect_slot_states mode)
{
	trx->ops->set_mode(trx, chd, mode);
	trx->slots[chd->slot].state = mode;
	trx->slots[chd->slot].chd.pkt = chd->pkt;
	trx->slots[chd->slot].chd.b_fmt = chd->b_fmt;
}

static inline void dect_set_carrier(struct dect_transceiver *trx,
				    u8 slot, u8 carrier)
{
	trx->slots[slot].chd.carrier = carrier;
	trx->slots[slot].rssi = 0;
	trx->ops->set_carrier(trx, slot, carrier);
}

static inline void dect_transceiver_tx(struct dect_transceiver *trx,
				       struct sk_buff *skb)
{
	u8 slot = DECT_TRX_CB(skb)->slot;

	trx->ops->tx(trx, skb);
	trx->slots[slot].tx_bytes += skb->len;
	trx->slots[slot].tx_packets++;
}

extern struct sk_buff *dect_transceiver_alloc_skb(struct dect_transceiver *trx, u8 slot);

static inline struct dect_transceiver_event *
dect_transceiver_event(struct dect_transceiver *trx, u8 n, u8 slotpos)
{
	struct dect_transceiver_event *event;

	event = &trx->event[n];
	if (unlikely(!atomic_add_unless(&event->busy, 1, 1))) {
		trx->stats.event_busy++;
		return NULL;
	}
	event->slotpos = slotpos;
	return event;
}

static inline void dect_transceiver_record_rssi(struct dect_transceiver_event *event,
						u8 slot, u8 rssi)
{
	u8 idx;

	idx = slot % event->trx->ops->eventrate;
	event->rssi[idx] = rssi;
	event->rssi_mask |= 1 << idx;
}

static inline void dect_release_transceiver_event(struct dect_transceiver_event *event)
{
	event->rssi_mask = 0;
	smp_mb__before_atomic_dec();
	atomic_dec(&event->busy);
}

extern struct list_head dect_transceiver_list;

enum dect_transceiver_events {
	DECT_TRANSCEIVER_REGISTER,
	DECT_TRANSCEIVER_UNREGISTER,
};

extern void dect_register_notifier(struct notifier_block *nb);
extern void dect_unregister_notifier(struct notifier_block *nb);

#define DECT_TRX_GROUP_MAX	16

/**
 * struct dect_transceiver_group
 *
 * @trx:		Transceiver array
 * @trxmask:		Mask of present transceivers
 * @latency:		Maximum latency of all transceivers
 * @blind_full_slots:	combined blind full slots state of all transceivers
 * @tasklet:		Event processing tasklet
 * @lock:		Event list lock
 * @events:		List of queued events
 * @seqno:		Transceiver event loss detection
 * @slot_low:		First unhandled slot
 * @slot_high:		First slot after slot window
 * @slots:		merged events for window slot_low - slot_high
 */
struct dect_transceiver_group {
	struct dect_transceiver			*trx[DECT_TRX_GROUP_MAX];
	u16					trxmask;
	u8					latency;
	u32					blind_full_slots;

	struct tasklet_struct			tasklet;
	spinlock_t				lock;
	struct list_head			events;

	u32					seqno;
	u8					slot_low;
	u8					slot_high;
	struct {
		struct sk_buff_head		queue;
		u16				mask;
		u8				rssi[DECT_TRX_GROUP_MAX];
	} slots[DECT_HALF_FRAME_SIZE];
};

extern void dect_transceiver_group_init(struct dect_transceiver_group *trg);
extern int dect_transceiver_group_add(struct dect_transceiver_group *trg,
				      struct dect_transceiver *trx);
extern void dect_transceiver_group_remove(struct dect_transceiver_group *trg,
					  struct dect_transceiver *trx);

extern bool dect_transceiver_channel_available(const struct dect_transceiver *trx,
					       const struct dect_channel_desc *chd);
extern bool dect_transceiver_reserve(struct dect_transceiver_group *trg,
				     struct dect_transceiver *trx,
				     const struct dect_channel_desc *chd);
extern bool dect_transceiver_release(struct dect_transceiver_group *trg,
				     struct dect_transceiver *trx,
				     const struct dect_channel_desc *chd);

extern void dect_transceiver_queue_event(struct dect_transceiver *trx,
					 struct dect_transceiver_event *ev);

#define dect_first_transceiver(trg)					\
({									\
	struct dect_transceiver_group *_trg = (void *)(trg);		\
	u32 mask = _trg->trxmask;					\
	mask ? (_trg)->trx[ffs(mask) - 1] : NULL; })

#define dect_next_transceiver(trx, trg)					\
({									\
	struct dect_transceiver_group *_trg = (void *)(trg);		\
	u32 mask = _trg->trxmask;					\
	mask &= ~((1 << ((trx)->index + 1)) - 1);			\
	mask ? (_trg)->trx[ffs(mask) - 1] : NULL; })

#define dect_foreach_transceiver(trx, trg)				\
	for ((trx) = dect_first_transceiver(trg);			\
	     (trx) != NULL;						\
	     (trx) = dect_next_transceiver(trx, trg))

#define dect_last_transceiver(trg)					\
({									\
	struct dect_transceiver_group *_trg = (void *)(trg);		\
	u32 mask = _trg->trxmask;					\
	mask ? (_trg)->trx[fls(mask) - 1] : NULL; })

#define dect_prev_transceiver(trx, trg)					\
({									\
	struct dect_transceiver_group *_trg = (void *)(trg);		\
	u32 mask = _trg->trxmask;					\
	mask &= (1 << (trx)->index) - 1;				\
	mask ? (_trg)->trx[fls(mask) - 1] : NULL; })

#define dect_foreach_transceiver_reverse(trx, trg)			\
	for ((trx) = dect_last_transceiver(trg);			\
	     (trx) != NULL;						\
	     (trx) = dect_prev_transceiver(trx, trg))

extern int dect_transceiver_module_init(void);
extern void dect_transceiver_module_exit(void);

#endif /* _NET_DECT_TRANSCEIVER_H */
