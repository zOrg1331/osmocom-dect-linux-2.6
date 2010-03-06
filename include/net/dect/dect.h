#ifndef _NET_DECT_DECT_H
#define _NET_DECT_DECT_H

#define DECT_FRAMES_PER_MULTIFRAME	16

static inline u8 dect_next_framenum(u8 framenum)
{
	if (++framenum == DECT_FRAMES_PER_MULTIFRAME)
		framenum = 0;
	return framenum;
}

static inline u8 dect_framenum_add(u8 f1, u8 f2)
{
	return (f1 + f2) % DECT_FRAMES_PER_MULTIFRAME;
}

#define DECT_MULTIFRAME_MASK		0x00ffffff

static inline u32 dect_next_mfn(u32 mfn)
{
	if (++mfn == (1 << 24) - 1)
		mfn = 0;
	return mfn;
}

static inline u32 dect_mfn_add(u32 mfn1, u32 mfn2)
{
	return (mfn1 + mfn2) & DECT_MULTIFRAME_MASK;
}

/* Compare multiframe numbers, considering overflows */
static inline bool dect_mfn_before(u32 mfn1, u32 mfn2)
{
	return (s32)((mfn2 << 8) - (mfn1 << 8)) > 0;
}

static inline bool dect_mfn_after(u32 mfn1, u32 mfn2)
{
	return dect_mfn_before(mfn2, mfn1);
}

#include <linux/dect.h>
#include <net/dect/identities.h>
#include <net/dect/mac_ccf.h>
#include <net/dect/dlc.h>

extern void __acquires(dect_cfg_mutex) dect_lock(void);
extern void __releases(dect_cfg_mutex) dect_unlock(void);

/**
 * struct dect_cluster - DECT cluster of up to 8/256 cells
 *
 * @list:		device list node
 * @name:		device identifier
 * @index:		unique numeric cluster identifier
 * @mode:		device mode (FP/PP/monitor)
 * @pari:		primary access rights identifier
 * @si:			system information
 * @bmc:		Broadcast Message Control
 * @cmc:		Connectionless Message Control
 * @mbcs:		Multi-Bearer Controllers
 * @cells:		DECT cells
 */
struct dect_cluster {
	struct list_head		list;
	char				name[DECTNAMSIZ];
	int				index;

	u32				tipc_id;
	u32				tipc_portref;
	struct dect_cluster_handle	handle;

	enum dect_cluster_modes		mode;

	spinlock_t			lock;

	struct dect_ari			pari;
	struct dect_si			si;

	u32				pmid;

	struct list_head		cells;
	struct dect_bmc			bmc;
	struct dect_cmc			cmc;
	struct list_head		mbcs;

	u32				mcei_rover;
	struct list_head		mac_connections;
};

extern void dect_cluster_init(struct dect_cluster *cl);
extern void dect_cluster_shutdown(struct dect_cluster *cl);

extern struct dect_cluster *dect_cluster_get_by_index(int index);
extern struct dect_cluster *dect_cluster_get_by_pari(const struct dect_ari *ari);

/**
 * struct dect_llme_req - LLME netlink request
 *
 * @nlh:		netlink header
 * @nlpid:		netlink socket PID
 */
struct dect_llme_req {
	struct nlmsghdr		nlh;
	u32			nlpid;
};

struct dect_scan_result;
extern void dect_llme_scan_result_notify(const struct dect_cluster *cl,
					 const struct dect_scan_result *res);

#include <net/sock.h>

extern const struct proto_ops dect_stream_ops;
extern const struct proto_ops dect_dgram_ops;

struct dect_proto {
	unsigned int		type;
	unsigned int		protocol;
	int			capability;
	const struct proto_ops	*ops;
	int			(*getname)(struct sock *sk,
					   struct sockaddr *uaddr, int *len,
					   int peer);
	struct proto		proto;
};

#include <net/tcp_states.h>

enum {
	DECT_SK_ESTABLISHED		= TCP_ESTABLISHED,
	DECT_SK_ESTABLISH_PENDING	= TCP_SYN_SENT,
	DECT_SK_RELEASED		= TCP_CLOSE,
	DECT_SK_RELEASE_PENDING		= TCP_CLOSING,
	DECT_SK_LISTEN			= TCP_LISTEN,
};

struct dect_csk {
	struct sock		sk;
	struct hlist_head	accept_queue;
};

static inline struct dect_csk *dect_csk(const struct sock *sk)
{
	return (struct dect_csk *)sk;
}

extern int dect_proto_register(struct dect_proto *proto);
extern void dect_proto_unregister(struct dect_proto *proto);

struct dect_skb_sk_cb {
	//struct dect_skb_trx_cb	cb;
	int			index;
};

#define DECT_SK_CB(skb)		((struct dect_skb_sk_cb *)(skb)->cb)

static inline int dect_sock_queue_rcv_skb(struct sock *sk, struct sk_buff *skb)
{
	/*
	 * Release the transceiver reference, it is only valid in IRQ and
	 * softirq context.
	 */
	//FIXME
	//DECT_SK_CB(skb)->index = DECT_CB(skb)->trx->dev->index;
	return sock_queue_rcv_skb(sk, skb);
}

struct dect_notification {
	u32		type;
};

#define DECT_NOTIFY_CB(skb)	((struct dect_notification *)(skb)->cb)

extern struct sk_buff *dect_alloc_notification(u32 type, const void *data,
					       unsigned int size);

extern void (*dect_raw_rcv_hook)(struct sk_buff *skb);
static inline void dect_raw_rcv(struct sk_buff *skb)
{
	typeof(dect_raw_rcv_hook) dect_raw_rcv;

	rcu_read_lock();
	dect_raw_rcv = dect_raw_rcv_hook;
	if (dect_raw_rcv != NULL)
		dect_raw_rcv(skb);
	rcu_read_unlock();
}

extern int dect_af_module_init(void);
extern void dect_af_module_exit(void);

extern int dect_bsap_module_init(void);
extern void dect_bsap_module_exit(void);
extern int dect_ssap_module_init(void);
extern void dect_ssap_module_exit(void);

extern int dect_netlink_module_init(void);
extern void dect_netlink_module_exit(void);

extern struct sk_buff *skb_append_frag(struct sk_buff *head, struct sk_buff *skb);

#endif /* _NET_DECT_DECT_H */
