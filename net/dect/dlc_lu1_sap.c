/*
 * DECT DLC LU1 SAP sockets
 *
 * Copyright (c) 2009-2011 Patrick McHardy <kaber@trash.net>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/socket.h>
#include <linux/net.h>
#include <linux/dect.h>
#include <net/sock.h>
#include <net/dect/dect.h>
#include <net/dect/transceiver.h>

#define DECT_LU1_FRAME_NONE	255
#define DECT_LU1_PREQUEUE_LEN	5

#define lu1_debug(lu1, fmt, args...) \
	pr_debug("LU1: rx_bytes: %u tx_bytes: %u " fmt, \
		 (lu1)->qstats.rx_bytes, (lu1)->qstats.tx_bytes, \
		 ## args)

struct dect_lu1_sap {
	struct sock			sk;
	int				index;
	struct dect_ulei		ulei;
	struct dect_mac_conn		*mc;
	u8				frame;
	u8				slot;
	struct sk_buff			*last;
	struct dect_lux			lux;
	struct dect_lu1_queue_stats	qstats;
};

/* Seamless handover slot offsets as per ETS 300 175-3 Annex F */
static const u8 slot_offset_tbl[][DECT_HALF_FRAME_SIZE] = {
	[DECT_FULL_SLOT] = {
		[0]		= 0,
		[1]		= 1,
		[2]		= 3,
		[3]		= 5,
		[4]		= 6,
		[5]		= 8,
		[6]		= 10,
		[7]		= 11,
		[8]		= 13,
		[9]		= 15,
		[10]		= 16,
		[11]		= 18,
	},
	[DECT_DOUBLE_SLOT] = {
		[0]		= 0,
		[2]		= 8,
		[4]		= 16,
		[6]		= 24,
		[8]		= 32,
		[10]		= 40,
	},
	[DECT_LONG_SLOT_640] = {
		[0]		= 0,
		[1]		= 3,
		[2]		= 6,
		[3]		= 10,
		[4]		= 13,
		[5]		= 16,
		[6]		= 20,
		[7]		= 23,
		[8]		= 26,
		[9]		= 30,
		[10]		= 33,
	},
};

static struct sk_buff *dect_lu1_dequeue(struct dect_lux *lux)
{
	struct dect_lu1_sap *lu1 = container_of(lux, struct dect_lu1_sap, lux);
	struct dect_cluster *cl = lu1->mc->cl;
	struct sock *sk = &lu1->sk;
	struct sk_buff *skb, *clone, *head = NULL;
	u8 need = dect_b_field_size(lu1->mc->mcp.slot);
	u8 frame, slot, off, last_off;

	/* Fill queue up to prequeue len before delivering the first frame */
	if (lu1->frame == DECT_LU1_FRAME_NONE &&
	    sk->sk_write_queue.qlen < DECT_LU1_PREQUEUE_LEN)
		return NULL;

	/* Calculate seamless handover data offset */
	frame = __dect_framenum(&cl->timer_base[DECT_TIMER_TX]);
	slot  = __dect_slotnum(&cl->timer_base[DECT_TIMER_TX]);
	if (slot >= DECT_HALF_FRAME_SIZE)
		slot -= DECT_HALF_FRAME_SIZE;

	last_off = slot_offset_tbl[lu1->mc->mcp.slot][lu1->slot];
	off      = slot_offset_tbl[lu1->mc->mcp.slot][slot];

	if (off > last_off)
		off -= last_off;
	else
		off += need - last_off;

	/* Advance queue */
	lu1_debug(lu1, "dequeue: slot: %u off: %u need: %u\n", slot, off, need);
	if (lu1->frame != DECT_LU1_FRAME_NONE && lu1->frame != frame)
		lu1->qstats.tx_bytes -= skb_queue_pull(&sk->sk_write_queue, off);

	lu1->frame = frame;
	lu1->slot  = slot;

	/* Duplicate data from last frame on underflow */
	if (lu1->qstats.tx_bytes < need && lu1->last) {
		lu1->qstats.tx_underflow++;
		skb = skb_clone(lu1->last, GFP_ATOMIC);
		if (skb == NULL)
			goto err;
		skb_pull(skb, skb->len - (need - lu1->qstats.tx_bytes));

		skb_queue_head(&sk->sk_write_queue, skb);
		lu1->qstats.tx_bytes += skb->len;
		lu1_debug(lu1, "fill: len: %u need: %u\n", skb->len, need);

	}

	skb = NULL;
	while (need > 0) {
		if (skb == NULL) {
			skb = skb_peek(&sk->sk_write_queue);
			if (skb == NULL)
				goto underflow;
			/* The head needs to be copied to avoid sharing the
			 * frag list. */
			clone = skb_copy(skb, GFP_ATOMIC);
		} else {
			if (skb_queue_is_last(&sk->sk_write_queue, skb))
				goto underflow;
			skb = skb->next;
			clone = skb_clone(skb, GFP_ATOMIC);
		}

		if (clone == NULL)
			goto err;

		if (clone->len > need)
			skb_trim(clone, need);
		need -= clone->len;

		head = skb_append_frag(head, clone);
		lu1_debug(lu1, "dequeue: head: %u need: %u\n", head->len, need);
	}

	if (skb_linearize(head) < 0)
		goto err;

	kfree_skb(lu1->last);
	lu1->last = skb_get(head);

	lu1_debug(lu1, "dequeued: len: %u\n", head->len);
	return head;

underflow:
	lu1->qstats.tx_underflow++;
err:
	kfree_skb(head);
	lu1_debug(lu1, "dequeue: no frame available\n");
	return NULL;
}

static void dect_lu1_enqueue(struct dect_lux *lux, struct sk_buff *skb)
{
	struct dect_lu1_sap *lu1 = container_of(lux, struct dect_lu1_sap, lux);
	unsigned int len = skb->len;

	if (sock_queue_rcv_skb(&lu1->sk, skb) < 0)
		kfree_skb(skb);
	else
		lu1->qstats.rx_bytes += len;
}

static void dect_lu1_disconnect(struct dect_lux *lux)
{
	struct dect_lu1_sap *lu1 = container_of(lux, struct dect_lu1_sap, lux);
	struct sock *sk = &lu1->sk;

	sk->sk_state = DECT_SK_RELEASED;
	sk->sk_err = ENETDOWN;
	if (!sock_flag(sk, SOCK_DEAD))
		sk->sk_error_report(sk);
	lu1->mc->fbx = NULL;
	dect_dlc_mac_conn_unbind(lu1->mc);
	lu1->mc = NULL;
}

static const struct dect_lux_ops dect_lu1_ops = {
	.dequeue	= dect_lu1_dequeue,
	.enqueue	= dect_lu1_enqueue,
	.disconnect	= dect_lu1_disconnect,
};

static inline struct dect_lu1_sap *dect_lu1_sap(struct sock *sk)
{
	return (struct dect_lu1_sap *)sk;
}

static int dect_parse_ulei(struct dect_ulei *ulei,
			   const struct sockaddr_dect_lu *addr)
{
	if (dect_parse_ari(&ulei->mci.ari, (u64)addr->dect_ari << 24) == 0)
		return -EINVAL;
	dect_parse_pmid(&ulei->mci.pmid, addr->dect_pmid);
	ulei->mci.lcn = addr->dect_lcn;
	return 0;
}

static void dect_build_ulei(struct sockaddr_dect_lu *addr,
			    const struct dect_ulei *ulei)
{
	addr->dect_family = AF_DECT;
	addr->dect_pmid   = dect_build_pmid(&ulei->mci.pmid);
	addr->dect_lcn    = ulei->mci.lcn;
}

static int dect_lu1_init(struct sock *sk)
{
	struct dect_lu1_sap *lu1 = dect_lu1_sap(sk);

	sk->sk_state = DECT_SK_RELEASED;
	lu1->frame   = DECT_LU1_FRAME_NONE;
	return 0;
}

static void dect_lu1_close(struct sock *sk, long timeout)
{
	struct dect_lu1_sap *lu1 = dect_lu1_sap(sk);

	if (sk->sk_state == DECT_SK_ESTABLISHED) {
		lu1->mc->fbx = NULL;
		dect_dlc_mac_conn_unbind(lu1->mc);
		sock_prot_inuse_add(sock_net(sk), sk->sk_prot, -1);
	}

	__skb_queue_purge(&sk->sk_receive_queue);
	__skb_queue_purge(&sk->sk_write_queue);
	kfree_skb(lu1->last);

	sock_orphan(sk);
	sock_put(sk);
}

static int dect_lu1_getname(struct sock *sk, struct sockaddr *uaddr,
			     int *len, int peer)
{
	struct sockaddr_dect_lu *addr = (struct sockaddr_dect_lu *)uaddr;
	struct dect_lu1_sap *lu1 = dect_lu1_sap(sk);

	if (peer)
		return -EOPNOTSUPP;

	addr->dect_index = lu1->index;
	dect_build_ulei(addr, &lu1->ulei);
	*len = sizeof(*addr);
	return 0;
}

static int dect_lu1_connect(struct sock *sk, struct sockaddr *uaddr, int len)
{
	struct sockaddr_dect_lu *addr = (struct sockaddr_dect_lu *)uaddr;
	struct dect_lu1_sap *lu1 = dect_lu1_sap(sk);
	struct dect_cluster *cl;
	struct dect_ulei ulei;
	struct dect_mac_conn *mc;
	int err;

	err = dect_parse_ulei(&ulei, addr);
	if (err < 0)
		goto err1;

	err = -ENODEV;
	cl = dect_cluster_get_by_index(addr->dect_index);
	if (cl == NULL)
		goto err1;

	err = -ENETDOWN;
	mc = dect_mac_conn_get_by_mci(cl, &ulei.mci);
	if (mc == NULL)
		goto err1;
	WARN_ON(mc->state == DECT_MAC_CONN_CLOSED);

	err = -EBUSY;
	if (mc->fbx != NULL)
		goto err1;

	memcpy(&lu1->ulei, &ulei, sizeof(lu1->ulei));

	sock_prot_inuse_add(sock_net(sk), sk->sk_prot, 1);
	sk->sk_state = DECT_SK_ESTABLISHED;

	lu1->lux.fbx.ops = &dect_fbn_ops;
	lu1->lux.ops = &dect_lu1_ops;
	lu1->mc = mc;
	mc->fbx = &lu1->lux.fbx;
	dect_dlc_mac_conn_bind(lu1->mc);
	pr_debug("LU1: bound to MCEI %u\n", mc->mcei);
	return 0;

err1:
	return err;
}

static int dect_lu1_getsockopt(struct sock *sk, int level, int optname,
			       char __user *optval, int __user *optlen)
{
	struct dect_lu1_sap *lu1 = dect_lu1_sap(sk);
	int len;

	if (get_user(len, optlen))
		return -EFAULT;
	if (len < 0)
		return -EINVAL;

	switch (optname) {
	case DECT_LU1_QUEUE_STATS:
		if (len > sizeof(lu1->qstats))
			len = sizeof(lu1->qstats);
		if (put_user(len, optlen) ||
		    copy_to_user(optval, &lu1->qstats, len))
			return -EFAULT;
		break;
	default:
		return -ENOPROTOOPT;
	}

	return 0;
}

static int dect_lu1_recvmsg(struct kiocb *iocb, struct sock *sk,
			    struct msghdr *msg, size_t len,
			    int noblock, int flags, int *addr_len)
{
	struct dect_lu1_sap *lu1 = dect_lu1_sap(sk);
	struct sk_buff *skb;
	size_t copied = 0, copy;
	long timeo;
	int err = 0;

	if (flags & (MSG_OOB | MSG_TRUNC))
		return -EOPNOTSUPP;

	lock_sock(sk);

	if (sk->sk_state != DECT_SK_ESTABLISHED) {
		err = -ENOTCONN;
		goto out;
	}

	timeo = sock_rcvtimeo(sk, noblock);

	while (copied < len) {
		skb = skb_peek(&sk->sk_receive_queue);
		if (skb != NULL)
			goto copy;

		if (!timeo) {
			err = -EAGAIN;
			break;
		}

		if (signal_pending(current)) {
			err = sock_intr_errno(timeo);
			break;
		}

		sk_wait_data(sk, &timeo);
		continue;

copy:
		copy = len - copied;
		if (copy > skb->len)
			copy = skb->len;

		err = skb_copy_datagram_iovec(skb, 0, msg->msg_iov, copy);
		if (err < 0)
			break;
		copied += copy;

		if (copy < skb->len) {
			__skb_pull(skb, copy);
			break;
		} else
			sk_eat_skb(sk, skb, 0);
	}

out:
	lu1->qstats.rx_bytes -= copied;
	if (copied < len)
		lu1->qstats.rx_underflow++;

	release_sock(sk);
	lu1_debug(lu1, "recvmsg: dequeued: %zu len: %zu\n", copied, len);
	return copied ? : err;
}

static int dect_lu1_sendmsg(struct kiocb *kiocb, struct sock *sk,
			    struct msghdr *msg, size_t len)
{
	struct dect_lu1_sap *lu1 = dect_lu1_sap(sk);
	struct sk_buff *skb;
	int err;

	if (msg->msg_flags & MSG_OOB)
		return -EOPNOTSUPP;

	if (sk->sk_state != DECT_SK_ESTABLISHED)
		return -ENOTCONN;

	skb = sock_alloc_send_skb(sk, len, msg->msg_flags & MSG_DONTWAIT, &err);
	if (skb == NULL)
		goto err1;
	err = memcpy_fromiovec(skb_put(skb, len), msg->msg_iov, len);
	if (err < 0)
		goto err2;

	skb_queue_tail(&sk->sk_write_queue, skb);
	lu1->qstats.tx_bytes += len;
	lu1_debug(lu1, "sendmsg: queued: %zu\n", len);
	return len;

err2:
	kfree_skb(skb);
err1:
	return err;
}

static struct dect_proto dect_lu1_proto = {
	.type			= SOCK_STREAM,
	.protocol		= DECT_LU1_SAP,
	.capability		= -1,
	.ops			= &dect_stream_ops,
	.proto.name		= "DECT_LU1_SAP",
	.proto.owner		= THIS_MODULE,
	.proto.obj_size		= sizeof(struct dect_lu1_sap),
	.proto.init		= dect_lu1_init,
	.proto.close		= dect_lu1_close,
	.proto.connect		= dect_lu1_connect,
	.proto.getsockopt	= dect_lu1_getsockopt,
	.proto.recvmsg		= dect_lu1_recvmsg,
	.proto.sendmsg		= dect_lu1_sendmsg,
	.getname		= dect_lu1_getname,
};

static int __init dect_lu1_sap_module_init(void)
{
	BUILD_BUG_ON(sizeof(struct sockaddr_dect_lu) >
		     sizeof(struct sockaddr));
	return dect_proto_register(&dect_lu1_proto);
}

static void dect_lu1_sap_module_exit(void)
{
	dect_proto_unregister(&dect_lu1_proto);
}

module_init(dect_lu1_sap_module_init);
module_exit(dect_lu1_sap_module_exit);

MODULE_AUTHOR("Patrick McHardy <kaber@trash.net>");
MODULE_DESCRIPTION("DECT DLC LU1 SAP sockets");
MODULE_LICENSE("GPL");

MODULE_ALIAS_NET_PF_PROTO(PF_DECT, DECT_LU1_SAP);
