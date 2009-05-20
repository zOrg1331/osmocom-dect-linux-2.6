/*
 * DECT RAW sockets
 *
 * Copyright (c) 2009 Patrick McHardy <kaber@trash.net>
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
#include <net/dect/mac_csf.h>

static HLIST_HEAD(dect_raw_sockets);

struct dect_raw_sk {
	struct sock		sk;
};

static inline struct dect_raw_sk *dect_raw_sk(struct sock *sk)
{
	return (struct dect_raw_sk *)sk;
}

static void __dect_raw_rcv(struct sk_buff *skb)
{
	struct dect_cell *cell = DECT_TRX_CB(skb)->trx->cell;
	struct hlist_node *node;
	struct sk_buff *skb2;
	struct sock *sk;

	sk_for_each_bound(sk, node, &dect_raw_sockets) {
		if (sk->sk_bound_dev_if &&
		    sk->sk_bound_dev_if != cell->index)
			continue;

		skb2 = skb_clone(skb, GFP_ATOMIC);
		if (skb2 == NULL) {
			sk->sk_err = -ENOMEM;
			sk->sk_error_report(sk);
		} else {
			/* Release the transceiver reference, it is only valid
			 * in IRQ and softirq context.
			 */
			DECT_TRX_CB(skb)->trx = NULL;
			if (dect_sock_queue_rcv_skb(sk, skb2) < 0)
				kfree_skb(skb2);
		}
	}
}

static void dect_raw_close(struct sock *sk, long timeout)
{
	if (!hlist_unhashed(&sk->sk_bind_node))
		__sk_del_bind_node(sk);
	sock_put(sk);
}

static int dect_raw_bind(struct sock *sk, struct sockaddr *uaddr, int len)
{
	struct sockaddr_dect *addr = (struct sockaddr_dect *)uaddr;

	if (len < sizeof(*addr) || addr->dect_family != AF_DECT)
		return -EINVAL;

	if (addr->dect_index != 0 &&
	    !dect_cell_get_by_index(addr->dect_index))
		return -ENODEV;

	lock_sock(sk);
	sk->sk_bound_dev_if = addr->dect_index;
	if (!hlist_unhashed(&sk->sk_bind_node))
		__sk_del_bind_node(sk);
	sk_add_bind_node(sk, &dect_raw_sockets);
	release_sock(sk);
	return 0;
}

static int dect_raw_getname(struct sock *sk, struct sockaddr *uaddr, int *len,
			    int peer)
{
	struct sockaddr_dect *addr = (struct sockaddr_dect *)uaddr;

	if (peer)
		return -EOPNOTSUPP;

	addr->dect_family = AF_DECT;
	addr->dect_index  = sk->sk_bound_dev_if;
	*len = sizeof(*addr);
	return 0;
}

static int dect_raw_recvmsg(struct kiocb *iocb, struct sock *sk,
			    struct msghdr *msg, size_t len,
			    int noblock, int flags, int *addrlen)
{
	struct sockaddr_dect *addr;
	struct dect_raw_auxdata aux;
	struct sk_buff *skb;
	size_t copied = 0;
	int err;

	if (flags & MSG_OOB)
		return -EOPNOTSUPP;

	skb = skb_recv_datagram(sk, flags, noblock, &err);
	if (skb == NULL)
		goto out;

	copied = skb->len;
	if (len < copied) {
		msg->msg_flags |= MSG_TRUNC;
		copied = len;
	}

	err = skb_copy_datagram_iovec(skb, 0, msg->msg_iov, copied);
	if (err < 0)
		goto out_free;

	if (msg->msg_name != NULL) {
		addr = (struct sockaddr_dect *)msg->msg_name;
		addr->dect_family = AF_DECT;
		addr->dect_index  = DECT_SK_CB(skb)->index;
		msg->msg_namelen = sizeof(*addr);
	}

	sock_recv_timestamp(msg, sk, skb);

	aux.mfn   = DECT_TRX_CB(skb)->mfn;
	aux.frame = DECT_TRX_CB(skb)->frame;
	aux.slot  = DECT_TRX_CB(skb)->slot;
	aux.rssi  = DECT_TRX_CB(skb)->rssi;
	put_cmsg(msg, SOL_DECT, DECT_RAW_AUXDATA, sizeof(aux), &aux);

	if (flags & MSG_TRUNC)
		copied = skb->len;
out_free:
	skb_free_datagram(sk, skb);
out:
	return err ? : copied;
}

static int dect_raw_sendmsg(struct kiocb *iocb, struct sock *sk,
			    struct msghdr *msg, size_t len)
{
	struct sockaddr_dect *addr = msg->msg_name;
	struct dect_raw_auxdata *aux = NULL;
	struct dect_cell *cell;
	struct sk_buff *skb;
	struct cmsghdr *cmsg;
	size_t size;
	int index;
	int err;

	if (msg->msg_namelen) {
		if (addr->dect_family != AF_DECT)
			return -EINVAL;
		index = addr->dect_index;
	} else
		index = sk->sk_bound_dev_if;

	cell = dect_cell_get_by_index(index);
	if (cell == NULL)
		return -ENODEV;

	for (cmsg = CMSG_FIRSTHDR(msg); cmsg != NULL; cmsg = CMSG_NXTHDR(msg, cmsg)) {
		if (!CMSG_OK(msg, cmsg))
			return -EINVAL;
		if (cmsg->cmsg_level != SOL_DECT)
			continue;

		switch (cmsg->cmsg_type) {
		case DECT_RAW_AUXDATA:
			if (cmsg->cmsg_len != CMSG_LEN(sizeof(*aux)))
				return -EINVAL;
			aux = (struct dect_raw_auxdata *)CMSG_DATA(cmsg);
			break;
		default:
			return -EINVAL;
		}
	}

	if (aux == NULL)
		return -EINVAL;

	size = DECT_PREAMBLE_SIZE + len;
	skb = sock_alloc_send_skb(sk, size, msg->msg_flags & MSG_DONTWAIT, &err);
	if (skb == NULL)
		goto err1;

	/* Reserve space for preamble */
	skb_reset_mac_header(skb);
	skb_reserve(skb, DECT_PREAMBLE_SIZE);

	err = memcpy_fromiovec(skb_put(skb, len), msg->msg_iov, len);
	if (err < 0)
		goto err2;

	DECT_TRX_CB(skb)->mfn   = aux->mfn;
	DECT_TRX_CB(skb)->frame = aux->frame;
	DECT_TRX_CB(skb)->slot  = aux->slot;

	skb_queue_tail(&cell->raw_tx_queue, skb);
	return len;

err2:
	kfree_skb(skb);
err1:
	return err;
}

static struct dect_proto dect_raw_proto = {
	.type		= SOCK_RAW,
	.protocol	= DECT_RAW,
	.capability	= CAP_NET_RAW,
	.ops		= &dect_dgram_ops,
	.proto.name	= "DECT_RAW",
	.proto.owner	= THIS_MODULE,
	.proto.obj_size	= sizeof(struct dect_raw_sk),
	.proto.close	= dect_raw_close,
	.proto.bind	= dect_raw_bind,
	.proto.recvmsg	= dect_raw_recvmsg,
	.proto.sendmsg	= dect_raw_sendmsg,
	.getname	= dect_raw_getname,
};

static int __init dect_raw_init(void)
{
	int err;

	err = dect_proto_register(&dect_raw_proto);
	if (err < 0)
		return err;
	rcu_assign_pointer(dect_raw_rcv_hook, __dect_raw_rcv);
	return 0;
}

static void __exit dect_raw_exit(void)
{
	rcu_assign_pointer(dect_raw_rcv_hook, NULL);
	synchronize_rcu();
	dect_proto_unregister(&dect_raw_proto);
}

module_init(dect_raw_init);
module_exit(dect_raw_exit);

MODULE_AUTHOR("Patrick McHardy <kaber@trash.net>");
MODULE_DESCRIPTION("DECT RAW sockets");
MODULE_LICENSE("GPL");

MODULE_ALIAS_NET_PF_PROTO(PF_DECT, DECT_RAW);
