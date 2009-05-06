/*
 * DECT DLC B SAP sockets - DLC C-plane broadcast service access
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
#include <linux/net.h>
#include <linux/socket.h>
#include <linux/dect.h>
#include <net/sock.h>
#include <net/dect/dect.h>

static HLIST_HEAD(dect_bsap_sockets);

struct dect_bsap {
	struct sock		sk;
};

static inline struct dect_bsap *dect_bsap(struct sock *sk)
{
	return (struct dect_bsap *)sk;
}

void dect_bsap_rcv(const struct dect_cluster *cl, struct sk_buff *skb)
{
	struct hlist_node *node;
	struct sk_buff *skb2;
	struct sock *sk;

	sk_for_each(sk, node, &dect_bsap_sockets) {
		if (sk->sk_bound_dev_if &&
		    sk->sk_bound_dev_if != cl->index)
			continue;

		skb2 = skb_clone(skb, GFP_ATOMIC);
		if (skb2 == NULL) {
			sk->sk_err = -ENOMEM;
			sk->sk_error_report(sk);
		} else if (dect_sock_queue_rcv_skb(sk, skb2) < 0)
			kfree_skb(skb2);
	}
}

static void dect_bsap_close(struct sock *sk, long timeout)
{
	sk_del_node_init(sk);
	sock_put(sk);
}

static int dect_bsap_bind(struct sock *sk, struct sockaddr *uaddr, int len)
{
	const struct sockaddr_dect *addr = (struct sockaddr_dect *)uaddr;
	int err;

	if (len < sizeof(*addr) || addr->dect_family != AF_DECT)
		return -EINVAL;

	if (addr->dect_index != 0 &&
	    !dect_cluster_get_by_index(addr->dect_index))
		return -ENODEV;

	lock_sock(sk);
	err = -EINVAL;
	if (!sk_unhashed(sk))
		goto out;

	sk->sk_bound_dev_if = addr->dect_index;
	sk_add_node(sk, &dect_bsap_sockets);
	err = 0;
out:
	release_sock(sk);
	return err;
}

static int dect_bsap_getname(struct sock *sk, struct sockaddr *uaddr, int *len,
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

static int dect_bsap_recvmsg(struct kiocb *iocb, struct sock *sk,
			     struct msghdr *msg, size_t len,
			     int noblock, int flags, int *addrlen)
{
	struct sockaddr_dect *addr;
	struct sk_buff *skb;
	size_t copied = 0;
	int err;

	if (flags & MSG_OOB)
		return -EOPNOTSUPP;

	noblock = flags & MSG_DONTWAIT;
	skb = skb_recv_datagram(sk, flags, noblock, &err);
	if (skb == NULL)
		goto out;

	//msg->msg_flags |= DECT_LB_CB(skb)->expedited ? MSG_OOB : 0;

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
		addr->dect_index = DECT_SK_CB(skb)->index;
		msg->msg_namelen = sizeof(*addr);
	}

	sock_recv_timestamp(msg, sk, skb);

	if (flags & MSG_TRUNC)
		copied = skb->len;
out_free:
	skb_free_datagram(sk, skb);
out:
	return err ? : copied;
}

static int dect_bsap_sendmsg(struct kiocb *kiocb, struct sock *sk,
			     struct msghdr *msg, size_t len)
{
	const struct sockaddr_dect *addr = msg->msg_name;
	bool expedited = msg->msg_flags & MSG_OOB;
	struct dect_cluster *cl;
	struct sk_buff *skb;
	int index;
	int err;

	if (msg->msg_namelen) {
		if (addr->dect_family != AF_DECT)
			return -EINVAL;
		index = addr->dect_index;
	} else
		index = sk->sk_bound_dev_if;

	/* Transmission is always in direction FP -> PP */
	cl = dect_cluster_get_by_index(index);
	if (cl == NULL)
		return -ENODEV;
	if (cl->mode != DECT_MODE_FP)
		return -EOPNOTSUPP;

	/* Valid frame sizes are 3 bytes (short frame), 5 bytes (long frame)
	 * or multiples of 5 bytes up to 30 bytes (extended frame). Extended
	 * frames can not use expedited operation. */
	if (len != DECT_LB_SHORT_FRAME_SIZE &&
	    len != DECT_LB_LONG_FRAME_SIZE) {
		if (len % DECT_LB_LONG_FRAME_SIZE != 0)
			return -EINVAL;
		if (len > DECT_LB_EXTENDED_FRAME_SIZE_MAX)
			return -EMSGSIZE;
		if (expedited)
			return -EOPNOTSUPP;
	}

	skb = sock_alloc_send_skb(sk, len, msg->msg_flags & MSG_DONTWAIT, &err);
	if (skb == NULL)
		goto err1;
	err = memcpy_fromiovec(skb_put(skb, len), msg->msg_iov, len);
	if (err < 0)
		goto err2;
	dect_bmc_mac_page_request(cl, skb, expedited);
	return len;

err2:
	kfree_skb(skb);
err1:
	return err;
}

static struct dect_proto dect_bsap_proto __read_mostly = {
	.type		= SOCK_DGRAM,
	.protocol	= DECT_B_SAP,
	.capability	= CAP_NET_RAW,
	.ops		= &dect_dgram_ops,
	.proto.name	= "DECT_B_SAP",
	.proto.owner	= THIS_MODULE,
	.proto.obj_size	= sizeof(struct dect_bsap),
	.proto.close	= dect_bsap_close,
	.proto.bind	= dect_bsap_bind,
	.proto.recvmsg	= dect_bsap_recvmsg,
	.proto.sendmsg	= dect_bsap_sendmsg,
	.getname	= dect_bsap_getname,
};

int __init dect_bsap_module_init(void)
{
	return dect_proto_register(&dect_bsap_proto);
}

void dect_bsap_module_exit(void)
{
	dect_proto_unregister(&dect_bsap_proto);
}

MODULE_AUTHOR("Patrick McHardy <kaber@trash.net>");
MODULE_DESCRIPTION("DECT DLC B SAP sockets");
MODULE_LICENSE("GPL");

MODULE_ALIAS_NET_PF_PROTO(PF_DECT, DECT_B_SAP);
