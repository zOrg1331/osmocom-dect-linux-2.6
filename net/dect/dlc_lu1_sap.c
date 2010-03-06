/*
 * DECT DLC LU1 SAP sockets
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

struct dect_lu1_sap {
	struct sock			sk;
	struct dect_ulei		ulei;
	struct dect_mac_conn		*mc;
	struct dect_lux			lux;
};

static struct sk_buff *dect_lu1_dequeue(struct dect_lux *lux)
{
	struct dect_lu1_sap *lu1 = container_of(lux, struct dect_lu1_sap, lux);

	return skb_dequeue(&lu1->sk.sk_write_queue);
}

static void dect_lu1_enqueue(struct dect_lux *lux, struct sk_buff *skb)
{
	struct dect_lu1_sap *lu1 = container_of(lux, struct dect_lu1_sap, lux);

	if (sock_queue_rcv_skb(&lu1->sk, skb) < 0)
		kfree_skb(skb);
}

static void dect_lu1_disconnect(struct dect_lux *lux)
{
	struct dect_lu1_sap *lu1 = container_of(lux, struct dect_lu1_sap, lux);
	struct sock *sk = &lu1->sk;

	sk->sk_state = DECT_SK_RELEASED;
	sk->sk_err = ENETDOWN;
	if (!sock_flag(sk, SOCK_DEAD))
		sk->sk_error_report(sk);
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
	sk->sk_state = DECT_SK_RELEASED;
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

	sock_put(sk);
}

static int dect_lu1_getname(struct sock *sk, struct sockaddr *uaddr,
			     int *len, int peer)
{
	struct sockaddr_dect_lu *addr = (struct sockaddr_dect_lu *)uaddr;
	struct dect_lu1_sap *lu1 = dect_lu1_sap(sk);

	if (peer)
		return -EOPNOTSUPP;

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
	cl = dect_cluster_get_by_pari(&ulei.mci.ari);
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

static int dect_lu1_recvmsg(struct kiocb *iocb, struct sock *sk,
			    struct msghdr *msg, size_t len,
			    int noblock, int flags, int *addr_len)
{
	struct sk_buff *skb;
	size_t copied = 0, copy;
	long timeo;
	int err;

	if (flags & (MSG_OOB | MSG_TRUNC))
		return -EOPNOTSUPP;

	lock_sock(sk);

	if (sk->sk_state != DECT_SK_ESTABLISHED) {
		err = -ENOTCONN;
		goto out;
	}

	timeo = sock_rcvtimeo(sk, noblock);

	do {
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
	} while (1);

out:
	pr_debug("LU1: %p: recv err %d copied %zu\n", sk, err, copied);
	release_sock(sk);
	return copied ? : err;
}

static int dect_lu1_sendmsg(struct kiocb *kiocb, struct sock *sk,
			    struct msghdr *msg, size_t len)
{
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
	return len;

err2:
	kfree_skb(skb);
err1:
	pr_debug("LU1: %p: send err %d wmem %u\n", sk, err, atomic_read(&sk->sk_wmem_alloc));
	return err;
}

static struct dect_proto dect_lu1_proto = {
	.type		= SOCK_STREAM,
	.protocol	= DECT_LU1_SAP,
	.capability	= -1,
	.ops		= &dect_stream_ops,
	.proto.name	= "DECT_LU1_SAP",
	.proto.owner	= THIS_MODULE,
	.proto.obj_size	= sizeof(struct dect_lu1_sap),
	.proto.init	= dect_lu1_init,
	.proto.close	= dect_lu1_close,
	.proto.connect	= dect_lu1_connect,
	.proto.recvmsg	= dect_lu1_recvmsg,
	.proto.sendmsg	= dect_lu1_sendmsg,
	.getname	= dect_lu1_getname,
};

int __init dect_lu1_sap_module_init(void)
{
	return dect_proto_register(&dect_lu1_proto);
}

void dect_lu1_sap_module_exit(void)
{
	dect_proto_unregister(&dect_lu1_proto);
}

module_init(dect_lu1_sap_module_init);
module_exit(dect_lu1_sap_module_exit);

MODULE_AUTHOR("Patrick McHardy <kaber@trash.net>");
MODULE_DESCRIPTION("DECT DLC LU1 SAP sockets");
MODULE_LICENSE("GPL");

MODULE_ALIAS_NET_PF_PROTO(PF_DECT, DECT_LU1_SAP);
