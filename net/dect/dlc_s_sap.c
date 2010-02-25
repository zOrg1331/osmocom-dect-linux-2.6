/*
 * DECT DLC S SAP sockets - DLC C-plane data link service access
 *
 * Copyright (c) 2009 Patrick McHardy <kaber@trash.net>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#ifdef CONFIG_DECT_DEBUG
#define DEBUG
#endif

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/socket.h>
#include <linux/net.h>
#include <linux/dect.h>
#include <asm/uaccess.h>
#include <net/sock.h>
#include <net/dect/dect.h>

static DEFINE_SPINLOCK(dect_ssap_lock);
static HLIST_HEAD(dect_ssap_sockets);
static HLIST_HEAD(dect_ssap_listeners);

#define DECT_LLN_ANY		255

struct dect_ssap {
	struct dect_csk		csk;
	struct dect_dlei	dlei;
	struct dect_lapc	*lapc;
};

static inline struct dect_ssap *dect_ssap(struct sock *sk)
{
	return (struct dect_ssap *)sk;
}

static int dect_parse_dlei(struct dect_dlei *dlei,
			   const struct sockaddr_dect_ssap *addr)
{
	if (dect_parse_ari(&dlei->mci.ari, (u64)addr->dect_ari << 24) == 0)
		return -EINVAL;
	dect_parse_pmid(&dlei->mci.pmid, addr->dect_pmid);
	dlei->mci.lcn = addr->dect_lcn;

	dlei->lln = addr->dect_lln;
	if (dlei->lln > DECT_LLN_MAX)
		return -EINVAL;

	dlei->sapi = addr->dect_sapi;
	switch (dlei->sapi) {
	case DECT_SAPI_CO_SIGNALLING:
	case DECT_SAPI_CL_SIGNALLING:
		break;
	default:
		return -EINVAL;
	}
	return 0;
}

static void dect_build_dlei(struct sockaddr_dect_ssap *addr,
			    const struct dect_dlei *dlei)
{
	addr->dect_family = AF_DECT;
	addr->dect_pmid = dect_build_pmid(&dlei->mci.pmid);
	addr->dect_ari  = dect_build_ari(&dlei->mci.ari) >> 24;
	addr->dect_lcn  = dlei->mci.lcn;
	addr->dect_lln  = dlei->lln;
	addr->dect_sapi = dlei->sapi;
}

static void dect_ssap_insert(struct sock *sk)
{
	sk_add_node(sk, &dect_ssap_sockets);
	sock_prot_inuse_add(sock_net(sk), sk->sk_prot, 1);
}

static void dect_ssap_unlink(struct sock *sk)
{
	if (sk_del_node_init(sk))
		sock_prot_inuse_add(sock_net(sk), sk->sk_prot, -1);
}

static int dect_ssap_init(struct sock *sk)
{
	struct dect_ssap *ssap = dect_ssap(sk);

	INIT_HLIST_HEAD(&ssap->csk.accept_queue);
	return 0;
}

static struct sock *dect_ssap_acceptq_dequeue(struct dect_ssap *ssap)
{
	struct sock *sk;

	if (hlist_empty(&ssap->csk.accept_queue))
		return NULL;
	sk = hlist_entry(ssap->csk.accept_queue.first, struct sock, sk_bind_node);
	__sk_del_bind_node(sk);
	sk_node_init(&sk->sk_bind_node);
	sk_acceptq_removed(&ssap->csk.sk);
	return sk;
}

static void dect_ssap_close(struct sock *sk, long timeout)
{
	struct dect_ssap *ssap = dect_ssap(sk);
	struct sock *req;

	pr_debug("close sock %p refcnt %u rmem %u wmem %u\n",
		 sk, atomic_read(&sk->sk_refcnt),
		 atomic_read(&sk->sk_rmem_alloc),
		 atomic_read(&sk->sk_wmem_alloc));

	spin_lock_bh(&dect_ssap_lock);
	dect_ssap_unlink(sk);
	spin_unlock_bh(&dect_ssap_lock);

	if (sk->sk_state != DECT_SK_RELEASED && ssap->lapc != NULL)
		dect_lapc_release(ssap->lapc, false);

	if (!hlist_unhashed(&sk->sk_bind_node))
		__sk_del_bind_node(sk);

	while ((req = dect_ssap_acceptq_dequeue(ssap)) != NULL) {
		spin_lock_bh(&dect_ssap_lock);
		dect_ssap_unlink(req);
		spin_unlock_bh(&dect_ssap_lock);

		dect_lapc_release(dect_ssap(req)->lapc, false);
	}

	sk_common_release(sk);
}

static int dect_ssap_bind_conflict(const struct dect_dlei *dlei)
{
	struct dect_ssap *ssap;
	struct hlist_node *n;
	struct sock *sk;

	// FIXME: wildcards
	sk_for_each(sk, n, &dect_ssap_sockets) {
		ssap = dect_ssap(sk);
		if (!dect_pmid_cmp(&ssap->dlei.mci.pmid, &dlei->mci.pmid) &&
		    ssap->dlei.lln == dlei->lln)
			return -EADDRINUSE;
	}
	return 0;
}

static int dect_ssap_bind(struct sock *sk, struct sockaddr *uaddr, int len)
{
	struct sockaddr_dect_ssap *addr = (struct sockaddr_dect_ssap *)uaddr;
	struct dect_ssap *ssap = dect_ssap(sk);
	struct dect_dlei dlei;
	int err;

	if (len < sizeof(*addr) || addr->dect_family != AF_DECT)
		return -EINVAL;

	err = dect_parse_dlei(&dlei, addr);
	if (err < 0)
		return err;

	lock_sock(sk);
	spin_lock_bh(&dect_ssap_lock);

	err = dect_ssap_bind_conflict(&dlei);
	if (err < 0)
		goto out;

	memcpy(&ssap->dlei, &dlei, sizeof(ssap->dlei));
	dect_ssap_insert(sk);
out:
	spin_unlock_bh(&dect_ssap_lock);
	release_sock(sk);
	return err;
}

static struct dect_ssap *dect_ssap_lookup_listener(const struct dect_dli *dli,
						   enum dect_sapis sapi)
{
	struct dect_ssap *ssap;
	struct hlist_node *n;
	struct sock *sk;

	pr_debug("lookup listener: lln %u sapi %u\n", dli->lln, sapi);
	sk_for_each_bound(sk, n, &dect_ssap_listeners) {
		ssap = dect_ssap(sk);
#if 0
		if (!dect_ari_cmp(&ssap->dlei.mci.ari, &dli->mci.ari))
			continue;
		if (!dect_pmid_cmp(&ssap->dlei.mci.pmid, &dli->mci.pmid))
			continue;
#endif
		pr_debug("ssap: lln %u sapi %u\n", ssap->dlei.lln, ssap->dlei.sapi);
		if (ssap->dlei.lln != DECT_LLN_ANY &&
		    ssap->dlei.lln != dli->lln)
			continue;
		if (ssap->dlei.sapi != sapi)
			continue;
		return ssap;
	}
	return NULL;
}

struct dect_lapc *dect_ssap_rcv_request(struct dect_lc *lc,
					const struct dect_dli *dli,
					enum dect_sapis sapi)
{
	struct dect_ssap *ssap, *newssap;
	struct sock *sk, *newsk;
	struct dect_lapc *lapc = NULL;

	spin_lock(&dect_ssap_lock);
	ssap = dect_ssap_lookup_listener(dli, sapi);
	if (ssap == NULL)
		goto out;

	sk = &ssap->csk.sk;
	if (sk_acceptq_is_full(sk))
		goto out;

	newsk = sk_alloc(&init_net, PF_DECT, GFP_ATOMIC, sk->sk_prot);
	if (newsk == NULL)
		goto out;

	sock_init_data(NULL, newsk);
	newsk->sk_type     = sk->sk_type;
	newsk->sk_protocol = sk->sk_protocol;
	newsk->sk_destruct = sk->sk_destruct;

	lapc = dect_lapc_init(newsk, dli, sapi, lc, GFP_ATOMIC);
	if (lapc == NULL)
		goto err1;

	newssap = dect_ssap(newsk);
	memcpy(&newssap->dlei.mci, &dli->mci, sizeof(newssap->dlei.mci));
	newssap->dlei.lln  = dli->lln;
	newssap->dlei.sapi = sapi;
	newssap->lapc      = lapc;

	newsk->sk_state = DECT_SK_ESTABLISHED;
	dect_ssap_insert(newsk);
	sk_add_bind_node(newsk, &ssap->csk.accept_queue);
	sk_acceptq_added(sk);

	sk->sk_state_change(sk);
	sk->sk_data_ready(sk, 0);
out:
	spin_unlock(&dect_ssap_lock);
	return lapc;

err1:
	sk_free(sk);
	goto out;
}

static void dect_ssap_hash(struct sock *sk)
{
	sk->sk_state = DECT_SK_LISTEN;

	spin_lock_bh(&dect_ssap_lock);
	sk_add_bind_node(sk, &dect_ssap_listeners);
	spin_unlock_bh(&dect_ssap_lock);
}

static void dect_ssap_unhash(struct sock *sk)
{
	if (sk_hashed(sk)) {
		spin_lock_bh(&dect_ssap_lock);
		__sk_del_bind_node(sk);
		spin_unlock_bh(&dect_ssap_lock);
	}
}

static int dect_ssap_wait_req(struct sock *sk, int noblock)
{
	struct task_struct *tsk = current;
	struct dect_ssap *ssap = dect_ssap(sk);
	long timeo = sock_rcvtimeo(sk, noblock);

	for (;;) {
		DEFINE_WAIT(wait);

		if (sk->sk_state != DECT_SK_LISTEN)
			return -EINVAL;
		if (!hlist_empty(&ssap->csk.accept_queue))
			break;
		if (!timeo)
			return -EWOULDBLOCK;
		if (signal_pending(tsk))
			return sock_intr_errno(timeo);

		prepare_to_wait_exclusive(&sk->sk_socket->wait, &wait,
					  TASK_INTERRUPTIBLE);
		release_sock(sk);
		timeo = schedule_timeout(timeo);
		lock_sock(sk);
		finish_wait(&sk->sk_socket->wait, &wait);
	}
	return 0;
}

static struct sock *dect_ssap_accept(struct sock *sk, int flags, int *errp)
{
	struct dect_ssap *ssap = dect_ssap(sk);
	struct sock *newsk;
	int err;

	lock_sock(sk);
	err = dect_ssap_wait_req(sk, flags & O_NONBLOCK);
	if (err < 0)
		goto err;

	newsk = dect_ssap_acceptq_dequeue(ssap);
	release_sock(sk);

	*errp = 0;
	return newsk;

err:
	release_sock(sk);
	*errp = err;
	return NULL;
}

static int dect_ssap_connect(struct sock *sk, struct sockaddr *uaddr, int len)
{
	struct sockaddr_dect_ssap *addr = (struct sockaddr_dect_ssap *)uaddr;
	struct dect_ssap *ssap = dect_ssap(sk);
	struct dect_cluster *cl;
	struct dect_dlei dlei;
	struct dect_dli dli;
	struct dect_lapc *lapc;
	struct dect_lc *lc;
	struct dect_mac_conn *mc;
	bool new_mc = false, new_lc = false;
	int err;

	if (len < sizeof(*addr) || addr->dect_family != AF_DECT)
		return -EINVAL;

	err = dect_parse_dlei(&dlei, addr);
	if (err < 0)
		goto err1;

	err = -ENODEV;
	cl = dect_cluster_get_by_pari(&dlei.mci.ari);
	if (cl == NULL)
		goto err1;

	/* The assignable class B LLNs may only be used for connections
	 * originating from a PT. The unassigned LLN may be used by an FT
	 * to request class B operation. Class A and U may be used by both.
	 */
	err = -EINVAL;
	switch (dlei.lln) {
	case DECT_LLN_ASSIGNABLE_MIN ... DECT_LLN_ASSIGNABLE_MAX:
		if (cl->mode != DECT_MODE_PP)
			goto err1;
		break;
	case DECT_LLN_UNASSIGNED:
		if (cl->mode != DECT_MODE_FP)
			goto err1;
		break;
	default:
		break;
	}

	/* Lookup MAC connection and initiate new one if necessary */
	err = -ENOMEM;
	mc = dect_mac_conn_get_by_mci(cl, &dlei.mci);
	if (mc == NULL) {
		mc = dect_mac_conn_init(cl, &dlei.mci, NULL);
		if (mc == NULL)
			goto err1;
		new_mc = true;
		lc = NULL;
	} else {
		WARN_ON(mc->state == DECT_MAC_CONN_CLOSED);
		lc = mc->lc;
	}

	/* Get Lc entity and verify LLN is available */
	if (lc == NULL) {
		lc = dect_lc_init(mc, GFP_KERNEL);
		if (lc == NULL)
			goto err2;
		mc->lc = lc;
		new_lc = true;
	} else {
		err = -EADDRINUSE;
		if (lc->lapcs[dlei.lln] != NULL)
			goto err2;
	}

	memcpy(&dli.mci, &dlei.mci, sizeof(dli.mci));
	dli.lln = dlei.lln;

	lapc = dect_lapc_init(sk, &dli, dlei.sapi, lc, GFP_KERNEL);
	if (lapc == NULL)
		goto err3;
	ssap->lapc = lapc;

	dect_lc_bind(lc, lapc);

	if (new_mc)
		err = dect_dlc_mac_conn_establish(mc);
	else
		err = dect_lapc_establish(lapc);

	if (err < 0)
		goto err4;

	sk->sk_state = DECT_SK_ESTABLISH_PENDING;
	return 0;

err4:
	dect_lapc_destroy(lapc);
	/* Both will be release by dect_lapc_destroy() */
	new_lc = false;
	new_mc = false;
err3:
	if (new_lc)
		dect_lc_destroy(lc);
err2:
	if (new_mc)
		dect_dlc_mac_conn_destroy(mc);
err1:
	return err;
}

static int dect_ssap_getname(struct sock *sk, struct sockaddr *uaddr, int *len,
			     int peer)
{
	struct sockaddr_dect_ssap *addr = (struct sockaddr_dect_ssap *)uaddr;
	struct dect_ssap *ssap = dect_ssap(sk);

#if 0
	if (peer)
		return -EOPNOTSUPP;
#endif
	dect_build_dlei(addr, &ssap->dlei);
	*len = sizeof(*addr);
	return 0;
}

static void dect_ssap_shutdown(struct sock *sk, int how)
{
	struct dect_ssap *ssap = dect_ssap(sk);

	if (!(how & SEND_SHUTDOWN))
		return;

	if (sk->sk_state == DECT_SK_ESTABLISHED)
		dect_lapc_release(ssap->lapc, true);
}

static int dect_ssap_setsockopt(struct sock *sk, int level, int optname,
				char __user *optval, unsigned int optlen)
{
	struct dect_ssap *ssap = dect_ssap(sk);
	struct dect_dl_encrypt *dle;
	int err;
	u64 ck;

	switch (optname) {
	case DECT_DL_ENC_KEY:
		if (optlen != sizeof(ck))
			return -EINVAL;
		if (sk->sk_state != DECT_SK_ESTABLISH_PENDING &&
		    sk->sk_state != DECT_SK_ESTABLISHED)
			return -ENOTCONN;
		if (copy_from_user(&ck, optval, sizeof(ck)))
			return -EFAULT;
		err = dect_dlc_mac_conn_enc_key_request(ssap->lapc->lc->mc, ck);
		break;
	case DECT_DL_ENCRYPT:
		if (optlen != sizeof(dle))
			return -EINVAL;
		if (sk->sk_state != DECT_SK_ESTABLISHED)
			return -ENOTCONN;
		if (ssap->lapc->lc->mc->cl->mode != DECT_MODE_PP)
			return -EOPNOTSUPP;
		if (copy_from_user(&dle, optval, sizeof(dle)))
			return -EFAULT;
		err = dect_dlc_mac_conn_enc_eks_request(ssap->lapc->lc->mc,
						        dle->status);
		break;
	default:
		err = -ENOPROTOOPT;
	}
	return err;
}

static int dect_ssap_recvmsg(struct kiocb *iocb, struct sock *sk,
			     struct msghdr *msg, size_t len,
			     int noblock, int flags, int *addr_len)
{
	struct sockaddr_dect *addr;
	struct sk_buff *skb, *eskb;
	size_t copied = 0;
	int err;

	if (flags & MSG_OOB)
		return -EOPNOTSUPP;

	eskb = skb_dequeue(&sk->sk_error_queue);
	skb = skb_recv_datagram(sk, flags, noblock, &err);
	if (skb == NULL) {
		if (eskb != NULL && err == -EAGAIN) {
			err = 0;
			goto out;
		}
		if (sk->sk_type == SOCK_SEQPACKET) {
			lock_sock(sk);
			if (sk->sk_state != DECT_SK_ESTABLISHED &&
			    err == -EAGAIN)
				err = -ENOTCONN;
			release_sock(sk);
		}
		goto out;
	}

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
	if (eskb != NULL)
		put_cmsg(msg, SOL_DECT, DECT_NOTIFY_CB(eskb)->type,
			 eskb->len, eskb->data);
	kfree_skb(eskb);

	return err ? : copied;
}

static int dect_ssap_sendmsg(struct kiocb *kiocb, struct sock *sk,
			     struct msghdr *msg, size_t len)
{
	struct dect_ssap *ssap = dect_ssap(sk);
	struct sk_buff *skb;
	long timeo;
	int err;

	if (msg->msg_flags & MSG_OOB)
		return -EOPNOTSUPP;

	if (len > DECT_FA_I_MAX)
		return -EMSGSIZE;

	lock_sock(sk);
	if (sk->sk_type == SOCK_SEQPACKET) {
		if (sk->sk_state != DECT_SK_ESTABLISHED) {
			timeo = sock_sndtimeo(sk, msg->msg_flags & MSG_DONTWAIT);
			err = sk_stream_wait_connect(sk, &timeo);
			if (err < 0)
				goto err1;
		}
	}

	err = -EPIPE;
	if (sk->sk_err || (sk->sk_shutdown & SEND_SHUTDOWN))
		goto err1;

	skb = sock_alloc_send_skb(sk, len + 32, msg->msg_flags & MSG_DONTWAIT, &err);
	if (skb == NULL)
		goto err1;
	skb_reset_mac_header(skb);
	skb_reserve(skb, 16);
	err = memcpy_fromiovec(skb_put(skb, len), msg->msg_iov, len);
	if (err < 0)
		goto err2;

	skb_queue_tail(&sk->sk_write_queue, skb);
	release_sock(sk);

	dect_lapc_transmit(ssap->lapc);
	return len;

err2:
	kfree_skb(skb);
err1:
	err = sk_stream_error(sk, msg->msg_flags, err);
	release_sock(sk);
	return err;
}

static struct dect_proto dect_ssap_proto __read_mostly = {
	.type			= SOCK_SEQPACKET,
	.protocol		= DECT_S_SAP,
	.capability		= CAP_NET_RAW,
	.ops			= &dect_stream_ops,
	.proto.name		= "DECT_S_SAP",
	.proto.owner		= THIS_MODULE,
	.proto.obj_size		= sizeof(struct dect_ssap),
	.proto.init		= dect_ssap_init,
	.proto.close		= dect_ssap_close,
	.proto.bind		= dect_ssap_bind,
	.proto.hash		= dect_ssap_hash,
	.proto.unhash		= dect_ssap_unhash,
	.proto.accept		= dect_ssap_accept,
	.proto.connect		= dect_ssap_connect,
	.proto.shutdown		= dect_ssap_shutdown,
	.proto.setsockopt	= dect_ssap_setsockopt,
	.proto.recvmsg		= dect_ssap_recvmsg,
	.proto.sendmsg		= dect_ssap_sendmsg,
	.getname		= dect_ssap_getname,
};

int __init dect_ssap_module_init(void)
{
	BUILD_BUG_ON(sizeof(struct sockaddr_dect_ssap) >
		     sizeof(struct sockaddr));
	return dect_proto_register(&dect_ssap_proto);
}

void dect_ssap_module_exit(void)
{
	dect_proto_unregister(&dect_ssap_proto);
}

MODULE_ALIAS_NET_PF_PROTO(PF_DECT, DECT_S_SAP);
