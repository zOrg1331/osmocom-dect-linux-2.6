/*
 * DECT sockets
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
#include <linux/spinlock.h>
#include <linux/socket.h>
#include <linux/net.h>
#include <linux/poll.h>
#include <linux/dect.h>
#include <net/sock.h>
#include <net/dect/dect.h>

static struct dect_proto *dect_protos[DECT_PROTO_NUM];
static DEFINE_SPINLOCK(dect_proto_lock);

void (*dect_raw_rcv_hook)(struct sk_buff *skb);
EXPORT_SYMBOL_GPL(dect_raw_rcv_hook);

int dect_proto_register(struct dect_proto *proto)
{
	int err;

	err = proto_register(&proto->proto, true);
	if (err < 0)
		return err;

	spin_lock(&dect_proto_lock);
	dect_protos[proto->protocol] = proto;
	spin_unlock(&dect_proto_lock);
	return 0;
}
EXPORT_SYMBOL_GPL(dect_proto_register);

void dect_proto_unregister(struct dect_proto *proto)
{
	spin_lock(&dect_proto_lock);
	dect_protos[proto->protocol] = NULL;
	spin_unlock(&dect_proto_lock);
	proto_unregister(&proto->proto);
}
EXPORT_SYMBOL_GPL(dect_proto_unregister);

struct sk_buff *dect_alloc_notification(u32 type, const void *data,
					unsigned int size)
{
	struct sk_buff *skb;

	skb = alloc_skb(size, GFP_ATOMIC);
	if (skb == NULL)
		return NULL;
	DECT_NOTIFY_CB(skb)->type = type;
	memcpy(skb_put(skb, size), data, size);
	return skb;
}

static void dect_destruct(struct sock *sk)
{
	__skb_queue_purge(&sk->sk_receive_queue);
	__skb_queue_purge(&sk->sk_error_queue);
	__skb_queue_purge(&sk->sk_write_queue);
}

static int dect_release(struct socket *sock)
{
	struct sock *sk = sock->sk;
	long timeout;

	if (sk == NULL)
		return 0;

	timeout = 0;
	if (sock_flag(sk, SOCK_LINGER) && !(current->flags & PF_EXITING))
		timeout = sk->sk_lingertime;
	sock->sk = NULL;
	sk->sk_prot->close(sk, timeout);
	return 0;
}

static int dect_bind(struct socket *sock, struct sockaddr *uaddr, int len)
{
	struct sock *sk = sock->sk;
	int err;

	err = 0;
	if (sk->sk_prot->bind != NULL)
		err = sk->sk_prot->bind(sk, uaddr, len);

	return err;
}

static int dect_listen(struct socket *sock, int backlog)
{
	struct sock *sk = sock->sk;
	int err;

	lock_sock(sk);
	err = -EINVAL;
	if (sock->state != SS_UNCONNECTED ||
	    (sock->type != SOCK_STREAM && sock->type != SOCK_SEQPACKET))
		goto out;

	if (sk->sk_state != DECT_SK_RELEASED && sk->sk_state != DECT_SK_LISTEN)
		goto out;

	if (sk->sk_state != DECT_SK_LISTEN)
		sk->sk_prot->hash(sk);
	sk->sk_max_ack_backlog = backlog;
	err = 0;
out:
	release_sock(sk);
	return err;
}

static int dect_accept(struct socket *sock, struct socket *newsock, int flags)
{
	struct sock *sk = sock->sk, *newsk;
	int err;

	newsk = sk->sk_prot->accept(sk, flags, &err);
	if (newsk == NULL)
		return err;

	lock_sock(newsk);
	sock_graft(newsk, newsock);
	newsock->state = SS_CONNECTED;
	release_sock(newsk);
	return 0;
}

static unsigned int dect_poll(struct file *file, struct socket *sock,
			      struct poll_table_struct *wait)
{
	struct sock *sk = sock->sk;
	unsigned int mask;

	poll_wait(file, sk->sk_sleep, wait);
	mask = 0;

	if (sk->sk_state == DECT_SK_LISTEN) {
		if (!hlist_empty(&dect_csk(sk)->accept_queue))
			return POLLIN | POLLRDNORM;
		return 0;
	}

	/* exceptional events? */
	if (sk->sk_err || !skb_queue_empty(&sk->sk_error_queue))
		mask |= POLLERR;
	if (sk->sk_shutdown & RCV_SHUTDOWN)
		mask |= POLLRDHUP;
	if (sk->sk_shutdown == SHUTDOWN_MASK)
		mask |= POLLHUP;

	/* readable? */
	if (!skb_queue_empty(&sk->sk_receive_queue) ||
	    (sk->sk_shutdown & RCV_SHUTDOWN))
		mask |= POLLIN | POLLRDNORM;

	/* Connection-based need to check for termination and startup */
	if (sk->sk_state == DECT_SK_RELEASED)
		mask |= POLLHUP;
	/* connection hasn't started yet? */
	if (sk->sk_state == DECT_SK_ESTABLISH_PENDING)
		return mask;

	/* writable? */
	if (sock_writeable(sk))
		mask |= POLLOUT | POLLWRNORM | POLLWRBAND;
	else
		set_bit(SOCK_ASYNC_NOSPACE, &sk->sk_socket->flags);

	return mask;
}

static int dect_shutdown(struct socket *sock, int how)
{
	struct sock *sk = sock->sk;
	int err = 0;

	how++;
	if ((how & ~SHUTDOWN_MASK) || !how)
		return -EINVAL;

	lock_sock(sk);

	if (sock->state == SS_CONNECTING &&
	    sk->sk_state == DECT_SK_ESTABLISH_PENDING)
		sock->state = SS_DISCONNECTING;

	switch (sk->sk_state) {
	case DECT_SK_RELEASED:
		err = -ENOTCONN;
		break;
	case DECT_SK_LISTEN:
		if (!(how & RCV_SHUTDOWN))
			break;
	default:
		sk->sk_shutdown |= how;
		if (sk->sk_prot->shutdown != NULL)
			sk->sk_prot->shutdown(sk, how);
	}

	/* wake up processes sleeping in poll() */
	sk->sk_state_change(sk);
	release_sock(sk);
	return err;
}

static int dect_connect(struct socket *sock, struct sockaddr *uaddr, int len,
			int flags)
{
	struct sock *sk = sock->sk;
	long timeo;
	int err;

	lock_sock(sk);
	switch (sock->state) {
	case SS_CONNECTED:
		err = -EISCONN;
		goto out;
	case SS_CONNECTING:
		err = -EALREADY;
		goto out;
	case SS_UNCONNECTED:
		err = -EISCONN;
		if (sk->sk_state != DECT_SK_RELEASED)
			goto out;
		err = sk->sk_prot->connect(sk, uaddr, len);
		if (err < 0)
			goto out;
		sock->state = SS_CONNECTING;
		err = -EINPROGRESS;
		break;
	default:
		err = -EINVAL;
		goto out;
	}

	if (sk->sk_state == DECT_SK_ESTABLISH_PENDING) {
		timeo = sock_sndtimeo(sk, flags & O_NONBLOCK);
		err = sk_stream_wait_connect(sk, &timeo);
		if (err < 0)
			goto out;

		err = sock_intr_errno(timeo);
		if (signal_pending(current))
			goto out;
	}

	/* Connection establishment was aborted or failed */
	if (sk->sk_state == DECT_SK_RELEASED)
		goto sock_error;

	sock->state = SS_CONNECTED;
	err = 0;
out:
	release_sock(sk);
	return err;

sock_error:
	err = sock_error(sk) ? : -ECONNABORTED;
	sock->state = SS_UNCONNECTED;
	goto out;
}

static int dect_getname(struct socket *sock, struct sockaddr *uaddr, int *len,
			int peer)
{
	const struct dect_proto *p;

	/* AF_DECT uses different address formats for the different SAPs */
	p = container_of(sock->sk->sk_prot, struct dect_proto, proto);
	if (p->getname != NULL)
		return p->getname(sock->sk, uaddr, len, peer);
	*len = 0;
	return 0;
}

static int dect_sendmsg(struct kiocb *iocb, struct socket *sock,
			struct msghdr *msg, size_t size)
{
	struct sock *sk = sock->sk;

	return sk->sk_prot->sendmsg(iocb, sk, msg, size);
}

static int dect_setsockopt(struct socket *sock, int level, int optname,
			   char __user *optval, unsigned int optlen)
{
	struct sock *sk = sock->sk;
	int err;

	if (level != SOL_DECT)
		return -ENOPROTOOPT;

	switch (optname) {
	default:
		if (sk->sk_prot->setsockopt)
			err = sk->sk_prot->setsockopt(sk, level, optname,
						      optval, optlen);
		else
			err = -ENOPROTOOPT;
	}
	return err;
}

static int dect_getsockopt(struct socket *sock, int level, int optname,
			   char __user *optval, int __user *optlen)
{
	struct sock *sk = sock->sk;
	int err;

	if (level != SOL_DECT)
		return -ENOPROTOOPT;

	switch (optname) {
	default:
		if (sk->sk_prot->getsockopt)
			err = sk->sk_prot->getsockopt(sk, level, optname,
						      optval, optlen);
		else
			err = -ENOPROTOOPT;
	}
	return err;
}

static int dect_create(struct net *net, struct socket *sock, int protocol,
		       int kern)
{
	struct dect_proto *p;
	struct sock *sk;
	int err = 0;

	if (protocol < 0 || protocol >= DECT_PROTO_NUM)
		return -EPROTONOSUPPORT;
#ifdef CONFIG_MODULES
	if (dect_protos[protocol] == NULL) {
		err = request_module("net-pf-%d-proto-%d", PF_DECT, protocol);
		if (err < 0)
			return err;
	}
#endif
	spin_lock(&dect_proto_lock);
	p = dect_protos[protocol];
	if (p != NULL && !try_module_get(p->proto.owner))
		p = NULL;
	spin_unlock(&dect_proto_lock);

	if (p == NULL)
		return -EPROTONOSUPPORT;

	if (p->type != sock->type) {
		err = -EPROTONOSUPPORT;
		goto err;
	}

	if (cap_valid(p->capability) && !capable(p->capability)) {
		err = -EACCES;
		goto err;
	}

	sock->state = SS_UNCONNECTED;
	sock->ops = p->ops;

	sk = sk_alloc(net, PF_DECT, GFP_KERNEL, &p->proto);
	if (sk == NULL) {
		err = -ENOMEM;
		goto err;
	}

	sock_init_data(sock, sk);
	sk->sk_protocol = protocol;
	sk->sk_destruct = dect_destruct;

	if (sk->sk_prot->init != NULL) {
		err = sk->sk_prot->init(sk);
		if (err < 0) {
			sock_orphan(sk);
			sock_put(sk);
		}
	}
err:
	module_put(p->proto.owner);
	return err;
}

const struct proto_ops dect_stream_ops = {
	.family		= PF_DECT,
	.owner		= THIS_MODULE,
	.release	= dect_release,
	.bind		= dect_bind,
	.connect	= dect_connect,
	.socketpair	= sock_no_socketpair,
	.getname	= dect_getname,
	.poll		= dect_poll,
	.ioctl		= sock_no_ioctl,
	.listen		= dect_listen,
	.accept		= dect_accept,
	.shutdown	= dect_shutdown,
	.setsockopt	= dect_setsockopt,
	.getsockopt	= dect_getsockopt,
	.sendmsg	= dect_sendmsg,
	.recvmsg	= sock_common_recvmsg,
	.mmap		= sock_no_mmap,
	.sendpage	= sock_no_sendpage,
};
EXPORT_SYMBOL_GPL(dect_stream_ops);

const struct proto_ops dect_dgram_ops = {
	.family		= PF_DECT,
	.owner		= THIS_MODULE,
	.release	= dect_release,
	.bind		= dect_bind,
	.connect	= sock_no_connect,
	.socketpair	= sock_no_socketpair,
	.getname	= dect_getname,
	.poll		= datagram_poll,
	.ioctl		= sock_no_ioctl,
	.listen		= sock_no_listen,
	.accept		= sock_no_accept,
	.shutdown	= sock_no_shutdown,
	.setsockopt	= sock_no_setsockopt,
	.getsockopt	= sock_no_getsockopt,
	.sendmsg	= dect_sendmsg,
	.recvmsg	= sock_common_recvmsg,
	.mmap		= sock_no_mmap,
	.sendpage	= sock_no_sendpage,
};
EXPORT_SYMBOL_GPL(dect_dgram_ops);

static struct net_proto_family dect_family_ops = {
	.family		= PF_DECT,
	.create		= dect_create,
	.owner		= THIS_MODULE,
};

int __init dect_af_module_init(void)
{
	int err;

	err = sock_register(&dect_family_ops);
	if (err < 0)
		goto err1;

	err = dect_bsap_module_init();
	if (err < 0)
		goto err2;

	err = dect_ssap_module_init();
	if (err < 0)
		goto err3;

	return 0;

err3:
	dect_bsap_module_exit();
err2:
	sock_unregister(PF_DECT);
err1:
	return err;
}

void dect_af_module_exit(void)
{
	dect_bsap_module_exit();
	dect_ssap_module_exit();
	sock_unregister(PF_DECT);
}

MODULE_ALIAS_NETPROTO(PF_DECT);
