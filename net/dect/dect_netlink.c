/*
 * DECT netlink control interface
 *
 * Copyright (c) 2009 Patrick McHardy <kaber@trash.net>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netlink.h>
#include <linux/skbuff.h>
#include <linux/net.h>
#include <linux/dect_netlink.h>
#include <linux/dect.h>
#include <net/netlink.h>
#include <net/sock.h>
#include <net/dect/dect.h>
#include <net/dect/mac_csf.h>

struct sock *dect_nlsk __read_mostly;
EXPORT_SYMBOL_GPL(dect_nlsk);

LIST_HEAD(dect_cluster_list);
EXPORT_SYMBOL_GPL(dect_cluster_list);

struct dect_cluster *dect_cluster_get_by_index(int index)
{
	struct dect_cluster *cl;

	list_for_each_entry(cl, &dect_cluster_list, list) {
		if (cl->index == index)
			return cl;
	}
	return NULL;
}
EXPORT_SYMBOL_GPL(dect_cluster_get_by_index);

static const struct dect_netlink_handler *dect_dispatch[DECT_NR_MSGTYPES];

void dect_netlink_register_handlers(const struct dect_netlink_handler *handler,
				    unsigned int base, unsigned int n)
{
	unsigned int i;

	dect_lock();
	base -= DECT_MSG_BASE;
	for (i = 0; i < n; i++)
		dect_dispatch[base + i] = handler + i;
	dect_unlock();
}
EXPORT_SYMBOL_GPL(dect_netlink_register_handlers);

void dect_netlink_unregister_handlers(unsigned int base, unsigned int n)
{
	unsigned int i;

	dect_lock();
	base -= DECT_MSG_BASE;
	for (i = 0; i < n; i++)
		dect_dispatch[base + i] = NULL;
	dect_unlock();
}
EXPORT_SYMBOL_GPL(dect_netlink_unregister_handlers);

static int dect_netlink_rcv_msg(struct sk_buff *skb, struct nlmsghdr *nlh)
{
	const struct dect_netlink_handler *link;
	u16 type;
	int err;

	type = nlh->nlmsg_type;
	if (type > DECT_MSG_MAX)
		return -EINVAL;

	link = dect_dispatch[type - DECT_MSG_BASE];
	if (link == NULL) {
#ifdef CONFIG_MODULES
		dect_unlock();
		switch (type) {
		case DECT_NEW_TRANSCEIVER ... DECT_GET_CELL:
			request_module("dect_csf");
			break;
		case DECT_NEW_CLUSTER ... DECT_LLME_MSG:
			request_module("dect_ccf");
			break;
		}
		dect_lock();

		link = dect_dispatch[type - DECT_MSG_BASE];
		if (link == NULL)
#endif
			return -EOPNOTSUPP;
	}

	/* dump and get requests don't require privileges */
	if (link->dump == NULL && !capable(CAP_NET_ADMIN))
		return -EPERM;

	if (nlh->nlmsg_flags & NLM_F_DUMP) {
		struct netlink_dump_control c = {
			.dump	= link->dump,
			.done	= link->done,
		};

		if (link->dump == NULL)
			return -EOPNOTSUPP;
		return netlink_dump_start(dect_nlsk, skb, nlh, &c);
	} else {
		struct nlattr *nla[link->maxtype + 1];

		err = nlmsg_parse(nlh, sizeof(struct dectmsg), nla,
				  link->maxtype, link->policy);
		if (err < 0)
			return err;
		if (link->doit == NULL)
			return -EOPNOTSUPP;
		return link->doit(skb, nlh, (const struct nlattr **)nla);
	}
}

static void dect_netlink_rcv(struct sk_buff *skb)
{
	dect_lock();
	netlink_rcv_skb(skb, dect_netlink_rcv_msg);
	dect_unlock();
}

static struct netlink_kernel_cfg dect_netlink_cfg = {
	.groups = DECTNLGRP_MAX,
	.input	= dect_netlink_rcv,
};

int __init dect_netlink_module_init(void)
{
	struct sock *sk;

	sk = netlink_kernel_create(&init_net, NETLINK_DECT, &dect_netlink_cfg);
	if (sk == NULL)
		return -ENOMEM;
	dect_nlsk = sk;
	return 0;
}

void dect_netlink_module_exit(void)
{
	netlink_kernel_release(dect_nlsk);
}

MODULE_ALIAS_NET_PF_PROTO(PF_NETLINK, NETLINK_DECT);
