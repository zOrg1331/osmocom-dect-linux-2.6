/*
 * Copyright (c) 2009 Patrick McHardy <kaber@trash.net>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/mutex.h>
#include <linux/list.h>
#include <linux/notifier.h>
#include <net/dect/dect.h>
#include <net/dect/transceiver.h>

static DEFINE_MUTEX(dect_cfg_mutex);

void dect_lock(void)
{
	mutex_lock(&dect_cfg_mutex);
}

void dect_unlock(void)
{
	mutex_unlock(&dect_cfg_mutex);
}

struct sk_buff *skb_append_frag(struct sk_buff *head, struct sk_buff *skb)
{
	struct sk_buff **pprev;

	if (head == NULL)
		return skb;

	pprev = &skb_shinfo(head)->frag_list;
	while (*pprev != NULL)
		pprev = &(*pprev)->next;
	*pprev = skb;

	head->data_len += skb->len;
	head->len += skb->len;
	head->truesize += skb->truesize;
	return head;
}

static int __init dect_module_init(void)
{
	int err;

	err = dect_transceiver_module_init();
	if (err < 0)
		goto err1;
	err = dect_netlink_module_init();
	if (err < 0)
		goto err2;
	err = dect_af_module_init();
	if (err < 0)
		goto err3;
	return 0;

err3:
	dect_netlink_module_exit();
err2:
	dect_af_module_exit();
err1:
	return err;
}

static void __exit dect_module_exit(void)
{
	dect_af_module_exit();
	dect_netlink_module_exit();
	dect_transceiver_module_exit();
}

module_init(dect_module_init);
module_exit(dect_module_exit);

MODULE_AUTHOR("Patrick McHardy <kaber@trash.net>");
MODULE_DESCRIPTION("DECT protocol stack");
MODULE_LICENSE("GPL");
