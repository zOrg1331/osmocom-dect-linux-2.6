/*
 * DECT DLC U-plane
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
#include <linux/list.h>
#include <linux/skbuff.h>
#include <linux/net.h>
#include <linux/dect.h>
#include <net/dect/dect.h>

static struct sk_buff *dect_fbn_dequeue(struct dect_fbx *fbx)
{
	struct dect_lux *lux = container_of(fbx, struct dect_lux, fbx);

	return lux->ops->dequeue(lux);
}

static void dect_fbn_enqueue(struct dect_fbx *fbx, struct sk_buff *skb)
{
	struct dect_lux *lux = container_of(fbx, struct dect_lux, fbx);

	lux->ops->enqueue(lux, skb);
}

const struct dect_fbx_ops dect_fbn_ops = {
	.dequeue	= dect_fbn_dequeue,
	.enqueue	= dect_fbn_enqueue,
};

struct sk_buff *dect_uplane_dtr(struct dect_mac_conn *mc, enum dect_data_channels chan)
{
	struct dect_fbx *fbx;

	fbx = mc->fbx;
	if (fbx == NULL)
		return NULL;
	return fbx->ops->dequeue(fbx);
}

void dect_uplane_rcv(struct dect_mac_conn *mc, enum dect_data_channels chan,
		     struct sk_buff *skb)
{
	struct dect_fbx *fbx;

	fbx = mc->fbx;
	if (fbx == NULL)
		goto err;
	return fbx->ops->enqueue(fbx, skb);

err:
	kfree_skb(skb);
}

void dect_uplane_notify_state_change(struct dect_mac_conn *mc)
{
	struct dect_lux *lux;
	struct dect_fbx *fbx;

	fbx = mc->fbx;
	if (fbx == NULL)
		return;
	lux = container_of(fbx, struct dect_lux, fbx);

	switch (mc->state) {
	case DECT_MAC_CONN_OPEN_PENDING:
		break;
	case DECT_MAC_CONN_OPEN:
		break;
	case DECT_MAC_CONN_CLOSED:
		return lux->ops->disconnect(lux);
	}
}
