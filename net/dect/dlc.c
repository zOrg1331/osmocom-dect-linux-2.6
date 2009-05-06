/*
 * DECT DLC Layer
 *
 * Copyright (c) 2009 Patrick McHardy <kaber@trash.net>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#define DEBUG
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/list.h>
#include <linux/skbuff.h>
#include <linux/net.h>
#include <linux/dect.h>
#include <net/dect/dect.h>

static struct dect_mac_conn *
dect_mac_conn_get_by_mcei(const struct dect_cluster *cl, u32 mcei)
{
	struct dect_mac_conn *mc;

	list_for_each_entry(mc, &cl->mac_connections, list) {
		if (mc->mcei == mcei)
			return mc;
	}
	return NULL;
}

struct dect_mac_conn *
dect_mac_conn_get_by_mci(const struct dect_cluster *cl, const struct dect_mci *mci)
{
	struct dect_mac_conn *mc;

	list_for_each_entry(mc, &cl->mac_connections, list) {
		if (!dect_ari_cmp(&mc->mci.ari, &mci->ari) &&
		    !dect_pmid_cmp(&mc->mci.pmid, &mci->pmid) &&
		    mc->mci.lcn == mci->lcn)
			return mc;
	}
	return NULL;
}

struct dect_mac_conn *dect_mac_conn_init(struct dect_cluster *cl,
					 const struct dect_mci *mci,
					 const struct dect_mbc_id *id)
{
	struct dect_mac_conn *mc;

	mc = kzalloc(sizeof(*mc), GFP_ATOMIC);
	if (mc == NULL)
		return NULL;

	mc->cl    = cl;
	mc->mcei  = id != NULL ? id->mcei : dect_mbc_alloc_mcei(cl);
	memcpy(&mc->mci, mci, sizeof(mc->mci));
	mc->state = DECT_MAC_CONN_CLOSED;

	list_add_tail(&mc->list, &cl->mac_connections);
	return mc;
}

void dect_dlc_mac_conn_release(struct dect_mac_conn *mc)
{
	list_del(&mc->list);
	kfree(mc);
}

static void dect_mac_conn_state_change(struct dect_mac_conn *mc,
				       enum dect_mac_conn_states state)
{
	mc->state = state;
	dect_cplane_notify_state_change(mc);
}

int dect_dlc_mac_conn_establish(struct dect_mac_conn *mc)
{
	struct dect_mbc_id mid = {
		.mcei		= mc->mcei,
		.ari		= mc->mci.ari,
		.pmid		= mc->mci.pmid,
		.type		= DECT_MAC_CONN_BASIC,
		.ecn		= mc->mci.lcn,
		.service	= mc->service,
	};
	int err;

	err = dect_mbc_con_request(mc->cl, &mid);
	if (err < 0)
		return err;
	dect_mac_conn_state_change(mc, DECT_MAC_CONN_OPEN_PENDING);
	return 0;
}

int dect_dlc_mac_conn_confirm(struct dect_cluster *cl, u32 mcei,
			      enum dect_mac_service_types service)
{
	struct dect_mac_conn *mc;

	mc = dect_mac_conn_get_by_mcei(cl, mcei);
	if (WARN_ON(mc == NULL))
		return -ENOENT;

	mc->service = service;
	dect_mac_conn_state_change(mc, DECT_MAC_CONN_OPEN);
	return 0;
}

int dect_dlc_mac_conn_indicate(struct dect_cluster *cl,
			       const struct dect_mbc_id *id)
{
	struct dect_mac_conn *mc;
	struct dect_mci mci = {
		.ari		= id->ari,
		.pmid		= id->pmid,
		.lcn		= id->ecn & DECT_LCN_MASK,
	};

	mc = dect_mac_conn_init(cl, &mci, id);
	if (mc == NULL)
		return -ENOMEM;
	mc->service = id->service;
	dect_mac_conn_state_change(mc, DECT_MAC_CONN_OPEN);
	return 0;
}

int dect_dlc_mac_conn_disconnect(struct dect_cluster *cl, u32 mcei)
{
	struct dect_mac_conn *mc;

	mc = dect_mac_conn_get_by_mcei(cl, mcei);
	if (WARN_ON(mc == NULL))
		return -ENOENT;

	dect_mac_conn_state_change(mc, DECT_MAC_CONN_CLOSED);
	dect_dlc_mac_conn_release(mc);
	return 0;
}

void dect_dlc_mac_co_data_indicate(struct dect_cluster *cl, u32 mcei,
				   enum dect_data_channels chan,
				   struct sk_buff *skb)
{
	struct dect_mac_conn *mc;

	mc = dect_mac_conn_get_by_mcei(cl, mcei);
	if (WARN_ON(mc == NULL))
		goto err;

	pr_debug("dlc: data mcei %u mc %p chan %u len %u\n", mcei, mc, chan, skb->len);
	switch (chan) {
	case DECT_MC_C_S:
	case DECT_MC_C_F:
		return dect_cplane_rcv(mc, chan, skb);
	case DECT_MC_I_N:
	case DECT_MC_I_P:
		return dect_uplane_rcv(mc, chan, skb);
	default:
		goto err;
	}
err:
	kfree_skb(skb);
}

struct sk_buff *dect_dlc_mac_co_dtr_indicate(struct dect_cluster *cl, u32 mcei,
					     enum dect_data_channels chan)
{
	struct dect_mac_conn *mc;

	mc = dect_mac_conn_get_by_mcei(cl, mcei);
	if (mc == NULL) {
		if (net_ratelimit())
			printk("DLC: DTR no connection\n");
		return NULL;
	}

	pr_debug("dlc: dtr mcei %u mc %p chan %u\n", mcei, mc, chan);
	switch (chan) {
	case DECT_MC_C_S:
	case DECT_MC_C_F:
		return dect_cplane_dtr(mc, chan);
	case DECT_MC_I_N:
	case DECT_MC_I_P:
		return dect_uplane_dtr(mc, chan);
	default:
		return NULL;
	}
}
