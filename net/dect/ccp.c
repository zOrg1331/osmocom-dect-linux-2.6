/*
 * DECT Cell Control Protocol
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
#include <linux/init.h>
#include <linux/list.h>
#include <linux/skbuff.h>
#include <linux/net.h>
#include <linux/dect.h>
#include <net/dect/dect.h>
#include <net/dect/mac_csf.h>
#include <net/dect/mac_ccf.h>
#include <net/dect/ccp.h>
#include <net/tipc/tipc.h>

static struct sk_buff *dect_ccp_msg_alloc(size_t size)
{
	struct sk_buff *skb;

	size += sizeof(struct dect_ccp_msg_hdr) + 2 * LL_MAX_HEADER;
	skb = alloc_skb(size, GFP_ATOMIC);
	if (skb == NULL)
		return NULL;
	skb_reserve(skb, size);
	return skb;
}

static void dect_ccp_build_msg(struct sk_buff *skb,
			       enum dect_ccp_primitives prim)
{
	struct dect_ccp_msg_hdr *h;

	h = (struct dect_ccp_msg_hdr *)skb_push(skb, sizeof(*h));
	h->primitive = prim;
}

static int dect_ccp_send_to_cell(const struct dect_cell_handle *ch,
				 struct sk_buff *skb,
				 enum dect_ccp_primitives prim)
{
	int err;

	dect_ccp_build_msg(skb, prim);
	err = tipc_send_buf(ch->portref, skb, skb->len);
	if (err < 0 && net_ratelimit())
		printk("Failed to send DECT CCP message\n");
	return err;
}

static int dect_ccp_send_to_cluster(const struct dect_cluster_handle *clh,
				    struct sk_buff *skb,
				    enum dect_ccp_primitives prim)
{
	int err;

	dect_ccp_build_msg(skb, prim);
	err = tipc_send_buf(clh->portref, skb, skb->len);
	if (err < 0 && net_ratelimit())
		printk("Failed to send DECT CCP message\n");
	return err;
}

static void dect_ccp_build_mbc_msg(struct sk_buff *skb, const struct dect_mbc_id *id,
				   u8 data)
{
	struct dect_ccp_mbc_msg *msg;

	msg = (struct dect_ccp_mbc_msg *)__skb_push(skb, sizeof(*msg));
	msg->mcei = cpu_to_be32(id->mcei);
	msg->pmid = cpu_to_be32(dect_build_pmid(&id->pmid));
	msg->ari  = cpu_to_be64(dect_build_ari(&id->ari));
	msg->ecn  = id->ecn;
	msg->data = data;
}

static bool dect_ccp_parse_mbc_msg(struct dect_mbc_id *id, u8 *data,
				   struct sk_buff *skb)
{
	struct dect_ccp_mbc_msg *msg;

	if (!pskb_may_pull(skb, sizeof(*msg)))
		return false;
	msg = (struct dect_ccp_mbc_msg *)skb->data;
	__skb_pull(skb, sizeof(*msg));

	id->mcei = be32_to_cpu(msg->mcei);
	dect_parse_pmid(&id->pmid, be32_to_cpu(msg->pmid));
	if (!dect_parse_ari(&id->ari, be64_to_cpu(msg->ari)))
		return false;
	id->ecn = msg->ecn;
	if (data != NULL)
		*data = msg->data;
	return true;
}

static void dect_ccp_build_sysinfo(struct sk_buff *skb,
				   const struct dect_ari *pari, u8 rpn,
				   const struct dect_si *si)
{
	struct dect_ccp_sysinfo_msg *msg;
	unsigned int i;

	msg = (struct dect_ccp_sysinfo_msg *)__skb_push(skb, sizeof(*msg));
	msg->pari = cpu_to_be64(dect_build_ari(pari));
	for (i = 0; i < si->num_saris; i++)
		msg->sari[i] = cpu_to_be64(dect_build_ari(&si->sari[i].ari));
	msg->num_saris = i;
	msg->fpc = cpu_to_be64(si->fpc.fpc);
	msg->hlc = cpu_to_be64(si->fpc.hlc);
	msg->mfn = cpu_to_be32(si->mfn.num);
	msg->rpn = rpn;
}

static bool dect_ccp_parse_sysinfo(struct dect_ari *pari, u8 *rpn,
				   struct dect_si *si, struct sk_buff *skb)
{
	struct dect_ccp_sysinfo_msg *msg;
	unsigned int i;

	if (!pskb_may_pull(skb, sizeof(*msg)))
		return false;
	msg = (struct dect_ccp_sysinfo_msg *)skb->data;
	__skb_pull(skb, sizeof(*msg));

	if (!dect_parse_ari(pari, be64_to_cpu(msg->pari)))
		return false;
	*rpn = msg->rpn;

	if (msg->num_saris > ARRAY_SIZE(si->sari))
		return false;
	for (i = 0; i < msg->num_saris; i++) {
		if (!dect_parse_ari(&si->sari[i].ari,
				    be64_to_cpu(msg->sari[i])))
			return false;
	}
	si->fpc.fpc = be64_to_cpu(msg->fpc);
	si->fpc.hlc = be64_to_cpu(msg->hlc);
	si->mfn.num = be32_to_cpu(msg->mfn);
	return true;
}

static int dect_ccp_send_set_mode(const struct dect_cell_handle *ch,
				  enum dect_cluster_modes mode)
{
	struct dect_ccp_mode_msg *msg;
	struct sk_buff *skb;

	skb = dect_ccp_msg_alloc(sizeof(*msg));
	if (skb == NULL)
		return -ENOMEM;
	msg = (struct dect_ccp_mode_msg *)__skb_push(skb, sizeof(*msg));
	msg->mode = mode;

	return dect_ccp_send_to_cell(ch, skb, DECT_CCP_SET_MODE);
}

static void dect_ccp_parse_set_mode(const struct dect_cell_handle *ch,
				    struct sk_buff *skb)
{
	struct dect_ccp_mode_msg *msg;

	if (!pskb_may_pull(skb, sizeof(*msg)))
		return;
	msg = (struct dect_ccp_mode_msg *)skb->data;

	ch->ops->set_mode(ch, msg->mode);
}

static int dect_ccp_send_scan(const struct dect_cell_handle *ch,
			      const struct dect_llme_req *lreq,
			      const struct dect_ari *ari,
			      const struct dect_ari *ari_mask)
{
	struct dect_ccp_scan_msg *msg;
	struct sk_buff *skb;

	skb = dect_ccp_msg_alloc(sizeof(*msg));
	if (skb == NULL)
		return -ENOMEM;
	msg = (struct dect_ccp_scan_msg *)__skb_push(skb, sizeof(*msg));
	msg->ari = cpu_to_be64(dect_build_ari(ari));
	msg->ari_mask = cpu_to_be64(dect_build_ari(ari_mask));

	return dect_ccp_send_to_cell(ch, skb, DECT_CCP_SCAN);
}

static void dect_ccp_parse_scan(const struct dect_cell_handle *ch,
				struct sk_buff *skb)
{
	struct dect_ccp_scan_msg *msg;
	struct dect_ari ari, ari_mask;

	if (!pskb_may_pull(skb, sizeof(*msg)))
		return;
	msg = (struct dect_ccp_scan_msg *)skb->data;

	if (!dect_parse_ari(&ari, be64_to_cpu(msg->ari)))
		return;
	if (!dect_parse_ari(&ari_mask, be64_to_cpu(msg->ari_mask)))
		return;
	ch->ops->scan(ch, NULL, &ari, &ari_mask);
}

static int dect_ccp_send_preload(const struct dect_cell_handle *ch,
				 const struct dect_ari *pari, u8 rpn,
				 const struct dect_si *si)
{
	struct sk_buff *skb;

	skb = dect_ccp_msg_alloc(sizeof(struct dect_ccp_sysinfo_msg));
	if (skb == NULL)
		return -ENOMEM;
	dect_ccp_build_sysinfo(skb, pari, rpn, si);

	return dect_ccp_send_to_cell(ch, skb, DECT_CCP_PRELOAD);
}

static void dect_ccp_parse_preload(const struct dect_cell_handle *ch,
				   struct sk_buff *skb)
{
	struct dect_ari pari;
	struct dect_si si;
	u8 rpn;

	if (!dect_ccp_parse_sysinfo(&pari, &rpn, &si, skb))
		return;
	ch->ops->preload(ch, &pari, rpn, &si);
}

static int dect_ccp_send_enable(const struct dect_cell_handle *ch)
{
	struct sk_buff *skb;

	skb = dect_ccp_msg_alloc(0);
	if (skb == NULL)
		return -ENOMEM;
	return dect_ccp_send_to_cell(ch, skb, DECT_CCP_ENABLE);
}

static void dect_ccp_parse_enable(const struct dect_cell_handle *ch,
				  struct sk_buff *skb)
{
	ch->ops->enable(ch);
}

static int dect_ccp_send_tbc_initiate(const struct dect_cell_handle *ch,
				      const struct dect_mbc_id *id,
				      const struct dect_channel_desc *cd)
{
	struct sk_buff *skb;

	skb = dect_ccp_msg_alloc(sizeof(struct dect_ccp_mbc_msg));
	if (skb == NULL)
		return -ENOMEM;
	dect_ccp_build_mbc_msg(skb, id, 0);
	return dect_ccp_send_to_cell(ch, skb, DECT_CCP_TBC_INITIATE);
}

static void dect_ccp_parse_tbc_initiate(const struct dect_cell_handle *ch,
					struct sk_buff *skb)
{
	struct dect_mbc_id id;

	if (!dect_ccp_parse_mbc_msg(&id, NULL, skb))
		return;
	ch->ops->tbc_initiate(ch, &id, NULL);
}

static void dect_ccp_send_tbc_release(const struct dect_cell_handle *ch,
				      const struct dect_mbc_id *id,
				      enum dect_release_reasons reason)
{
	struct sk_buff *skb;

	skb = dect_ccp_msg_alloc(sizeof(struct dect_ccp_mbc_msg));
	if (skb == NULL)
		return;
	dect_ccp_build_mbc_msg(skb, id, reason);
	dect_ccp_send_to_cell(ch, skb, DECT_CCP_TBC_RELEASE);
}

static void dect_ccp_parse_tbc_release(const struct dect_cell_handle *ch,
				       struct sk_buff *skb)
{
	struct dect_mbc_id id;
	u8 reason;

	if (!dect_ccp_parse_mbc_msg(&id, &reason, skb))
		return;
	ch->ops->tbc_release(ch, &id, reason);
}

static int dect_ccp_send_tbc_confirm(const struct dect_cell_handle *ch,
				     const struct dect_mbc_id *id)
{
	struct sk_buff *skb;

	skb = dect_ccp_msg_alloc(sizeof(struct dect_ccp_mbc_msg));
	if (skb == NULL)
		return -ENOMEM;
	dect_ccp_build_mbc_msg(skb, id, 0);
	return dect_ccp_send_to_cell(ch, skb, DECT_CCP_TBC_CONFIRM);
}

static void dect_ccp_parse_tbc_confirm(const struct dect_cell_handle *ch,
				       struct sk_buff *skb)
{
	struct dect_mbc_id id;

	if (!dect_ccp_parse_mbc_msg(&id, NULL, skb))
		return;
	ch->ops->tbc_confirm(ch, &id);
}

static void dect_ccp_send_tbc_data_request(const struct dect_cell_handle *ch,
					   const struct dect_mbc_id *id,
					   enum dect_data_channels chan,
					   struct sk_buff *skb)
{
	dect_ccp_build_mbc_msg(skb, id, chan);
	dect_ccp_send_to_cell(ch, skb, DECT_CCP_TBC_DATA_REQUEST);
}

static void dect_ccp_send_scan_report(const struct dect_cluster_handle *clh,
				      const struct dect_scan_result *res)
{
}

static int dect_ccp_send_mbc_conn_indicate(const struct dect_cluster_handle *clh,
					   const struct dect_cell_handle *ch,
					   const struct dect_mbc_id *id)
{
	struct sk_buff *skb;

	skb = dect_ccp_msg_alloc(sizeof(struct dect_ccp_mbc_msg));
	if (skb == NULL)
		return -ENOMEM;
	dect_ccp_build_mbc_msg(skb, id, 0);

	return dect_ccp_send_to_cluster(clh, skb, DECT_CCP_MBC_CONN_INDICATE);
}

static void dect_ccp_parse_mbc_conn_indicate(const struct dect_cell_handle *ch,
					     struct sk_buff *skb)
{
	const struct dect_cluster_handle *clh = ch->clh;
	struct dect_mbc_id id;

	if (!dect_ccp_parse_mbc_msg(&id, NULL, skb))
		return;
	clh->ops->mbc_conn_indicate(clh, ch, &id);
}

static int dect_ccp_send_mbc_conn_notify(const struct dect_cluster_handle *clh,
					 const struct dect_mbc_id *id,
					 enum dect_tbc_event event)
{
	struct sk_buff *skb;

	skb = dect_ccp_msg_alloc(sizeof(struct dect_ccp_mbc_msg));
	if (skb == NULL)
		return -ENOMEM;
	dect_ccp_build_mbc_msg(skb, id, event);

	return dect_ccp_send_to_cluster(clh, skb, DECT_CCP_MBC_CONN_NOTIFY);
}

static void dect_ccp_parse_mbc_conn_notify(const struct dect_cell_handle *ch,
					   struct sk_buff *skb)
{
	const struct dect_cluster_handle *clh = ch->clh;
	struct dect_mbc_id id;
	u8 event;

	if (!dect_ccp_parse_mbc_msg(&id, &event, skb))
		return;
	clh->ops->mbc_conn_notify(clh, &id, event);
}

static void dect_ccp_send_mbc_data_indicate(const struct dect_cluster_handle *clh,
					    const struct dect_mbc_id *id,
					    enum dect_data_channels chan,
					    struct sk_buff *skb)
{
	dect_ccp_build_mbc_msg(skb, id, chan);
	dect_ccp_send_to_cluster(clh, skb, DECT_CCP_MBC_DATA_INDICATE);
}

static void dect_ccp_parse_mbc_data_indicate(const struct dect_cell_handle *ch,
					     struct sk_buff *skb)
{
	const struct dect_cluster_handle *clh = ch->clh;
	struct dect_mbc_id id;
	u8 chan;

	if (!dect_ccp_parse_mbc_msg(&id, &chan, skb))
		return;
	clh->ops->mbc_data_indicate(clh, &id, chan, skb);
}

static void dect_ccp_send_mbc_dtr_indicate(const struct dect_cluster_handle *clh,
					   const struct dect_mbc_id *id,
					   enum dect_data_channels chan)
{
	struct sk_buff *skb;

	skb = dect_ccp_msg_alloc(sizeof(struct dect_ccp_mbc_msg));
	if (skb == NULL)
		return;
	dect_ccp_build_mbc_msg(skb, id, chan);

	dect_ccp_send_to_cluster(clh, skb, DECT_CCP_MBC_DTR_INDICATE);
}

static void dect_ccp_parse_mbc_dtr_indicate(const struct dect_cell_handle *ch,
					    struct sk_buff *skb)
{
	const struct dect_cluster_handle *clh = ch->clh;
	struct dect_mbc_id id;
	u8 chan;

	if (!dect_ccp_parse_mbc_msg(&id, &chan, skb))
		return;
	clh->ops->mbc_dtr_indicate(clh, &id, chan);
}

static void dect_ccp_send_mbc_dis_indicate(const struct dect_cluster_handle *clh,
					   const struct dect_mbc_id *id,
					   enum dect_release_reasons reason)
{
	struct sk_buff *skb;

	skb = dect_ccp_msg_alloc(sizeof(struct dect_ccp_mbc_msg));
	if (skb == NULL)
		return;// -ENOMEM;
	dect_ccp_build_mbc_msg(skb, id, reason);

	dect_ccp_send_to_cluster(clh, skb, DECT_CCP_MBC_DIS_INDICATE);
}

static void dect_ccp_parse_mbc_dis_indicate(const struct dect_cell_handle *ch,
					    struct sk_buff *skb)
{
	const struct dect_cluster_handle *clh = ch->clh;
	struct dect_mbc_id id;
	u8 reason;

	if (!dect_ccp_parse_mbc_msg(&id, &reason, skb))
		return;
	clh->ops->mbc_dis_indicate(clh, &id, reason);
}

static void dect_ccp_rcv_cell_msg(void *handle, u32 portref,
				  struct sk_buff **pskb,
				  const u8 *data, u32 size)
{
	struct dect_cell_handle *ch = handle;
	struct dect_ccp_msg_hdr *h;
	struct sk_buff *skb = *pskb;

	if (!pskb_may_pull(skb, sizeof(*h)))
		return;
	h = (struct dect_ccp_msg_hdr *)skb->data;
	__skb_pull(skb, sizeof(*h));

	switch (h->primitive) {
	case DECT_CCP_MBC_CONN_INDICATE:
		return dect_ccp_parse_mbc_conn_indicate(ch, skb);
	case DECT_CCP_MBC_CONN_NOTIFY:
		return dect_ccp_parse_mbc_conn_notify(ch, skb);
	case DECT_CCP_MBC_DATA_INDICATE:
		return dect_ccp_parse_mbc_data_indicate(ch, skb);
	case DECT_CCP_MBC_DTR_INDICATE:
		return dect_ccp_parse_mbc_dtr_indicate(ch, skb);
	case DECT_CCP_MBC_DIS_INDICATE:
		return dect_ccp_parse_mbc_dis_indicate(ch, skb);
	}
}

static void dect_ccp_cl_disconnect(void *handle, u32 portref,
				   struct sk_buff **pskb,
				   const u8 *data, u32 size, int reason)
{
	struct dect_cell_handle *ch = handle;
	struct dect_cluster_handle *clh = ch->clh;

	pr_debug("cell disconnected\n");
	clh->ops->unbind(clh, ch);
	kfree(ch);
}

static const struct dect_csf_ops dect_ccp_csf_ops = {
	.set_mode		= dect_ccp_send_set_mode,
	.scan			= dect_ccp_send_scan,
	.enable			= dect_ccp_send_enable,
	.preload		= dect_ccp_send_preload,
	.tbc_initiate		= dect_ccp_send_tbc_initiate,
	.tbc_confirm		= dect_ccp_send_tbc_confirm,
	.tbc_release		= dect_ccp_send_tbc_release,
	.tbc_data_request	= dect_ccp_send_tbc_data_request,
};

static void dect_ccp_cl_named_msg(void *handle, u32 portref,
				  struct sk_buff **pskb,
				  const u8 *data, u32 size,
				  u32 importance,
				  const struct tipc_portid *source,
				  const struct tipc_name_seq *dest)
{
	struct dect_cluster *cl = handle;
	struct dect_cluster_handle *clh = &cl->handle;
	struct dect_cell_handle *ch;
	struct iovec ack = { NULL, 0};
	int err;

	ch = kzalloc(sizeof(*ch), GFP_ATOMIC);
	if (ch == NULL)
		goto err1;
	ch->ops = &dect_ccp_csf_ops;

	err = tipc_createport(cl->tipc_id, ch, TIPC_HIGH_IMPORTANCE,
			      NULL, NULL, dect_ccp_cl_disconnect,
			      NULL, NULL, dect_ccp_rcv_cell_msg, NULL,
			      &ch->portref);
	if (err < 0)
		goto err2;

	err = tipc_connect2port(ch->portref, source);
	if (err < 0)
		goto err3;

	err = tipc_send(ch->portref, 1, &ack);
	if (err < 0)
		goto err3;

	err = clh->ops->bind(clh, ch);
	if (err < 0)
		goto err4;
	return;

err4:
	tipc_disconnect(ch->portref);
err3:
	tipc_deleteport(ch->portref);
err2:
	kfree(ch);
err1:
	return;
}

/**
 * dect_ccp_cluster_init - Initialize a cluster control CCP instance
 *
 * @cl:		DECT cluster
 */
int dect_ccp_cluster_init(struct dect_cluster *cl)
{
	struct tipc_name_seq seq;
	int err;

	err = tipc_attach(&cl->tipc_id, NULL, NULL);
	if (err < 0)
		goto err1;

	err = tipc_createport(cl->tipc_id, cl, TIPC_HIGH_IMPORTANCE,
			      NULL, NULL, NULL, NULL, dect_ccp_cl_named_msg,
			      NULL, NULL, &cl->tipc_portref);
	if (err < 0)
		goto err2;

	seq.type  = DECT_CCP_TIPC_TYPE;
	seq.lower = DECT_CCP_CLUSTER_PORT_BASE + cl->index;
	seq.upper = DECT_CCP_CLUSTER_PORT_BASE + cl->index;
	err = tipc_publish(cl->tipc_portref, TIPC_CLUSTER_SCOPE, &seq);
	if (err < 0)
		goto err3;
	return 0;

err3:
	tipc_deleteport(cl->tipc_portref);
err2:
	tipc_detach(cl->tipc_id);
err1:
	return err;
}

void dect_ccp_cluster_shutdown(struct dect_cluster *cl)
{
	tipc_detach(cl->tipc_id);
}

static void dect_ccp_rcv_cluster_msg(void *handle, u32 portref,
				     struct sk_buff **pskb,
				     const u8 *data, u32 size)
{
	struct sk_buff *skb = *pskb;
	struct dect_cell_handle *ch = handle;
	struct dect_ccp_msg_hdr *h;

	if (!pskb_may_pull(skb, sizeof(*h)))
		return;
	h = (struct dect_ccp_msg_hdr *)skb->data;
	__skb_pull(skb, sizeof(*h));

	switch (h->primitive) {
	case DECT_CCP_SET_MODE:
		return dect_ccp_parse_set_mode(ch, skb);
	case DECT_CCP_SCAN:
		return dect_ccp_parse_scan(ch, skb);
	case DECT_CCP_ENABLE:
		return dect_ccp_parse_enable(ch, skb);
	case DECT_CCP_PRELOAD:
		return dect_ccp_parse_preload(ch, skb);
	case DECT_CCP_TBC_INITIATE:
		return dect_ccp_parse_tbc_initiate(ch, skb);
	case DECT_CCP_TBC_CONFIRM:
		return dect_ccp_parse_tbc_confirm(ch, skb);
	case DECT_CCP_TBC_RELEASE:
		return dect_ccp_parse_tbc_release(ch, skb);
	}
}

static void dect_ccp_cluster_disconnect(void *handle, u32 portref,
					struct sk_buff **pskb,
					const u8 *data, u32 size, int reason)
{
	pr_debug("Cluster disconnected\n");
#if 0
	struct dect_cell_handle *clh = handle;

	clh->ops->unbind(clh);
#endif
}

static void dect_ccp_subscr_rcv(void *handle, u32 portref,
				struct sk_buff **pskb,
				const u8 *data, u32 size)
{
	struct dect_cell_handle *ch = handle;
	struct dect_cluster_handle *clh = ch->clh;
	struct sk_buff *skb = *pskb;
	struct tipc_event *ev;
	struct tipc_name name;
	int err;

	if (!pskb_may_pull(skb, sizeof(*ev)))
		return;
	ev = (struct tipc_event *)skb->data;

	if (ev->event != TIPC_PUBLISHED)
		return;

	/* Connect to cluster */
	err = tipc_createport(clh->tipc_id, ch, TIPC_HIGH_IMPORTANCE,
			      NULL, NULL, dect_ccp_cluster_disconnect,
			      NULL, NULL, dect_ccp_rcv_cluster_msg, NULL,
			      &clh->portref);
	if (err < 0)
		goto err1;

	name.type = DECT_CCP_TIPC_TYPE;
	name.instance = DECT_CCP_CLUSTER_PORT_BASE + clh->index;
	err = tipc_send2name(clh->portref, &name, 0, 0, NULL);
	if (err < 0)
		goto err2;
	return;

err2:
	tipc_deleteport(clh->portref);
err1:
	return;
}

/**
 * dect_ccp_cell_init - Initialize a cell CCP instance
 *
 * @cell:	DECT cell
 */
static int dect_ccp_bind_cell(struct dect_cluster_handle *clh,
			      struct dect_cell_handle *ch)
{
	struct tipc_subscr subscr;
	struct iovec iov = { &subscr, sizeof(subscr) };
	struct tipc_name tname;
	int err;

	err = tipc_attach(&clh->tipc_id, NULL, NULL);
	if (err < 0)
		goto err1;
	ch->clh = clh;

	/* Connect to topology service and subscribe to cluster port */
	err = tipc_createport(clh->tipc_id, ch, TIPC_CRITICAL_IMPORTANCE,
			      NULL, NULL, NULL, NULL, NULL,
			      dect_ccp_subscr_rcv, NULL, &clh->tportref);
	if (err < 0)
		goto err2;

	subscr.seq.type = DECT_CCP_TIPC_TYPE;
	subscr.seq.lower = DECT_CCP_CLUSTER_PORT_BASE + clh->index;
	subscr.seq.upper = DECT_CCP_CLUSTER_PORT_BASE + clh->index;
	subscr.timeout = TIPC_WAIT_FOREVER;
	subscr.filter = TIPC_SUB_PORTS;
	memset(&subscr.usr_handle, 0, sizeof(subscr.usr_handle));

	tname.type = TIPC_TOP_SRV;
	tname.instance = TIPC_TOP_SRV;

	err = tipc_send2name(clh->tportref, &tname, 0, 1, &iov);
	if (err < 0)
		goto err3;
	return 0;

err3:
	tipc_deleteport(clh->tportref);
err2:
	tipc_detach(clh->tipc_id);
err1:
	return err;

}

static void dect_ccp_unbind_cell(struct dect_cluster_handle *clh,
				 struct dect_cell_handle *ch)
{
	tipc_detach(clh->tipc_id);
}

static void dect_ccp_send_bmc_page_indicate(const struct dect_cluster_handle *clh,
					    struct sk_buff *skb)
{
}

static const struct dect_ccf_ops dect_ccp_ccf_ops = {
	.bind			= dect_ccp_bind_cell,
	.unbind			= dect_ccp_unbind_cell,
	.scan_report		= dect_ccp_send_scan_report,
	.mbc_conn_indicate	= dect_ccp_send_mbc_conn_indicate,
	.mbc_conn_notify	= dect_ccp_send_mbc_conn_notify,
	.mbc_dis_indicate	= dect_ccp_send_mbc_dis_indicate,
	.mbc_data_indicate	= dect_ccp_send_mbc_data_indicate,
	.mbc_dtr_indicate	= dect_ccp_send_mbc_dtr_indicate,
	.bmc_page_indicate	= dect_ccp_send_bmc_page_indicate,
};

struct dect_cluster_handle *dect_ccp_cell_init(struct dect_cell *cell, u8 clindex)
{
	struct dect_cluster_handle *clh;

	clh = kzalloc(sizeof(*clh), GFP_KERNEL);
	if (clh == NULL)
		return NULL;
	clh->index = clindex;
	clh->ops = &dect_ccp_ccf_ops;
	return clh;
}
