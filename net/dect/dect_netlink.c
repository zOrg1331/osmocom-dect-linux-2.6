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

static struct sock *nlsk __read_mostly;

static LIST_HEAD(dect_cluster_list);
static LIST_HEAD(dect_cell_list);

static struct dect_cluster *dect_cluster_get_by_name(const struct nlattr *nla)
{
	struct dect_cluster *cl;

	list_for_each_entry(cl, &dect_cluster_list, list) {
		if (!nla_strcmp(nla, cl->name))
			return cl;
	}
	return NULL;
}

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

struct dect_cluster *dect_cluster_get_by_pari(const struct dect_ari *ari)
{
	struct dect_cluster *cl;

	list_for_each_entry(cl, &dect_cluster_list, list) {
		if (!dect_ari_cmp(&cl->pari, ari))
			return cl;
	}
	return NULL;
}
EXPORT_SYMBOL_GPL(dect_cluster_get_by_pari);

struct dect_cell *dect_cell_get_by_index(u32 index)
{
	struct dect_cell *cell;

	list_for_each_entry(cell, &dect_cell_list, list) {
		if (cell->index == index)
			return cell;
	}
	return NULL;
}
EXPORT_SYMBOL_GPL(dect_cell_get_by_index);

static struct dect_cell *dect_cell_get_by_name(const struct nlattr *nla)
{
	struct dect_cell *cell;

	list_for_each_entry(cell, &dect_cell_list, list) {
		if (!nla_strcmp(nla, cell->name))
			return cell;
	}
	return NULL;
}

static struct dect_transceiver *dect_transceiver_get_by_name(const struct nlattr *nla)
{
	struct dect_transceiver *trx;

	list_for_each_entry(trx, &dect_transceiver_list, list) {
		if (!nla_strcmp(nla, trx->name))
			return trx;
	}
	return NULL;
}

/*
 * LLME
 */

static struct sk_buff *dect_llme_fill(const struct dect_cluster *cl,
				      const struct dect_llme_req *lreq,
				      u8 op, u8 type,
				      int (*fill)(const struct dect_cluster *,
						  struct sk_buff *, const void *),
				      const void *data);

static void dect_llme_req_init(struct dect_llme_req *lreq,
			       const struct nlmsghdr *nlh,
			       const struct sk_buff *skb)
{
	memcpy(&lreq->nlh, nlh, sizeof(lreq->nlh));
	lreq->nlpid = NETLINK_CB(skb).pid;
}

static int dect_fill_ari(struct sk_buff *skb, const struct dect_ari *ari, int attr)
{
	struct nlattr *nla;

	nla = nla_nest_start(skb, attr);
	if (nla == NULL)
		goto nla_put_failure;

	NLA_PUT_U8(skb, DECTA_ARI_CLASS, ari->arc);
	NLA_PUT_U32(skb, DECTA_ARI_FPN, ari->fpn);

	switch (ari->arc) {
	case DECT_ARC_A:
		NLA_PUT_U16(skb, DECTA_ARI_EMC, ari->emc);
		break;
	case DECT_ARC_B:
		NLA_PUT_U16(skb, DECTA_ARI_EIC, ari->eic);
		NLA_PUT_U32(skb, DECTA_ARI_FPS, ari->fps);
		break;
	case DECT_ARC_C:
		NLA_PUT_U16(skb, DECTA_ARI_POC, ari->poc);
		NLA_PUT_U32(skb, DECTA_ARI_FPS, ari->fps);
		break;
	case DECT_ARC_D:
		NLA_PUT_U32(skb, DECTA_ARI_GOP, ari->gop);
		break;
	case DECT_ARC_E:
		NLA_PUT_U16(skb, DECTA_ARI_FIL, ari->fil);
		break;
	}
	nla_nest_end(skb, nla);
	return 0;

nla_put_failure:
	return -1;
}

static const struct nla_policy dect_ari_policy[DECTA_ARI_MAX + 1] = {
	[DECTA_ARI_CLASS]	= { .type = NLA_U8 },
	[DECTA_ARI_FPN]		= { .type = NLA_U32 },
	[DECTA_ARI_FPS]		= { .type = NLA_U32 },
	[DECTA_ARI_EMC]		= { .type = NLA_U16 },
	[DECTA_ARI_EIC]		= { .type = NLA_U16 },
	[DECTA_ARI_POC]		= { .type = NLA_U16 },
	[DECTA_ARI_GOP]		= { .type = NLA_U32 },
	[DECTA_ARI_FIL]		= { .type = NLA_U32 },
};

static const u32 dect_ari_valid_attrs[] = {
	[DECT_ARC_A]		= (1 << DECTA_ARI_EMC),
	[DECT_ARC_B]		= (1 << DECTA_ARI_EIC) | (1 << DECTA_ARI_FPS),
	[DECT_ARC_C]		= (1 << DECTA_ARI_POC) | (1 << DECTA_ARI_FPS),
	[DECT_ARC_D]		= (1 << DECTA_ARI_GOP),
	[DECT_ARC_E]		= (1 << DECTA_ARI_FIL),
};

static int dect_nla_parse_ari(struct dect_ari *ari, const struct nlattr *nla)
{
	struct nlattr *tb[DECTA_ARI_MAX + 1];
	unsigned int attr;
	int err;

	err = nla_parse_nested(tb, DECTA_ARI_MAX, nla, dect_ari_policy);
	if (err < 0)
		return err;

	if (tb[DECTA_ARI_CLASS] == NULL)
		return -EINVAL;

	memset(ari, 0, sizeof(ari));
	ari->arc = nla_get_u8(tb[DECTA_ARI_CLASS]);
	if (ari->arc > DECT_ARC_E)
		return -EINVAL;

	for (attr = DECTA_ARI_UNSPEC + 1; attr <= DECTA_ARI_MAX; attr++) {
		if (tb[attr] == NULL)
			continue;

		switch (attr) {
		case DECTA_ARI_CLASS:
		case DECTA_ARI_FPN:
			/* always valid */
			break;
		default:
			if (!(dect_ari_valid_attrs[ari->arc] & (1 << attr)))
				return -EINVAL;
			break;
		}
	}

	if (tb[DECTA_ARI_FPN] != NULL)
		ari->fpn = nla_get_u32(tb[DECTA_ARI_FPN]);
	if (tb[DECTA_ARI_FPS] != NULL)
		ari->fps = nla_get_u32(tb[DECTA_ARI_FPS]);

	switch (ari->arc) {
	case DECT_ARC_A:
		if (tb[DECTA_ARI_EMC] != NULL)
			ari->emc = nla_get_u16(tb[DECTA_ARI_EMC]);
		break;
	case DECT_ARC_B:
		if (tb[DECTA_ARI_EIC] != NULL)
			ari->eic = nla_get_u16(tb[DECTA_ARI_EIC]);
		break;
	case DECT_ARC_C:
		if (tb[DECTA_ARI_POC] != NULL)
			ari->poc = nla_get_u16(tb[DECTA_ARI_POC]);
		break;
	case DECT_ARC_D:
		if (tb[DECTA_ARI_GOP] != NULL)
			ari->gop = nla_get_u32(tb[DECTA_ARI_GOP]);
		break;
	case DECT_ARC_E:
		if (tb[DECTA_ARI_FIL] != NULL)
			ari->fil = nla_get_u16(tb[DECTA_ARI_FIL]);
		break;
	}
	return 0;
}

static int dect_fill_sari(struct sk_buff *skb, const struct dect_sari *sari,
			  int attr)
{
	struct nlattr *nla;

	nla = nla_nest_start(skb, attr);
	if (nla == NULL)
		goto nla_put_failure;
	if (dect_fill_ari(skb, &sari->ari, DECTA_SARI_ARI) < 0)
		goto nla_put_failure;
	if (sari->black)
		NLA_PUT_FLAG(skb, DECTA_SARI_BLACK);
	if (sari->tari)
		NLA_PUT_FLAG(skb, DECTA_SARI_TARI);
	nla_nest_end(skb, nla);
	return 0;

nla_put_failure:
	return -1;
}

static int dect_llme_fill_mac_info(const struct dect_cluster *cl,
				   struct sk_buff *skb, const void *data)
{
	const struct dect_scan_result *res = data;
	const struct dect_idi *idi = &res->idi;
	const struct dect_si *si = &res->si;
	struct nlattr *nla;
	unsigned int i;

	NLA_PUT_U8(skb, DECTA_MAC_INFO_RSSI, res->rssi >> DECT_RSSI_AVG_SCALE);

	if (dect_fill_ari(skb, &idi->pari, DECTA_MAC_INFO_PARI) < 0)
		goto nla_put_failure;
	NLA_PUT_U8(skb, DECTA_MAC_INFO_RPN, idi->rpn);

	if (si->mask & (1 << DECT_TM_TYPE_SARI) && si->num_saris > 0) {
		nla = nla_nest_start(skb, DECTA_MAC_INFO_SARI_LIST);
		if (nla == NULL)
			goto nla_put_failure;
		for (i = 0; i < si->num_saris; i++) {
			if (dect_fill_sari(skb, &si->sari[i],
					   DECTA_LIST_ELEM) < 0)
				goto nla_put_failure;
		}
		nla_nest_end(skb, nla);
	}

	if (si->mask & (1 << DECT_TM_TYPE_FPC)) {
		NLA_PUT_U32(skb, DECTA_MAC_INFO_FPC, si->fpc.fpc);
		NLA_PUT_U32(skb, DECTA_MAC_INFO_HLC, si->fpc.hlc);
	}

	if (si->mask & (1 << DECT_TM_TYPE_EFPC)) {
		nla = nla_nest_start(skb, DECTA_MAC_INFO_EFPC);
		if (nla == NULL)
			goto nla_put_failure;
		NLA_PUT_U8(skb, DECTA_EFPC_CRFP_HOPS, si->efpc.crfp);
		NLA_PUT_U8(skb, DECTA_EFPC_REP_HOPS, si->efpc.rep);
		NLA_PUT_U16(skb, DECTA_EFPC_EHLC, si->efpc.ehlc);
		nla_nest_end(skb, nla);
	}

	return 0;

nla_put_failure:
	return -EMSGSIZE;
}

void dect_llme_scan_result_notify(const struct dect_cluster *cl,
				  const struct dect_scan_result *res)
{
	struct sk_buff *skb;
	u32 pid = res->lreq.nlpid;
	int err = -ENOBUFS;

	skb = dect_llme_fill(cl, &res->lreq,
			     DECT_LLME_INDICATE, DECT_LLME_MAC_INFO,
			     dect_llme_fill_mac_info, res);
	if (IS_ERR(skb)) {
		err = PTR_ERR(skb);
		goto err;
	}
	nlmsg_notify(nlsk, skb, pid, DECTNLGRP_LLME, 1, GFP_ATOMIC);
err:
	if (err < 0)
		netlink_set_err(nlsk, pid, DECTNLGRP_LLME, err);
}

static const struct nla_policy dect_llme_mac_info_policy[DECTA_MAC_INFO_MAX + 1] =  {
	[DECTA_MAC_INFO_PARI]		= { .type = NLA_NESTED },
	[DECTA_MAC_INFO_RPN]		= { .type = NLA_U8 },
	[DECTA_MAC_INFO_RSSI]		= { .type = NLA_U8 },
	[DECTA_MAC_INFO_SARI_LIST]	= { .type = NLA_NESTED },
	[DECTA_MAC_INFO_FPC]		= { .type = NLA_U32 },
	[DECTA_MAC_INFO_EFPC]		= { .type = NLA_NESTED },
};

static int dect_llme_scan_request(struct dect_cluster *cl,
				  const struct sk_buff *skb,
				  const struct nlmsghdr *nlh,
				  const struct nlattr *tb[DECTA_MAC_INFO_MAX + 1])
{
	struct dect_llme_req lreq;
	struct dect_ari pari, pari_mask;
	int err;

	if (tb[DECTA_MAC_INFO_PARI] != NULL) {
		err = dect_nla_parse_ari(&pari, tb[DECTA_MAC_INFO_PARI]);
		if (err < 0)
			return err;
	} else
		memset(&pari, 0, sizeof(pari));
	memset(&pari_mask, 0, sizeof(pari_mask));

	dect_llme_req_init(&lreq, nlh, skb);
	return dect_cluster_scan(cl, &lreq, &pari, &pari_mask);
}

static struct sk_buff *dect_llme_fill(const struct dect_cluster *cl,
				      const struct dect_llme_req *lreq,
				      u8 op, u8 type,
				      int (*fill)(const struct dect_cluster *,
						  struct sk_buff *, const void *),
				      const void *data)
{
	struct sk_buff *skb;
	struct nlmsghdr *nlh;
	struct dectmsg *dm;
	struct nlattr *nest;
	u32 seq = lreq ? lreq->nlh.nlmsg_seq : 0;
	int err = -ENOBUFS;

	skb = nlmsg_new(NLMSG_GOODSIZE, GFP_ATOMIC);
	if (skb == NULL)
		goto err1;

	nlh = nlmsg_put(skb, 0, seq, DECT_LLME_MSG, sizeof(*dm), NLMSG_DONE);
	if (nlh == NULL) {
		err = -EMSGSIZE;
		goto err2;
	}

	dm = nlmsg_data(nlh);
	dm->dm_index = cl->index;

	NLA_PUT_U8(skb, DECTA_LLME_OP, op);
	NLA_PUT_U8(skb, DECTA_LLME_TYPE, type);
	nest = nla_nest_start(skb, DECTA_LLME_DATA);
	if (nest == NULL)
		goto nla_put_failure;
	if (fill(cl, skb, data) < 0)
		goto nla_put_failure;
	nla_nest_end(skb, nest);

	nlmsg_end(skb, nlh);
	return skb;

nla_put_failure:
err2:
	kfree_skb(skb);
err1:
	return ERR_PTR(err);
}

static const struct dect_llme_link {
	struct {
		int (*doit)(struct dect_cluster *cl, const struct sk_buff *,
			    const struct nlmsghdr *, const struct nlattr *[]);
	} ops[DECT_LLME_MAX + 1];
	const struct nla_policy *policy;
	unsigned int maxtype;
} dect_llme_dispatch[DECT_LLME_MAX + 1] = {
	[DECT_LLME_SCAN]	= {
		.policy		= dect_llme_mac_info_policy,
		.maxtype	= DECTA_MAC_INFO_MAX,
		.ops		= {
			[DECT_LLME_REQUEST].doit = dect_llme_scan_request,
		},
	},
};

static const struct nla_policy dect_llme_policy[DECTA_LLME_MAX + 1] = {
	[DECTA_LLME_OP]		= { .type = NLA_U8 },
	[DECTA_LLME_TYPE]	= { .type = NLA_U8 },
	[DECTA_LLME_DATA]	= { .type = NLA_NESTED },
};

static int dect_llme_msg(const struct sk_buff *skb,
			 const struct nlmsghdr *nlh,
			 const struct nlattr *tb[DECTA_LLME_MAX + 1])
{
	const struct dect_llme_link *link;
	struct dect_cluster *cl;
	struct dectmsg *dm;
	enum dect_llme_msg_types type;
	enum dect_llme_ops op;
	int err;

	if (tb[DECTA_LLME_OP] == NULL ||
	    tb[DECTA_LLME_TYPE] == NULL ||
	    tb[DECTA_LLME_DATA] == NULL)
		return -EINVAL;

	dm = nlmsg_data(nlh);
	cl = dect_cluster_get_by_index(dm->dm_index);
	if (cl == NULL)
		return -ENODEV;

	type = nla_get_u8(tb[DECTA_LLME_TYPE]);
	if (type > DECT_LLME_MAX)
		return -EINVAL;
	link = &dect_llme_dispatch[type];

	op = nla_get_u8(tb[DECTA_LLME_OP]);
	switch (op) {
	case DECT_LLME_REQUEST:
	case DECT_LLME_INDICATE:
	case DECT_LLME_RESPONSE:
	case DECT_LLME_CONFIRM:
		if (link->ops[op].doit == NULL)
			return -EOPNOTSUPP;
		break;
	default:
		return -EINVAL;
	}

	if (1) {
		struct nlattr *nla[link->maxtype + 1];

		err = nla_parse_nested(nla, link->maxtype, tb[DECTA_LLME_DATA],
				       link->policy);
		if (err < 0)
			return err;
		return link->ops[op].doit(cl, skb, nlh,
					  (const struct nlattr **)nla);
	}
}

/*
 * Cluster
 */

static int dect_cluster_alloc_index(void)
{
	static int index;

	for (;;) {
		if (++index <= 0)
			index = 1;
		if (!dect_cluster_get_by_index(index))
			return index;
	}
}

static int dect_fill_cluster(struct sk_buff *skb,
			     const struct dect_cluster *cl,
			     u16 type, u32 pid, u32 seq, u16 flags)
{
	struct nlmsghdr *nlh;
	struct dectmsg *dm;
	struct nlattr *nest;
	struct dect_cell_handle *ch;

	nlh = nlmsg_put(skb, pid, seq, type, sizeof(*dm), flags);
	if (nlh == NULL)
		return -EMSGSIZE;

	dm = nlmsg_data(nlh);
	dm->dm_index = cl->index;
	NLA_PUT_STRING(skb, DECTA_CLUSTER_NAME, cl->name);
	NLA_PUT_U8(skb, DECTA_CLUSTER_MODE, cl->mode);
	if (dect_fill_ari(skb, &cl->pari, DECTA_CLUSTER_PARI) < 0)
		goto nla_put_failure;

	if (!list_empty(&cl->cells)) {
		nest = nla_nest_start(skb, DECTA_CLUSTER_CELLS);
		if (nest == NULL)
			goto nla_put_failure;
		list_for_each_entry(ch, &cl->cells, list)
			NLA_PUT_U8(skb, DECTA_LIST_ELEM, ch->rpn);
		nla_nest_end(skb, nest);
	}

	return nlmsg_end(skb, nlh);

nla_put_failure:
	nlmsg_cancel(skb, nlh);
	return -EMSGSIZE;
}

static int dect_dump_cluster(struct sk_buff *skb,
			     struct netlink_callback *cb)
{
	const struct dect_cluster *cl;
	unsigned int idx, s_idx;

	s_idx = cb->args[0];
	idx = 0;
	list_for_each_entry(cl, &dect_cluster_list, list) {
		if (idx < s_idx)
			goto cont;
		if (dect_fill_cluster(skb, cl, DECT_NEW_CLUSTER,
				      NETLINK_CB(cb->skb).pid,
				      cb->nlh->nlmsg_seq, NLM_F_MULTI) <= 0)
			break;
cont:
		idx++;
	}
	cb->args[0] = idx;

	return skb->len;
}

static void dect_notify_cluster(u16 event, const struct dect_cluster *cl,
				const struct nlmsghdr *nlh, u32 pid)
{
	struct sk_buff *skb;
	bool report = nlh ? nlmsg_report(nlh) : 0;
	u32 seq = nlh ? nlh->nlmsg_seq : 0;
	int err = -ENOBUFS;

	skb = nlmsg_new(NLMSG_GOODSIZE, GFP_KERNEL);
	if (skb == NULL)
		goto err;

	err = dect_fill_cluster(skb, cl, event, pid, seq, NLMSG_DONE);
	if (err < 0) {
		WARN_ON(err == -EMSGSIZE);
		kfree_skb(skb);
		goto err;
	}
	nlmsg_notify(nlsk, skb, pid, DECTNLGRP_CLUSTER, report, GFP_KERNEL);
err:
	if (err < 0)
		netlink_set_err(nlsk, pid, DECTNLGRP_CLUSTER, err);
}

static const struct nla_policy dect_cluster_policy[DECTA_CLUSTER_MAX + 1] = {
	[DECTA_CLUSTER_NAME]		= { .type = NLA_STRING, .len = DECTNAMSIZ },
	[DECTA_CLUSTER_MODE]		= { .type = NLA_U8 },
	[DECTA_CLUSTER_PARI]		= { .len  = NLA_NESTED },
};

static int dect_new_cluster(const struct sk_buff *skb,
			    const struct nlmsghdr *nlh,
			    const struct nlattr *tb[DECTA_CLUSTER_MAX + 1])
{
	struct dect_cluster *cl;
	struct dect_ari pari;
	enum dect_cluster_modes uninitialized_var(mode);
	int err;

	if (tb[DECTA_CLUSTER_NAME] == NULL)
		return -EINVAL;

	if (tb[DECTA_CLUSTER_MODE] != NULL) {
		mode = nla_get_u8(tb[DECTA_CLUSTER_MODE]);
		switch (mode) {
		case DECT_MODE_FP:
		case DECT_MODE_PP:
		case DECT_MODE_MONITOR:
			break;
		default:
			return -EINVAL;
		}
	}

	if (tb[DECTA_CLUSTER_PARI] != NULL) {
		err = dect_nla_parse_ari(&pari, tb[DECTA_CLUSTER_PARI]);
		if (err < 0)
			return err;
	}

	cl = dect_cluster_get_by_name(tb[DECTA_CLUSTER_NAME]);
	if (cl != NULL) {
		if (nlh->nlmsg_flags & NLM_F_EXCL)
			return -EEXIST;

		return 0;
	}

	if (!(nlh->nlmsg_flags & NLM_F_CREATE))
		return -ENOENT;

	if (tb[DECTA_CLUSTER_MODE] == NULL)
		return -EINVAL;

	cl = kzalloc(sizeof(*cl), GFP_KERNEL);
	if (cl == NULL)
		return -ENOMEM;
	nla_strlcpy(cl->name, tb[DECTA_CLUSTER_NAME], sizeof(cl->name));

	memcpy(&cl->pari, &pari, sizeof(cl->pari));
	cl->index = dect_cluster_alloc_index();
	cl->mode  = mode;
	dect_cluster_init(cl);

	list_add_tail(&cl->list, &dect_cluster_list);
	dect_notify_cluster(DECT_NEW_CLUSTER, cl, nlh, NETLINK_CB(skb).pid);
	return 0;
}

static int dect_del_cluster(const struct sk_buff *skb,
			    const struct nlmsghdr *nlh,
			    const struct nlattr *tb[DECTA_CLUSTER_MAX + 1])
{
	struct dect_cluster *cl;
	struct dectmsg *dm;

	dm = nlmsg_data(nlh);
	if (dm->dm_index != 0)
		cl = dect_cluster_get_by_index(dm->dm_index);
	else if (tb[DECTA_CLUSTER_NAME] != NULL)
		cl = dect_cluster_get_by_name(tb[DECTA_CLUSTER_NAME]);
	else
		return -EINVAL;
	if (cl == NULL)
		return -ENODEV;

	dect_cluster_shutdown(cl);
	list_del(&cl->list);

	dect_notify_cluster(DECT_DEL_CLUSTER, cl, nlh, NETLINK_CB(skb).pid);
	kfree(cl);
	return 0;
}

static int dect_get_cluster(const struct sk_buff *in_skb,
			    const struct nlmsghdr *nlh,
			    const struct nlattr *tb[DECTA_CLUSTER_MAX + 1])
{
	u32 pid = NETLINK_CB(in_skb).pid;
	const struct dect_cluster *cl;
	struct dectmsg *dm;
	struct sk_buff *skb;
	int err;

	dm = nlmsg_data(nlh);
	if (dm->dm_index != 0)
		cl = dect_cluster_get_by_index(dm->dm_index);
	else if (tb[DECTA_CLUSTER_NAME] != NULL)
		cl = dect_cluster_get_by_name(tb[DECTA_CLUSTER_NAME]);
	else
		return -EINVAL;
	if (cl == NULL)
		return -ENODEV;

	skb = alloc_skb(NLMSG_GOODSIZE, GFP_KERNEL);
	if (skb == NULL)
		return -ENOMEM;
	err = dect_fill_cluster(skb, cl, DECT_NEW_CLUSTER, pid,
			        nlh->nlmsg_seq, NLMSG_DONE);
	if (err < 0)
		goto err1;
	return nlmsg_unicast(nlsk, skb, pid);

err1:
	kfree_skb(skb);
	return err;
}

/*
 * Cell
 */

static u32 dect_cell_alloc_index(void)
{
	static u32 index;

	for (;;) {
		if (++index == 0)
			index = 1;
		if (!dect_cell_get_by_index(index))
			return index;
	}
}

static int dect_fill_cell(struct sk_buff *skb,
			  const struct dect_cell *cell,
			  u16 type, u32 pid, u32 seq, u16 flags)
{
	const struct dect_transceiver *trx;
	struct nlmsghdr *nlh;
	struct dectmsg *dm;
	struct nlattr *nest;

	nlh = nlmsg_put(skb, pid, seq, type, sizeof(*dm), flags);
	if (nlh == NULL)
		return -EMSGSIZE;
	dm = nlmsg_data(nlh);
	dm->dm_index = cell->index;

	NLA_PUT_STRING(skb, DECTA_CELL_NAME, cell->name);
	if (cell->flags != 0)
		NLA_PUT_U32(skb, DECTA_CELL_FLAGS, cell->flags);
	if (cell->trg.trxmask != 0) {
		nest = nla_nest_start(skb, DECTA_CELL_TRANSCEIVERS);
		if (nest == NULL)
			goto nla_put_failure;
		dect_foreach_transceiver(trx, &cell->trg)
			NLA_PUT_STRING(skb, DECTA_LIST_ELEM, trx->name);
		nla_nest_end(skb, nest);
	}
	if (cell->handle.clh != NULL)
		NLA_PUT_U8(skb, DECTA_CELL_CLUSTER, cell->handle.clh->index);

	return nlmsg_end(skb, nlh);

nla_put_failure:
	nlmsg_cancel(skb, nlh);
	return -EMSGSIZE;
}

static int dect_dump_cell(struct sk_buff *skb,
			  struct netlink_callback *cb)
{
	const struct dect_cell *cell;
	unsigned int idx, s_idx;

	s_idx = cb->args[0];
	idx = 0;
	list_for_each_entry(cell, &dect_cell_list, list) {
		if (idx < s_idx)
			goto cont;
		if (dect_fill_cell(skb, cell, DECT_NEW_CELL,
				   NETLINK_CB(cb->skb).pid,
				   cb->nlh->nlmsg_seq, NLM_F_MULTI) <= 0)
			break;
cont:
		idx++;
	}
	cb->args[0] = idx;

	return skb->len;
}

static void dect_notify_cell(u16 event, const struct dect_cell *cell,
			     const struct nlmsghdr *nlh, u32 pid)
{
	struct sk_buff *skb;
	bool report = nlh ? nlmsg_report(nlh) : 0;
	u32 seq = nlh ? nlh->nlmsg_seq : 0;
	int err = -ENOBUFS;

	skb = nlmsg_new(NLMSG_GOODSIZE, GFP_KERNEL);
	if (skb == NULL)
		goto err;

	err = dect_fill_cell(skb, cell, event, pid, seq, NLMSG_DONE);
	if (err < 0) {
		WARN_ON(err == -EMSGSIZE);
		kfree_skb(skb);
		goto err;
	}
	nlmsg_notify(nlsk, skb, pid, DECTNLGRP_CELL, report, GFP_KERNEL);
err:
	if (err < 0)
		netlink_set_err(nlsk, pid, DECTNLGRP_CELL, err);
}

static const struct nla_policy dect_cell_policy[DECTA_CELL_MAX + 1] = {
	[DECTA_CELL_NAME]		= { .type = NLA_STRING, .len = DECTNAMSIZ },
	[DECTA_CELL_FLAGS]		= { .type = NLA_U32 },
	[DECTA_CELL_CLUSTER]		= { .type = NLA_U8 },
};

static int dect_new_cell(const struct sk_buff *skb,
			 const struct nlmsghdr *nlh,
			 const struct nlattr *tb[DECTA_CELL_MAX + 1])
{
	struct dect_cell *cell;
	struct dectmsg *dm;
	u32 flags = 0;
	u8 cli = 0;
	int err;

	dm = nlmsg_data(nlh);
	if (dm->dm_index != 0)
		cell = dect_cell_get_by_index(dm->dm_index);
	else if (tb[DECTA_CELL_NAME] != NULL)
		cell = dect_cell_get_by_name(tb[DECTA_CELL_NAME]);
	else
		return -EINVAL;

	if (tb[DECTA_CELL_FLAGS] != NULL) {
		flags = nla_get_u32(tb[DECTA_CELL_FLAGS]);
		if (flags & ~(DECT_CELL_CCP | DECT_CELL_SLAVE))
			return -EINVAL;
	}

	if (tb[DECTA_CELL_CLUSTER] != NULL)
		cli = nla_get_u8(tb[DECTA_CELL_CLUSTER]);

	if (cell != NULL) {
		if (nlh->nlmsg_flags & NLM_F_EXCL)
			return -EEXIST;

		if (tb[DECTA_CELL_CLUSTER] != NULL) {
			if (cell->handle.clh != NULL)
				return -EBUSY;
			if (cli != 0)
				return dect_cell_bind(cell, cli);
		}
		return 0;
	}

	if (!(nlh->nlmsg_flags & NLM_F_CREATE))
		return -ENOENT;

	cell = kzalloc(sizeof(*cell), GFP_KERNEL);
	if (cell == NULL)
		return -ENOMEM;
	cell->index = dect_cell_alloc_index();
	nla_strlcpy(cell->name, tb[DECTA_CELL_NAME], sizeof(cell->name));
	cell->flags = flags;
	dect_cell_init(cell);

	if (cli != 0) {
		err = dect_cell_bind(cell, cli);
		if (err < 0)
			goto err;
	}

	list_add_tail(&cell->list, &dect_cell_list);
	dect_notify_cell(DECT_NEW_CELL, cell, nlh, NETLINK_CB(skb).pid);
	return 0;

err:
	kfree(cell);
	return err;
}

static int dect_del_cell(const struct sk_buff *skb,
			 const struct nlmsghdr *nlh,
			 const struct nlattr *tb[DECTA_CELL_MAX + 1])
{
	struct dect_cell *cell = NULL;
	struct dectmsg *dm;

	dm = nlmsg_data(nlh);
	if (dm->dm_index != 0)
		cell = dect_cell_get_by_index(dm->dm_index);
	else if (tb[DECTA_CELL_NAME] != NULL)
		cell = dect_cell_get_by_name(tb[DECTA_CELL_NAME]);
	if (cell == NULL)
		return -ENODEV;

	cell = dect_cell_get_by_name(tb[DECTA_CELL_NAME]);
	if (cell == NULL)
		return -ENOENT;

	dect_cell_shutdown(cell);
	list_del(&cell->list);
	dect_notify_cell(DECT_DEL_CELL, cell, nlh, NETLINK_CB(skb).pid);
	kfree(cell);
	return 0;
}

static int dect_get_cell(const struct sk_buff *in_skb,
			 const struct nlmsghdr *nlh,
			 const struct nlattr *tb[DECTA_CELL_MAX + 1])
{
	u32 pid = NETLINK_CB(in_skb).pid;
	const struct dect_cell *cell = NULL;
	struct dectmsg *dm;
	struct sk_buff *skb;
	int err;

	dm = nlmsg_data(nlh);
	if (dm->dm_index != 0)
		cell = dect_cell_get_by_index(dm->dm_index);
	else if (tb[DECTA_CELL_NAME] != NULL)
		cell = dect_cell_get_by_name(tb[DECTA_CELL_NAME]);
	if (cell == NULL)
		return -ENODEV;

	skb = alloc_skb(NLMSG_GOODSIZE, GFP_KERNEL);
	if (skb == NULL)
		return -ENOMEM;
	err = dect_fill_cell(skb, cell, DECT_NEW_CELL, pid, nlh->nlmsg_seq,
			     NLMSG_DONE);
	if (err < 0)
		goto err1;
	return nlmsg_unicast(nlsk, skb, pid);

err1:
	kfree_skb(skb);
	return err;
}

/*
 * Transceiver
 */

static int dect_fill_slot(struct sk_buff *skb,
			  const struct dect_transceiver *trx, u8 slot)
{
	const struct dect_transceiver_slot *ts = &trx->slots[slot];

	NLA_PUT_U8(skb, DECTA_SLOT_NUM, slot);
	NLA_PUT_U8(skb, DECTA_SLOT_STATE, ts->state);
	NLA_PUT_U32(skb, DECTA_SLOT_FLAGS, ts->flags);
	NLA_PUT_U8(skb, DECTA_SLOT_CARRIER, ts->chd.carrier);
	NLA_PUT_U32(skb, DECTA_SLOT_FREQUENCY, trx->band->frequency[ts->chd.carrier]);
	if (ts->state == DECT_SLOT_RX) {
		NLA_PUT_U32(skb, DECTA_SLOT_PHASEOFF, ts->phaseoff);
		NLA_PUT_U8(skb, DECTA_SLOT_RSSI,
			   ts->rssi >> DECT_RSSI_AVG_SCALE);
	}
	NLA_PUT_U32(skb, DECTA_SLOT_RX_BYTES, ts->rx_bytes);
	NLA_PUT_U32(skb, DECTA_SLOT_RX_PACKETS, ts->rx_packets);
	NLA_PUT_U32(skb, DECTA_SLOT_RX_A_CRC_ERRORS, ts->rx_a_crc_errors);
	NLA_PUT_U32(skb, DECTA_SLOT_RX_X_CRC_ERRORS, ts->rx_x_crc_errors);
	NLA_PUT_U32(skb, DECTA_SLOT_TX_BYTES, ts->tx_bytes);
	NLA_PUT_U32(skb, DECTA_SLOT_TX_PACKETS, ts->tx_packets);
	return 0;

nla_put_failure:
	return -1;
}

static int dect_fill_transceiver(struct sk_buff *skb,
				 const struct dect_transceiver *trx,
				 u16 type, u32 pid, u32 seq, u16 flags)
{
	const struct dect_transceiver_stats *stats = &trx->stats;
	struct nlattr *nest, *chan;
	struct nlmsghdr *nlh;
	struct dectmsg *dm;
	u8 slot;

	nlh = nlmsg_put(skb, pid, seq, type, sizeof(*dm), flags);
	if (nlh == NULL)
		return -EMSGSIZE;

	dm = nlmsg_data(nlh);

	NLA_PUT_STRING(skb, DECTA_TRANSCEIVER_NAME, trx->name);
	NLA_PUT_STRING(skb, DECTA_TRANSCEIVER_TYPE, trx->ops->name);
	if (trx->cell != NULL)
		NLA_PUT_U8(skb, DECTA_TRANSCEIVER_LINK, trx->cell->index);

	nest = nla_nest_start(skb, DECTA_TRANSCEIVER_STATS);
	if (nest == NULL)
		goto nla_put_failure;
	NLA_PUT_U32(skb, DECTA_TRANSCEIVER_STATS_EVENT_BUSY, stats->event_busy);
	NLA_PUT_U32(skb, DECTA_TRANSCEIVER_STATS_EVENT_LATE, stats->event_late);
	nla_nest_end(skb, nest);

	NLA_PUT_U8(skb, DECTA_TRANSCEIVER_BAND, trx->band->band);

	nest = nla_nest_start(skb, DECTA_TRANSCEIVER_SLOTS);
	if (nest == NULL)
		goto nla_put_failure;
	for (slot = 0; slot < DECT_FRAME_SIZE; slot++) {
		if (!dect_slot_available(trx, slot))
			continue;

		chan = nla_nest_start(skb, DECTA_LIST_ELEM);
		if (chan == NULL)
			goto nla_put_failure;
		if (dect_fill_slot(skb, trx, slot) < 0)
			goto nla_put_failure;
		nla_nest_end(skb, chan);
	}
	nla_nest_end(skb, nest);

	return nlmsg_end(skb, nlh);

nla_put_failure:
	nlmsg_cancel(skb, nlh);
	return -EMSGSIZE;
}

static const struct nla_policy dect_transceiver_policy[DECTA_TRANSCEIVER_MAX + 1] = {
	[DECTA_TRANSCEIVER_NAME]	= { .type = NLA_STRING, .len = DECTNAMSIZ },
	[DECTA_TRANSCEIVER_LINK]	= { .type = NLA_U8 },
};

static int dect_new_transceiver(const struct sk_buff *in_skb,
				const struct nlmsghdr *nlh,
				const struct nlattr *tb[DECTA_TRANSCEIVER_MAX + 1])
{
	struct dect_transceiver *trx;
	struct dect_cell *cell;
	struct dectmsg *dm;
	int index;

	dm = nlmsg_data(nlh);

	if (tb[DECTA_TRANSCEIVER_NAME] == NULL)
		return -EINVAL;

	trx = dect_transceiver_get_by_name(tb[DECTA_TRANSCEIVER_NAME]);
	if (trx == NULL) {
		if (nlh->nlmsg_flags & NLM_F_CREATE)
			return -EOPNOTSUPP;
		return -ENOENT;
	}
	if (nlh->nlmsg_flags & NLM_F_EXCL)
		return -EEXIST;

	if (tb[DECTA_TRANSCEIVER_LINK] != NULL) {
		index = nla_get_u8(tb[DECTA_TRANSCEIVER_LINK]);
		if (index == -1)
			dect_cell_detach_transceiver(trx->cell, trx);
		else {
			cell = dect_cell_get_by_index(index);
			if (cell == NULL)
				return -ENOENT;
			return dect_cell_attach_transceiver(cell, trx);
		}
	}
	return 0;
}

static int dect_get_transceiver(const struct sk_buff *in_skb,
				const struct nlmsghdr *nlh,
				const struct nlattr *tb[DECTA_TRANSCEIVER_MAX + 1])
{
	u32 pid = NETLINK_CB(in_skb).pid;
	const struct dect_transceiver *trx;
	struct sk_buff *skb;
	int err;

	if (tb[DECTA_TRANSCEIVER_NAME] == NULL)
		return -EINVAL;

	trx = dect_transceiver_get_by_name(tb[DECTA_TRANSCEIVER_NAME]);
	if (trx == NULL)
		return -ENOENT;

	skb = alloc_skb(NLMSG_GOODSIZE, GFP_KERNEL);
	if (skb == NULL)
		return -ENOMEM;
	err = dect_fill_transceiver(skb, trx, DECT_NEW_TRANSCEIVER, pid,
				    nlh->nlmsg_seq, NLMSG_DONE);
	if (err < 0)
		goto err1;
	return nlmsg_unicast(nlsk, skb, pid);

err1:
	kfree_skb(skb);
	return err;
}

static int dect_dump_transceiver(struct sk_buff *skb,
				 struct netlink_callback *cb)
{
	const struct dect_transceiver *trx;
	unsigned int idx, s_idx;

	s_idx = cb->args[0];
	idx = 0;
	list_for_each_entry(trx, &dect_transceiver_list, list) {
		if (idx < s_idx)
			goto cont;
		if (dect_fill_transceiver(skb, trx, DECT_NEW_TRANSCEIVER,
					  NETLINK_CB(cb->skb).pid,
					  cb->nlh->nlmsg_seq, NLM_F_MULTI) <= 0)
			break;
cont:
		idx++;
	}
	cb->args[0] = idx;

	return skb->len;
}

static void dect_notify_transceiver(u16 event, const struct dect_transceiver *trx,
				    const struct nlmsghdr *nlh, u32 pid)
{
	struct sk_buff *skb;
	bool report = nlh ? nlmsg_report(nlh) : 0;
	u32 seq = nlh ? nlh->nlmsg_seq : 0;
	int err = -ENOBUFS;

	skb = nlmsg_new(NLMSG_GOODSIZE, GFP_KERNEL);
	if (skb == NULL)
		goto err;

	err = dect_fill_transceiver(skb, trx, event, pid, seq, NLMSG_DONE);
	if (err < 0) {
		WARN_ON(err == -EMSGSIZE);
		kfree_skb(skb);
		goto err;
	}
	nlmsg_notify(nlsk, skb, pid, DECTNLGRP_TRANSCEIVER, report, GFP_KERNEL);
err:
	if (err < 0)
		netlink_set_err(nlsk, pid, DECTNLGRP_TRANSCEIVER, err);
}

static int dect_transceiver_notify(struct notifier_block *this,
				   unsigned long event, void *ptr)
{
	struct dect_transceiver *trx = ptr;
	struct dect_cell *cell = trx->cell;

	switch (event) {
	case DECT_TRANSCEIVER_REGISTER:
		dect_notify_transceiver(DECT_NEW_TRANSCEIVER, trx, NULL, 0);
		break;
	case DECT_TRANSCEIVER_UNREGISTER:
		if (cell != NULL) {
			dect_cell_detach_transceiver(cell, trx);
			dect_notify_cell(DECT_NEW_CELL, cell, NULL, 0);
		}
		dect_notify_transceiver(DECT_DEL_TRANSCEIVER, trx, NULL, 0);
		break;
	}
	return 0;
};

static struct notifier_block dect_netlink_notifier __read_mostly = {
	.notifier_call	= dect_transceiver_notify,
};

static const struct dect_link {
	int (*doit)(const struct sk_buff *, const struct nlmsghdr *,
		    const struct nlattr *[]);
	int (*dump)(struct sk_buff *, struct netlink_callback *);
	int (*done)(struct netlink_callback *);
	const struct nla_policy *policy;
	unsigned int maxtype;
} dect_dispatch[DECT_NR_MSGTYPES] = {
	[DECT_NEW_TRANSCEIVER - DECT_MSG_BASE] = {
		.policy		= dect_transceiver_policy,
		.maxtype	= DECTA_TRANSCEIVER_MAX,
		.doit		= dect_new_transceiver,
	},
	[DECT_GET_TRANSCEIVER - DECT_MSG_BASE] = {
		.policy		= dect_transceiver_policy,
		.maxtype	= DECTA_TRANSCEIVER_MAX,
		.doit		= dect_get_transceiver,
		.dump		= dect_dump_transceiver,
	},
	[DECT_NEW_CELL - DECT_MSG_BASE] = {
		.policy		= dect_cell_policy,
		.maxtype	= DECTA_CELL_MAX,
		.doit		= dect_new_cell,
	},
	[DECT_DEL_CELL - DECT_MSG_BASE] = {
		.policy		= dect_cell_policy,
		.maxtype	= DECTA_CELL_MAX,
		.doit		= dect_del_cell,
	},
	[DECT_GET_CELL - DECT_MSG_BASE] = {
		.policy		= dect_cell_policy,
		.maxtype	= DECTA_CELL_MAX,
		.doit		= dect_get_cell,
		.dump		= dect_dump_cell,
	},
	[DECT_NEW_CLUSTER - DECT_MSG_BASE] = {
		.policy		= dect_cluster_policy,
		.maxtype	= DECTA_CLUSTER_MAX,
		.doit		= dect_new_cluster,
	},
	[DECT_DEL_CLUSTER - DECT_MSG_BASE] = {
		.policy		= dect_cluster_policy,
		.maxtype	= DECTA_CLUSTER_MAX,
		.doit		= dect_del_cluster,
	},
	[DECT_GET_CLUSTER - DECT_MSG_BASE] = {
		.policy		= dect_cluster_policy,
		.maxtype	= DECTA_CLUSTER_MAX,
		.doit		= dect_get_cluster,
		.dump		= dect_dump_cluster,
	},
	[DECT_LLME_MSG - DECT_MSG_BASE] = {
		.policy		= dect_llme_policy,
		.maxtype	= DECTA_LLME_MAX,
		.doit		= dect_llme_msg,
	},
};

static int dect_netlink_rcv_msg(struct sk_buff *skb, struct nlmsghdr *nlh)
{
	const struct dect_link *link;
	u16 type;
	int err;

	type = nlh->nlmsg_type;
	if (type > DECT_MSG_MAX)
		return -EINVAL;

	type -= DECT_MSG_BASE;
	link = &dect_dispatch[type];

	/* dump and get requests don't require privileges */
	if (link->dump == NULL && security_netlink_recv(skb, CAP_NET_ADMIN))
		return -EPERM;

	if (nlh->nlmsg_flags & NLM_F_DUMP) {
		if (link->dump == NULL)
			return -EOPNOTSUPP;
		return netlink_dump_start(nlsk, skb, nlh, link->dump,
					  link->done);
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

int __init dect_netlink_module_init(void)
{
	struct sock *sk;

	sk = netlink_kernel_create(&init_net, NETLINK_DECT, DECTNLGRP_MAX,
				   dect_netlink_rcv, NULL, THIS_MODULE);
	if (sk == NULL)
		return -ENOMEM;
	nlsk = sk;

	dect_register_notifier(&dect_netlink_notifier);
	return 0;
}

void dect_netlink_module_exit(void)
{
	dect_unregister_notifier(&dect_netlink_notifier);
	netlink_kernel_release(nlsk);
}

MODULE_ALIAS_NET_PF_PROTO(PF_NETLINK, NETLINK_DECT);
