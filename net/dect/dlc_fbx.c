/*
 * DECT DLC Layer
 *
 * Copyright (c) 2009 Patrick McHardy <kaber@trash.net>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

static void dect_dlc_fb1_enqueue(struct dect_dlc_fbx *fbx, struct sk_buff *skb)
{
	struct dect_dlc_lux *lux = container_of(fbx, struct dect_dlc_lux, fbx);
	struct sock *sk = &lux->sk;

	skb_queue_tail(&sk->sk_write_queue, skb);
}

static struct sk_buff *dect_dlc_fb1_dequeue(struct dect_dlc_fbx *fbx)
{
	struct dect_dlc_lux *lux = container_of(fbx, struct dect_dlc_lux, fbx);
	struct sock *sk = &lux->sk;
	struct sk_buff *skb, *clone, *head = NULL;
	int need = 40;

	while (need > 0) {
		skb = skb_peek(&sk->sk_write_queue);
		if (skb == NULL)
			goto err;

		if (skb->len <= need) {
			__skb_unlink(skb, &sk->sk_write_queue);
			need -= skb->len;
		} else {
			clone = skb_clone(skb, GFP_ATOMIC);
			if (clone == NULL)
				goto err;
			clone->len = need;
			skb_pull(skb, need);
			skb = clone;
		}
		head = skb_append_frag(head, skb);
	}
	return head;
err:
	return NULL;
}

const struct dect_dlc_fbx_ops dect_dlc_fb1_ops = {
	.enqueue	= dect_dlc_fb1_enqueue,
	.dequeue	= dect_dlc_fb1_dequeue,
};
