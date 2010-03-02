#ifndef _DECT_VTRX_H
#define _DECT_VTRX_H

struct dect_vtrx_group {
	struct list_head	list;
	struct device		dev;
	char			name[16];
	struct hrtimer		timer;
	struct list_head	trx_list;
	struct list_head	act_list;
	struct sk_buff_head	txq[DECT_FRAME_SIZE];
	unsigned int		slot;
};

struct dect_vtrx {
	struct list_head	list;
	struct device		dev;
	struct dect_vtrx_group	*group;
	struct dect_transceiver	*trx;
	u64			tx_power;
	unsigned int		pos_x;
	unsigned int		pos_y;
};

extern struct dect_vtrx_group *dect_vtrx_group_init(const char *name);
extern void	dect_vtrx_group_free(struct dect_vtrx_group *group);
extern int	dect_vtrx_group_register_sysfs(struct dect_vtrx_group *group);
extern void	dect_vtrx_group_unregister_sysfs(struct dect_vtrx_group *group);

extern int	dect_vtrx_register_sysfs(struct dect_vtrx *vtrx);
extern void	dect_vtrx_unregister_sysfs(struct dect_vtrx *vtrx);
extern int	dect_vtrx_init(struct dect_vtrx_group *group);
extern void	dect_vtrx_free(struct dect_vtrx *vtrx);

extern int	dect_vtrx_sysfs_init(void);
extern void	dect_vtrx_sysfs_exit(void);

#define DECT_VTRX_POWER_SCALE		10000000000ULL

extern int	dect_mw_to_dbm(u64 mw);

#endif /* _DECT_VTRX_H */
