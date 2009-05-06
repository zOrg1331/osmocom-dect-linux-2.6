/*
 * com_on_air - basic driver for the Dosch and Amand "com on air" cards
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * authors:
 * (C) 2008  Andreas Schuler <krater at badterrorist dot com>
 * (C) 2008  Matthias Wenzel <dect at mazzoo dot de>
 * (C) 2009  Patrick McHardy <kaber@trash.net>
 *
 */

#ifndef COM_ON_AIR_H
#define COM_ON_AIR_H

#include <linux/types.h>

struct coa_freq_map_entry {
	struct {
		u8	divisor;
		u8	swcnt;
	} rx, tx;
};

struct coa_freq_map {
	struct coa_freq_map_entry	carrier[DECT_CARRIER_NUM];
};

struct coa_device;
struct coa_radio_ops {
	void		(*rx_init)(const struct coa_device *dev, u16 offset);
	void		(*tx_init)(const struct coa_device *dev, u16 offset);
	void		(*set_carrier)(const struct coa_device *dev, u16 offset,
				       enum dect_slot_states mode, u8 carrier);
	u64		(*map_band)(struct coa_device *dev,
				    const struct dect_band *band);
	const char	*type;
};

extern const struct coa_radio_ops coa_u2785_radio_ops;
extern const struct coa_radio_ops coa_lmx3161_radio_ops;

enum coa_device_types {
	COA_TYPE_PCI,
	COA_TYPE_PCMCIA,
};

struct coa_device {
	const struct device		*dev;
	unsigned int			irq;

	enum coa_device_types		type;

	const struct coa_radio_ops	*radio_ops;
	struct coa_freq_map		freq_map;

	uint				config_base;
	u8 __iomem			*sc14421_base;
	u16				cfg_reg;
	u16				irq_reg;
	u16				code_base;
	u16				data_base;
	u16				data_mask;

	u8				ctrl;
};

extern irqreturn_t sc14421_interrupt(int irq, void *dev_id);
extern const struct dect_transceiver_ops sc14421_transceiver_ops;

extern int sc14421_init_device(struct coa_device *dev);
extern void sc14421_shutdown_device(struct coa_device *dev);

extern void sc14421_rfdesc_write(const struct coa_device *dev, u16 offset,
				 const u8 *src, u16 length);

#endif
