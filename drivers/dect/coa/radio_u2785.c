/*
 * radio_u2785 - ATMEL U2785 RF IC radio operations
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * Copyright (c) 2009 Patrick McHardy <kaber@trash.net>
 */

#define DEBUG
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/dect.h>
#include <net/dect/dect.h>
#include <net/dect/transceiver.h>

#include "com_on_air.h"

#define u2785_debug(dev, fmt, args...) \
	dev_dbg(dev->dev, "u2785: " fmt, ## args)

/* Intermediate frequencies */
#define RADIO_U2785_FREQ_IF1	110592	/* kHz */
#define RADIO_U2785_FREQ_IF2	112320	/* kHz */

/*
 *  RC (Reference Divider)
 */
#define RADIO_U2785_RC_SHIFT	22
#define RADIO_U2785_RC_12	(0x1 << RADIO_U2785_RC_SHIFT)
#define RADIO_U2785_RC_16	(0x2 << RADIO_U2785_RC_SHIFT)
#define RADIO_U2785_RC_24	(0x3 << RADIO_U2785_RC_SHIFT)

/*
 * SC (Swallow Counter) 0-31
 */
#define RADIO_U2785_SC_SHIFT	17
#define RADIO_U2785_SC_MAX	31
#define RADIO_U2785_SC_MASK	(0x1F << RADIO_U2785_SC_SHIFT)

/*
 *  MC (Main Divider)
 */
#define RADIO_U2785_MC_SHIFT	15
#define RADIO_U2785_MC_MIN	31
#define RADIO_U2785_MC_MAX	34
#define RADIO_U2785_MC_31	(0x0 << RADIO_U2785_MC_SHIFT)
#define RADIO_U2785_MC_32	(0x1 << RADIO_U2785_MC_SHIFT)
#define RADIO_U2785_MC_33	(0x2 << RADIO_U2785_MC_SHIFT)
#define RADIO_U2785_MC_34	(0x3 << RADIO_U2785_MC_SHIFT)

/*
 *  PS (Phase Settings)
 */

/* Phase of GF_DATA */
#define RADIO_U2785_PS_GF	(0x1 << 14)
/* Phase of MCC Internal Connection */
#define RADIO_U2785_PS_MCC	(0x1 << 13)
/* Phase of Charge Pump */
#define RADIO_U2785_PS_CP	(0x1 << 12)

/*
 * Current-Saving Power-up/down Settings
 */

/* Gaussian Filter */
#define RADIO_U2785_GF		(0x1 << 11)
/* Modulation Compensation Circuit */
#define RADIO_U2785_MCC		(0x1 << 10)
/* Frequency Doubler */
#define RADIO_U2785_FD		(0x1 << 8)
/* OP1 + OP2 (Op Amps) */
#define RADIO_U2785_OP		(0x1 << 7)

/*
 *  Current Gain Settings (in percent)
 */
#define RADIO_U2785_CGS_60	0x0
#define RADIO_U2785_CGS_70	0x1
#define RADIO_U2785_CGS_80	0x2
#define RADIO_U2785_CGS_90	0x3
#define RADIO_U2785_CGS_100	0x4
#define RADIO_U2785_CGS_110	0x5
#define RADIO_U2785_CGS_120	0x6
#define RADIO_U2785_CGS_130	0x7

/* GFCS (Gaussian-Filter Current Settings) */
#define RADIO_U2785_GFCS_SHIFT	7
/* CPCS (Charge-Pump Current Settings) */
#define RADIO_U2785_CPCS_SHIFT	1
/* MCCS (Modulation-Compensation Current Settings) */
#define RADIO_U2785_MCCS_SHIFT	4

/*
 * Pretune DAC Voltage
 */
#define RADIO_U2785_DAC_SHIFT	4
#define RADIO_U2785_DAC_300mV	(0x0 << RADIO_U2785_DAC_SHIFT)
#define RADIO_U2785_DAC_600mV	(0x1 << RADIO_U2785_DAC_SHIFT)
#define RADIO_U2785_DAC_900mV	(0x2 << RADIO_U2785_DAC_SHIFT)
#define RADIO_U2785_DAC_1200mV	(0x3 << RADIO_U2785_DAC_SHIFT)
#define RADIO_U2785_DAC_1400mV	(0x4 << RADIO_U2785_DAC_SHIFT)
#define RADIO_U2785_DAC_1700mV	(0x5 << RADIO_U2785_DAC_SHIFT)
#define RADIO_U2785_DAC_2000mV	(0x6 << RADIO_U2785_DAC_SHIFT)
#define RADIO_U2785_DAC_2300mV	(0x7 << RADIO_U2785_DAC_SHIFT)

/*
 * Address bit
 */
#define RADIO_U2785_ADDRESS_BIT	0x1

static void u2785_write_config(const struct coa_device *dev, u16 offset,
			       u32 init1, u32 init2)
{
	u8 init[5] = {
		/* first word: 24 bits */
		[0]	= init1 >> 16,
		[1]	= init1 >> 8,
		[2]	= init1 | RADIO_U2785_ADDRESS_BIT,
		/* second word: 9 bits */
		[3]	= init2 >> 1,
		[4]	= 0,
	};

	sc1442x_rfdesc_write(dev, offset, init, sizeof(init));
}

static void u2785_rx_init(const struct coa_device *dev, u16 offset)
{
	u32 init1 = 0, init2 = 0;

	init1 |= RADIO_U2785_RC_12;
	init1 |= RADIO_U2785_MC_32;
	init1 |= 10 << RADIO_U2785_SC_SHIFT;

	init1 |= RADIO_U2785_CGS_100 << RADIO_U2785_CPCS_SHIFT;

	init2 |= RADIO_U2785_FD;
	init2 |= RADIO_U2785_CGS_100 << RADIO_U2785_MCCS_SHIFT;

	u2785_write_config(dev, offset, init1, init2);
}

static void u2785_tx_init(const struct coa_device *dev, u16 offset)
{
	u32 init1 = 0, init2 = 0;

	init1 |= RADIO_U2785_RC_12;
	init1 |= RADIO_U2785_MC_34;
	init1 |= 7 << RADIO_U2785_SC_SHIFT;

	init1 |= RADIO_U2785_GF;
	init1 |= RADIO_U2785_MCC;
	init1 |= RADIO_U2785_CGS_120 << RADIO_U2785_GFCS_SHIFT;
	init1 |= RADIO_U2785_DAC_1400mV;
	init1 |= RADIO_U2785_CGS_60 << RADIO_U2785_CPCS_SHIFT;

	init2 |= RADIO_U2785_FD;
	init2 |= RADIO_U2785_CGS_130 << RADIO_U2785_MCCS_SHIFT;

	u2785_write_config(dev, offset, init1, init2);
}

static void u2785_write_carrier(const struct coa_device *dev, u16 offset,
			        u32 init1)
{
	u8 init[3] = {
		/* first word: 24 bits */
		[0]	= init1 >> 16,
		[1]	= init1 >> 8,
		[2]	= init1 | RADIO_U2785_ADDRESS_BIT,
	};

	sc1442x_rfdesc_write(dev, offset, init, sizeof(init));
}

static void u2785_set_carrier(const struct coa_device *dev, u16 offset,
			      enum dect_slot_states mode, u8 carrier)
{
	const struct coa_freq_map_entry *fe = &dev->freq_map.carrier[carrier];
	u32 init1 = 0;

	init1 |= RADIO_U2785_RC_12;

	switch (mode) {
	case DECT_SLOT_SCANNING:
	case DECT_SLOT_RX:
		init1 |= (fe->rx.divisor - RADIO_U2785_MC_MIN) <<
			 RADIO_U2785_MC_SHIFT;
		init1 |= fe->rx.swcnt << RADIO_U2785_SC_SHIFT;

		init1 |= RADIO_U2785_CGS_100 << RADIO_U2785_CPCS_SHIFT;
		break;
	case DECT_SLOT_TX:
		init1 |= (fe->tx.divisor - RADIO_U2785_MC_MIN) <<
			 RADIO_U2785_MC_SHIFT;
		init1 |= fe->tx.swcnt << RADIO_U2785_SC_SHIFT;

		init1 |= RADIO_U2785_GF;
		init1 |= RADIO_U2785_MCC;
		init1 |= RADIO_U2785_CGS_120 << RADIO_U2785_GFCS_SHIFT;
		init1 |= RADIO_U2785_DAC_1400mV;
		init1 |= RADIO_U2785_CGS_60 << RADIO_U2785_CPCS_SHIFT;
		break;
	default:
		return;
	}

	u2785_write_carrier(dev, offset, init1);
}

static int u2785_map_freq(u32 frequency, u8 *s_mc, u8 *s_sc)
{
	frequency /= DECT_CARRIER_WIDTH;

	*s_mc = frequency / 32;
	if (*s_mc < RADIO_U2785_MC_MIN || *s_mc > RADIO_U2785_MC_MAX)
		return false;
	*s_sc = frequency % 32;
	return true;
}

static u64 u2785_map_band(struct coa_device *dev, const struct dect_band *band)
{
	struct coa_freq_map_entry *fe;
	u64 carriers = 0;
	u32 frequency;
	u8 carrier;

	for (carrier = 0; carrier < band->carriers; carrier++) {
		frequency = band->frequency[carrier];
		fe = &dev->freq_map.carrier[carrier];

		if (!u2785_map_freq(frequency - RADIO_U2785_FREQ_IF1,
				    &fe->rx.divisor, &fe->rx.swcnt))
			continue;
		if (!u2785_map_freq(frequency,
				    &fe->tx.divisor, &fe->tx.swcnt))
			continue;

		carriers |= 1 << carrier;
		u2785_debug(dev, "carrier %u (%u.%03uMHz) => "
			    "rx: div: %u sw: %u tx: div: %u sw: %u\n",
			    carrier, frequency / 1000, frequency % 1000,
			    fe->rx.divisor, fe->rx.swcnt,
			    fe->tx.divisor, fe->tx.swcnt);
	}

	return carriers;
}

const struct coa_radio_ops coa_u2785_radio_ops = {
	.type		= "U2785B",
	.rx_init	= u2785_rx_init,
	.tx_init	= u2785_tx_init,
	.set_carrier	= u2785_set_carrier,
	.map_band	= u2785_map_band,
};
EXPORT_SYMBOL_GPL(coa_u2785_radio_ops);
