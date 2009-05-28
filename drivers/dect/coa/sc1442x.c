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

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/dect.h>
#include <net/dect/dect.h>
#include <net/dect/mac_csf.h>
#include <net/dect/transceiver.h>
#include <asm/io.h>

#include "com_on_air.h"
#include "sc1442x_firmware.h"
#include "dip_opcodes.h"

/*
 * The sc1442x contain a 2k data RAM and 512b code RAM. The two primary
 * methods for memory access are direct and indirect access. In indirect
 * mode, the access goes through the DIP and the memory bank needs to be
 * mapped by writting its number to the control register. In direct mode
 * the memory can be accessed directly, the three modes differ only in
 * the address space layout. The choice between direct and indirect mode
 * is made by the device vendor.
 *
 * The address space is layed out as follows:
 *
 * PCI - size 8k:
 *
 * 0x0a00 - 0x11ff:	data memory
 * 0x1a00 - 0x1bff:	code memory
 * 0x1f00 - 0x1fff:	DIP control and status registers
 *
 * PCMCIA - size 1k:
 *
 * 0x0000 - 0x01ff:	256 bytes memory
 * 0x0200 - 0x02ff:	DIP control and status registers
 *
 * Memory of the PCMCIA device is addressed in 16 bit little endian quantities.
 *
 * The first bank of the data memory contains DIP specific control data,
 * the remaining banks are used to store packet and slot configuration data.
 */

#define SC1442X_DIPSTOPPED		0x80
#define SC1442X_PRESCALER_ENABLED	0x40
#define SC1442X_TIMER_INTERRUPT_ENABLED	0x02

/* Memory access modes */
#define SC1442X_LINEAR_MODE		0x01
#define SC1442X_LINEAR_MODE_0		(SC14421_LINEAR_MODE | 0x0)
#define SC1442X_LINEAR_MODE_1		(SC14421_LINEAR_MODE | 0x2)
#define SC1442X_LINEAR_MODE_2		(SC14421_LINEAR_MODE | 0x3)

/* Indirect mode RAM bank select */
#define SC1442X_RAMBANK0		0x00
#define SC1442X_RAMBANK1		0x04
#define SC1442X_RAMBANK2		0x08
#define SC1442X_RAMBANK3		0x0c
#define SC1442X_RAMBANK4		0x10
#define SC1442X_RAMBANK5		0x14
#define SC1442X_RAMBANK6		0x18
#define SC1442X_RAMBANK7		0x1c
#define SC1442X_CODEBANK		0x20
#define SC1442X_BANKSIZE		0x100

/* Interrupts 0-3 */
#define SC1442X_IRQ_SLOT_0_5		0x01
#define SC1442X_IRQ_SLOT_6_11		0x02
#define SC1442X_IRQ_SLOT_12_17		0x04
#define SC1442X_IRQ_SLOT_18_23		0x08
#define SC1442X_IRQ_TIMER		0x10
#define SC1442X_IRQ_MASK		0x0f

/* Interrupt status 1: DIP/CLK100/TIM1/TIM0/SPI/UART/P10/KEYB */
#define SC14424_RESET_INT_PENDING_1	0x1f02

/* DIP_INT and CLK100_INT priority level */
#define SC14424_INT_PRIORITY_1		0x1f06

/* P1 output control */
#define SC14424_P1_SET_OUTPUT_DATA	0x1f21
#define SC14424_P1_RESET_OUTPUT_DATA	0x1f22

/* P1 input/output direction */
#define SC14424_P1_DIR_REG		0x1f23

/*
 * Burst Mode Controller control information
 */

/* Maximum number of unmasked errors in S-field bits 8 to 31 */
#define SC1442X_BC0_S_ERR_SHIFT		4
/* Invert incoming data (RDI) */
#define SC1442X_BC0_INV_RDI		0x08
/* Invert outgoing data (TDO) */
#define SC1442X_BC0_INV_TDO		0x04
/* Disable writing B-field on A-field CRC error */
#define SC1442X_BC0_SENS_A		0x02
/* PP/FP mode */
#define SC1442X_BC0_PP_MODE		0x01

/* Error test mask for S-field bits 15-8 */
#define SC1442X_BC1_MASK_MASK		0xff

/* Sliding error test mask for S-field bits 15-8 */
#define SC1442X_BC2_SLIDE_MASK		0xff

/* DAC output value when BCM is active (for frequency control?) */
#define SC1442X_BC3_DAC_MASK		0x1f

/* Only perform phase jump for correct A-field CRC + SL_EN_ADJ command */
#define SC1442X_BC4_ADP			0x10
/* Window in which S-field is accepted */
#define SC1442X_BC4_WIN_MASK		0x0f

/* Amplitude-trimming of gaussian shape */
#define SC1442X_BC5_VOL_SHIFT		4
/* Disable scrambling */
#define SC1442X_BC5_SC_OFF		0x08
/* PD1 synchronization pattern:
 * 0 = S-field received, 1 = preamble + first 2 bits of synchronization word */
#define SC1442X_BC5_DO_FR		0x04
/* TDO output shape */
#define SC1442X_BC5_TDO_DIGITAL		0x00
#define SC1442X_BC5_TDO_GAUSIAN		0x01
#define SC1442X_BC5_TDO_POWER_DOWN	0x02
#define SC1442X_BC5_TDO_MID_LEVEL	0x03

/* Low 4 bits of multiframe number */
#define SC1442X_BC6_MFR_SHIFT		4
#define SC1442X_BC6_MFR_MASK		0xf0
/* Frame number */
#define SC1442X_BC6_FR_MASK		0x0f

/*
 * Burst Mode Controller status information
 */

/* Peak binary value of ADC (RSSI) */
#define SC1442X_ST0_ADC_MASK		0x3f

/* S-pattern recognized according to BMC configuration */
#define SC1442X_ST1_IN_SYNC		0x80

/* A-field R-CRC correct */
#define SC1442X_ST1_A_CRC		0x40

/* Protected Bn-subfield R-CRC correct */
#define SC1442X_ST1_B_CRC_MASK		0x3c
#define SC1442X_ST1_B1_CRC		0x20
#define SC1442X_ST1_B2_CRC		0x10
#define SC1442X_ST1_B3_CRC		0x08
#define SC1442X_ST1_B4_CRC		0x04

/* B-field X-CRC correct */
#define SC1442X_ST1_X_CRC		0x02

/* Z-field equals X-CRC */
#define SC1442X_ST1_Z_CRC		0x01

/* Phase offset of received S-field: which of the nine internal clock cycles
 * per symbol sampled the incoming data. The frequency deviation can be
 * calculated from the difference of the offsets of two consequitive frames as:
 *
 * K * (T / 9) / 10m = K * 96ns / 10m = K * 9.6ppm
 */
#define SC1442X_ST2_TAP_SHIFT		4
#define SC1442X_ST2_TAP_MASK		0xf0
#define SC1442X_ST2_TAP_SCALE		(DECT_PHASE_OFFSET_SCALE * 96 / 10)

/* Number of unmasked S-field errors according to BMC configuration */
#define SC1442X_ST2_S_ERR_SHIFT		0
#define SC1442X_ST2_S_ERR_MASK		0x0f

/* Phase offset of received S-field: difference of number of symbol periods
 * between nominal 11520 symbols per frame and actual number of symbols. The
 * frequency deviation can be calculated from the difference of two
 * consequitive frames as:
 *
 * N * T / 10m = N * 870ns / 10m = N * 87ppm
 */
#define SC1442X_ST3_PHASE_MASK		0xff
#define SC1442X_ST2_PHASE_SCALE		(DECT_PHASE_OFFSET_SCALE * 87)

/* DC offset of received data to comparator reference input (DAC) */
#define SC1442X_ST4_DC_MASK		0x3f

/*
 * Codec configuration
 */

#define SC1442X_CC_SIZE			6

#define SC1442X_CC0_STANDBY		0xc2
#define SC1442X_CC0_POWERDOWN		0x3d


static const u8 banktable[] = {
	SC1442X_RAMBANK1, 0,
	SC1442X_RAMBANK1, 0,
	SC1442X_RAMBANK2, 0,
	SC1442X_RAMBANK2, 0,
	SC1442X_RAMBANK3, 0,
	SC1442X_RAMBANK3, 0,
	SC1442X_RAMBANK4, 0,
	SC1442X_RAMBANK4, 0,
	SC1442X_RAMBANK5, 0,
	SC1442X_RAMBANK5, 0,
	SC1442X_RAMBANK6, 0,
	SC1442X_RAMBANK6, 0,
};

static const u8 jumptable[] = {
	JP0, 0,
	JP2, 0,
	JP4, 0,
	JP6, 0,
	JP8, 0,
	JP10, 0,
	JP12, 0,
	JP14, 0,
	JP16, 0,
	JP18, 0,
	JP20, 0,
	JP22, 0
};

static const u8 patchtable[] = {
	PP0, 0,
	PP2, 0,
	PP4, 0,
	PP6, 0,
	PP8, 0,
	PP10, 0,
	PP12, 0,
	PP14, 0,
	PP16, 0,
	PP18, 0,
	PP20, 0,
	PP22, 0
};

static const u8 sc1442x_rx_funcs[DECT_PACKET_MAX + 1][DECT_B_MAX + 1] = {
	[DECT_PACKET_P00][DECT_B_NONE]		= RecvP32U,
	[DECT_PACKET_P32][DECT_B_UNPROTECTED]	= RecvP32U,
	[DECT_PACKET_P32][DECT_B_PROTECTED]	= RecvP32P,
};

static const u8 sc1442x_tx_funcs[DECT_PACKET_MAX + 1][DECT_B_MAX + 1] = {
	[DECT_PACKET_P00][DECT_B_NONE]		= TransmitP00,
	[DECT_PACKET_P32][DECT_B_UNPROTECTED]	= TransmitP32U,
	[DECT_PACKET_P32][DECT_B_PROTECTED]	= TransmitP32P,
};

/*
 * Raw IO functions
 */

static void sc1442x_lock_mem(struct coa_device *dev) __acquires(dev->lock)
{
	spin_lock_irq(&dev->lock);
}

static void sc1442x_unlock_mem(struct coa_device *dev) __releases(dev->lock)
{
	mmiowb();
	spin_unlock_irq(&dev->lock);
}

static u8 sc1442x_readb(const struct coa_device *dev, u16 offset)
{
	switch (dev->type) {
	case COA_TYPE_PCI:
		return readb(dev->sc1442x_base + offset);
	case COA_TYPE_PCMCIA:
		return le16_to_cpu(readw(dev->sc1442x_base + 2 * offset));
	default:
		BUG();
	}
}

static u16 sc1442x_readw(const struct coa_device *dev, u16 offset)
{
	u32 tmp;

	switch (dev->type) {
	case COA_TYPE_PCI:
		return le16_to_cpu(readw(dev->sc1442x_base + offset));
	case COA_TYPE_PCMCIA:
		tmp = le32_to_cpu(readl(dev->sc1442x_base + 2 * offset));
		return (tmp >> 8) | (tmp & 0xff);
	default:
		BUG();
	}
}

static void sc1442x_writeb(const struct coa_device *dev, u16 offset, u8 value)
{
	switch (dev->type) {
	case COA_TYPE_PCI:
		writeb(value, dev->sc1442x_base + offset);
		break;
	case COA_TYPE_PCMCIA:
		writew(cpu_to_le16(value), dev->sc1442x_base + 2 * offset);
		break;
	}
}

static void sc1442x_writew(const struct coa_device *dev, u16 offset, u16 value)
{
	u32 tmp;

	switch (dev->type) {
	case COA_TYPE_PCI:
		writew(cpu_to_le16(value), dev->sc1442x_base + offset);
		break;
	case COA_TYPE_PCMCIA:
		tmp = ((value & 0xff00) << 8) | (value & 0xff);
		writel(cpu_to_le32(tmp), dev->sc1442x_base + 2 * offset);
		break;
	}
}

static void sc1442x_stop_dip(struct coa_device *dev)
{
	/* Prevent the interrupt handler from restarting the DIP */
	dev->ctrl = SC1442X_DIPSTOPPED;

	/* Stop the DIP and wait for interrupt handler to complete */
	sc1442x_writeb(dev, dev->cfg_reg, SC1442X_DIPSTOPPED);
	synchronize_irq(dev->irq);
}

static void sc1442x_start_dip(struct coa_device *dev)
{
	dev->ctrl = 0;
	sc1442x_writeb(dev, dev->cfg_reg, 0x00);
}

static void sc1442x_switch_to_bank(const struct coa_device *dev, u8 bank)
{
	if (dev->type != COA_TYPE_PCMCIA)
		return;
	sc1442x_writeb(dev, dev->cfg_reg, bank | dev->ctrl);
	/* need to wait for 4 IO cycles */
	inb_p(dev->config_base);
	inb_p(dev->config_base);
	inb_p(dev->config_base);
	inb_p(dev->config_base);
}

static void sc1442x_toggle_led(struct coa_device *dev)
{
	if (dev->type != COA_TYPE_PCI)
		return;

	if ((dev->led & 0xf) > 0x7)
		sc1442x_writeb(dev, SC14424_P1_SET_OUTPUT_DATA, 0x40);
	else
		sc1442x_writeb(dev, SC14424_P1_RESET_OUTPUT_DATA, 0x40);
	dev->led++;
}

/*
 * Code memory IO functions
 */
static void sc1442x_write_cmd(const struct coa_device *dev, u16 label,
			      u8 opcode, u8 operand)
{
	sc1442x_writeb(dev, dev->code_base + 2 * label + 0, opcode);
	sc1442x_writeb(dev, dev->code_base + 2 * label + 1, operand);
}

static void sc1442x_to_cmem(const struct coa_device *dev,
			    const u8 *src, u16 length)
{
	u16 i;

	for (i = 0; i < length; i++)
		sc1442x_writeb(dev, dev->code_base + i, src[i]);
}

/*
 * Data memory IO functions
 */
static inline u8 sc1442x_dreadb(const struct coa_device *dev, u16 offset)
{
	return sc1442x_readb(dev, dev->data_base + (offset & dev->data_mask));
}

static inline u16 sc1442x_dreadw(const struct coa_device *dev, u16 offset)
{
	return sc1442x_readw(dev, dev->data_base + (offset & dev->data_mask));
}

static inline void sc1442x_dwriteb(const struct coa_device *dev,
				  u16 offset, u8 value)
{
	sc1442x_writeb(dev, dev->data_base + (offset & dev->data_mask), value);
}

static inline void sc1442x_dwritew(const struct coa_device *dev,
				   u16 offset, u16 value)
{
	sc1442x_writew(dev, dev->data_base + (offset & dev->data_mask), value);
}

static void sc1442x_to_dmem(const struct coa_device *dev, u16 offset,
			    const u8 *src, u16 length)
{
	u16 i = 0;

	for (; length >= 2; length -= 2, i += 2)
		sc1442x_dwritew(dev, offset + i, *(u16 *)&src[i]);
	for (; length >= 1; length -= 1, i += 1)
		sc1442x_dwriteb(dev, offset + i, src[i]);
}

static void sc1442x_from_dmem(const struct coa_device *dev, u8 *dst,
			      u16 offset, u16 length)
{
	u16 i = 0;

	for (; length >= 2; length -= 2, i += 2)
		*(u16 *)&dst[i] = sc1442x_dreadw(dev, offset + i);
	for (; length >= 1; length -= 1, i += 1)
		dst[i] = sc1442x_dreadb(dev, offset + i);
}

static u16 sc1442x_slot_offset(u8 slot)
{
	u16 offset;

	offset = SC1442X_BANKSIZE + slot / 4 * SC1442X_BANKSIZE;
	if (slot & 0x2)
		offset += SC1442X_BANKSIZE / 2;
	return offset;
}

void sc1442x_rfdesc_write(const struct coa_device *dev, u16 offset,
			  const u8 *src, u16 length)
{
	sc1442x_to_dmem(dev, offset + RF_DESC, src, length);
}

/*
 * Transceiver operations
 */

static void sc1442x_disable(const struct dect_transceiver *trx)
{
	sc1442x_stop_dip(dect_transceiver_priv(trx));
}

static void sc1442x_enable(const struct dect_transceiver *trx)
{
	const struct coa_device *dev = dect_transceiver_priv(trx);
	u8 slot;

	/* Restore slot table to a pristine state */
	sc1442x_switch_to_bank(dev, SC1442X_CODEBANK);
	for (slot = 0; slot < DECT_FRAME_SIZE; slot += 2)
		sc1442x_write_cmd(dev, patchtable[slot], WNT, 2);

	if (trx->mode == DECT_TRANSCEIVER_MASTER) {
		sc1442x_write_cmd(dev, RFStart, BR, SlotTable);
		sc1442x_write_cmd(dev, ClockSyncOn, WT, 1);
		sc1442x_write_cmd(dev, ClockSyncOff, WT, 1);
	} else {
		sc1442x_write_cmd(dev, RFStart, BR, SyncInit);
		sc1442x_write_cmd(dev, SyncLoop, BR, Sync);
		sc1442x_write_cmd(dev, ClockSyncOn, P_SC, 0x20);
		sc1442x_write_cmd(dev, ClockSyncOff, P_SC, 0x00);
	}

	sc1442x_start_dip(dect_transceiver_priv(trx));
}

static void sc1442x_confirm(const struct dect_transceiver *trx)
{
	struct coa_device *dev = dect_transceiver_priv(trx);

	/*
	 * This locks the firmware into a cycle where it will receive every
	 * 24th slot. This must happen within the time it takes to transmit
	 * 22 slots after the interrupt to lock to the correct signal.
	 */
	sc1442x_lock_mem(dev);
	sc1442x_switch_to_bank(dev, SC1442X_CODEBANK);
	sc1442x_write_cmd(dev, SyncLoop, BR, SyncLock);
	sc1442x_unlock_mem(dev);
}

static void sc1442x_unlock(const struct dect_transceiver *trx)
{
	struct coa_device *dev = dect_transceiver_priv(trx);

	/* Restore jump into Sync loop */
	sc1442x_lock_mem(dev);
	sc1442x_switch_to_bank(dev, SC1442X_CODEBANK);
	sc1442x_write_cmd(dev, SyncLoop, BR, Sync);
	sc1442x_unlock_mem(dev);
}

static void sc1442x_lock(const struct dect_transceiver *trx, u8 slot)
{
	struct coa_device *dev = dect_transceiver_priv(trx);

	/*
	 * We're receiving the single slot "slot". Adjust the firmware so it
	 * will jump into the correct slottable position on the next receive
	 * event. This will automagically establish the correct slot numbers
	 * and thereby interrupt timing for all slots.
	 */
	sc1442x_lock_mem(dev);
	sc1442x_switch_to_bank(dev, SC1442X_CODEBANK);
	sc1442x_write_cmd(dev, SyncLoop, BR, jumptable[slot]);
	sc1442x_unlock_mem(dev);
}

static void sc1442x_set_mode(const struct dect_transceiver *trx,
			     const struct dect_channel_desc *chd,
			     enum dect_slot_states mode)
{
	struct coa_device *dev = dect_transceiver_priv(trx);
	u8 slot = chd->slot;
	u16 off;

	sc1442x_lock_mem(dev);
	switch (mode) {
	case DECT_SLOT_IDLE:
		sc1442x_switch_to_bank(dev, SC1442X_CODEBANK);
		sc1442x_write_cmd(dev, patchtable[slot], WNT, 2);
		break;
	case DECT_SLOT_SCANNING:
	case DECT_SLOT_RX:
		sc1442x_switch_to_bank(dev, banktable[slot]);
		off = sc1442x_slot_offset(slot);
		dev->radio_ops->rx_init(dev, off);

		sc1442x_switch_to_bank(dev, SC1442X_CODEBANK);
		sc1442x_write_cmd(dev, patchtable[slot], JMP,
				  sc1442x_rx_funcs[chd->pkt][chd->b_fmt]);
		break;
	case DECT_SLOT_TX:
		sc1442x_switch_to_bank(dev, banktable[slot]);
		off = sc1442x_slot_offset(slot);
		dev->radio_ops->tx_init(dev, off);

		sc1442x_switch_to_bank(dev, SC1442X_CODEBANK);
		sc1442x_write_cmd(dev, patchtable[slot], JMP,
				  sc1442x_tx_funcs[chd->pkt][chd->b_fmt]);
		break;
	}
	sc1442x_unlock_mem(dev);
}

static void sc1442x_set_carrier(const struct dect_transceiver *trx,
				u8 slot, u8 carrier)
{
	const struct dect_transceiver_slot *ts = &trx->slots[slot];
	struct coa_device *dev = dect_transceiver_priv(trx);
	u16 off;

	WARN_ON(ts->state == DECT_SLOT_IDLE);

	sc1442x_lock_mem(dev);
	sc1442x_switch_to_bank(dev, banktable[slot]);
	off = sc1442x_slot_offset(slot);
	dev->radio_ops->set_carrier(dev, off, ts->state, carrier);
	sc1442x_unlock_mem(dev);
}

static u64 sc1442x_set_band(const struct dect_transceiver *trx,
			    const struct dect_band *band)
{
	struct coa_device *dev = dect_transceiver_priv(trx);

	return dev->radio_ops->map_band(dev, band);
}

static void sc1442x_tx(const struct dect_transceiver *trx, struct sk_buff *skb)
{
	struct coa_device *dev = dect_transceiver_priv(trx);
	u8 slot = DECT_TRX_CB(skb)->slot;
	u16 off;

	sc1442x_lock_mem(dev);
	sc1442x_switch_to_bank(dev, banktable[slot]);
	off = sc1442x_slot_offset(slot);

	/* Duplicate first byte for transmission during ramp-up */
	sc1442x_dwriteb(dev, off + SD_PREAMBLE_OFF - 1, *skb_mac_header(skb));
	sc1442x_to_dmem(dev, off + SD_PREAMBLE_OFF,
			skb_mac_header(skb), skb->mac_len);
	sc1442x_to_dmem(dev, off + SD_DATA_OFF, skb->data, skb->len);
	sc1442x_dwriteb(dev, off + TX_DESC + TRX_DESC_FN,
		       DECT_TRX_CB(skb)->frame);
	sc1442x_unlock_mem(dev);

	kfree_skb(skb);
}

const struct dect_transceiver_ops sc1442x_transceiver_ops = {
	.name			= "sc1442x",
	.slotmask		= 0x555555,
	.eventrate		= 6,
	.latency		= 6,
	.disable		= sc1442x_disable,
	.enable			= sc1442x_enable,
	.confirm		= sc1442x_confirm,
	.unlock			= sc1442x_unlock,
	.lock			= sc1442x_lock,
	.set_mode		= sc1442x_set_mode,
	.set_carrier		= sc1442x_set_carrier,
	.set_band		= sc1442x_set_band,
	.tx			= sc1442x_tx,
	.destructor		= dect_transceiver_free,
};
EXPORT_SYMBOL_GPL(sc1442x_transceiver_ops);

static u8 sc1442x_clear_interrupt(const struct coa_device *dev)
{
	u8 int1, int2, cnt = 0;

	int1 = sc1442x_readb(dev, dev->cfg_reg);
	/* is the card still plugged? */
	if (int1 == 0xff)
		return 0;

	int2 = int1 & SC1442X_IRQ_MASK;

	/* Clear interrupt status before checking for any remaining events */
	if (int2 && dev->type == COA_TYPE_PCI)
		sc1442x_writeb(dev, SC14424_RESET_INT_PENDING_1, 0x80);

	while (int1) {
		cnt++;
		if (cnt > 254) {
			int2 = 0;
			break;
		}

		int1 = sc1442x_readb(dev, dev->cfg_reg) & SC1442X_IRQ_MASK;
		int2 |= int1;
	}

	return int2 & SC1442X_IRQ_MASK;
}

static void sc1442x_update_phase_offset(struct coa_device *dev,
					struct dect_transceiver_slot *ts,
					u8 framenum)
{
	struct sc1442x_phase_state *ps = &dev->phase_state[ts->chd.slot / 2];
	u16 off = sc1442x_slot_offset(ts->chd.slot);
	s32 phaseoff;
	s8 phase;
	u8 tap;

	/* The phase offset is calculated from the differences of the tap and
	 * phase status of two consequitive frames. The tap field contains
	 * which of the nine internal clock cycles per symbol sampled the
	 * incoming data and measures small scale frequency deviations up to
	 * +-8 * 9.6ppm == +-86.4ppm. The phase field contains the absolute
	 * phase offset in multiples of 87ppm.
	 */
	tap   = sc1442x_dreadb(dev, off + 2) >> SC1442X_ST2_TAP_SHIFT;
	phase = sc1442x_dreadb(dev, off + 3);

	if (dect_next_framenum(ps->framenum) == framenum) {
		phaseoff = (tap - ps->tap) * SC1442X_ST2_TAP_SCALE;
		phaseoff += (phase - ps->phase) * SC1442X_ST2_PHASE_SCALE;

		ts->phaseoff = dect_average_phase_offset(ts->phaseoff, phaseoff);
	}

	ps->framenum = framenum;
	ps->tap      = tap;
	ps->phase    = phase;
}

static void sc1442x_process_slot(struct coa_device *dev,
				 struct dect_transceiver *trx,
				 struct dect_transceiver_event *event,
				 u8 slot)
{
	struct dect_transceiver_slot *ts = &trx->slots[slot];
	struct sk_buff *skb;
	u8 status, framenum, csum, rssi;
	u16 off;

	if (ts->state == DECT_SLOT_IDLE || ts->state == DECT_SLOT_TX)
		return;

	framenum = trx->cell->timer_base[DECT_TIMER_RX].framenum;

	sc1442x_switch_to_bank(dev, banktable[slot]);
	off = sc1442x_slot_offset(slot);

	/*
	 * The SC1442X contains a 6 bit ADC for RSSI measurement, convert to
	 * units used by the stack.
	 */
	status = sc1442x_dreadb(dev, off + SD_RSSI_OFF);
	rssi = (status & SC1442X_ST0_ADC_MASK) * DECT_RSSI_RANGE / 63;

	/* validate and clear checksum */
	status = sc1442x_dreadb(dev, off + SD_CSUM_OFF);
	if (!(status & SC1442X_ST1_IN_SYNC))
		goto out;
	sc1442x_dwriteb(dev, off + SD_CSUM_OFF, 0);

	if (!(status & SC1442X_ST1_A_CRC)) {
		if (ts->chd.pkt == DECT_PACKET_P00)
			goto out;
		csum = 0;
	} else
		csum = DECT_CHECKSUM_A_CRC_OK;

	/* calculate phase offset */
	sc1442x_update_phase_offset(dev, ts, framenum);

	skb = dect_transceiver_alloc_skb(trx, slot);
	if (skb == NULL)
		goto out;
	sc1442x_from_dmem(dev, skb->data, off + SD_DATA_OFF, skb->len);
	DECT_TRX_CB(skb)->csum = csum;
	DECT_TRX_CB(skb)->rssi = rssi;
	__skb_queue_tail(&event->rx_queue, skb);

	ts->rx_bytes += skb->len;
	ts->rx_packets++;
out:
	ts->rssi = dect_average_rssi(ts->rssi, rssi);
	dect_transceiver_record_rssi(event, slot, rssi);

	/* Update frame number for next reception */
	sc1442x_dwriteb(dev, off + RX_DESC + TRX_DESC_FN,
		       dect_next_framenum(framenum));
}

irqreturn_t sc1442x_interrupt(int irq, void *dev_id)
{
	struct dect_transceiver *trx = dev_id;
	struct coa_device *dev = dect_transceiver_priv(trx);
	struct dect_transceiver_event *event;
	u8 slot, i;

	irq = sc1442x_clear_interrupt(dev);
	if (!irq)
		return IRQ_NONE;

	if (unlikely(hweight8(irq) != 1 && net_ratelimit()))
		dev_info(dev->dev, "lost some interrupts\n");

	for (i = 0; i < 4; i++) {
		if (!(irq & (1 << i)))
			continue;

		if (irq & SC1442X_IRQ_SLOT_0_5)
			sc1442x_toggle_led(dev);

		event = dect_transceiver_event(trx, i % 2, i * 6);
		if (event == NULL)
			goto out;

		spin_lock(&dev->lock);
		for (slot = 6 * i; slot < 6 * (i + 1); slot += 2)
			sc1442x_process_slot(dev, trx, event, slot);
		spin_unlock(&dev->lock);

		dect_transceiver_queue_event(trx, event);
	}
out:
	return IRQ_HANDLED;
}
EXPORT_SYMBOL_GPL(sc1442x_interrupt);

static void sc1442x_write_bmc_config(const struct coa_device *dev,
				     u16 off, bool pp, bool tx)
{
	u8 cfg;

	cfg  = 2 << SC1442X_BC0_S_ERR_SHIFT;
	cfg |= SC1442X_BC0_INV_TDO;
	cfg |= SC1442X_BC0_SENS_A;
	if (pp && !tx)
		cfg |= SC1442X_BC0_PP_MODE;
	sc1442x_dwriteb(dev, off + 0, cfg);

	/* S-field error mask */
	sc1442x_dwriteb(dev, off + 1, 0);
	/* S-field sliding window error mask */
	sc1442x_dwriteb(dev, off + 2, 0x3f);

	/* DAC output */
	sc1442x_dwriteb(dev, off + 3, 0);

	cfg  = SC1442X_BC4_ADP;
	cfg |= 0xf;
	cfg |= 0x80;
	sc1442x_dwriteb(dev, off + 4, cfg);

	cfg  = SC1442X_BC5_DO_FR;
	cfg |= tx ? SC1442X_BC5_TDO_DIGITAL : SC1442X_BC5_TDO_POWER_DOWN;
	sc1442x_dwriteb(dev, off + 5, cfg);

	/* Frame number */
	sc1442x_dwriteb(dev, off + 6, 0);
}

static void sc1442x_init_slot(const struct coa_device *dev, u8 slot)
{
	u16 off;

	sc1442x_switch_to_bank(dev, banktable[slot]);
	off = sc1442x_slot_offset(slot);
	sc1442x_write_bmc_config(dev, off + TX_DESC, slot < 12, true);
	sc1442x_write_bmc_config(dev, off + RX_DESC, slot < 12, false);
	dev->radio_ops->rx_init(dev, off);
}

static int sc1442x_check_dram(const struct coa_device *dev)
{
	unsigned int bank, i;
	unsigned int cnt;
	u16 off;
	u8 val;

	for (bank = 0; bank < 8; bank++) {
		sc1442x_switch_to_bank(dev, 4 * bank);

		off = bank * SC1442X_BANKSIZE;
		for (i = 0; i < SC1442X_BANKSIZE - 2; i++)
			sc1442x_dwriteb(dev, off + i, bank + i);
	}

	cnt = 0;
	for (bank = 0; bank < 8; bank++) {
		sc1442x_switch_to_bank(dev, 4 * bank);

		off = bank * SC1442X_BANKSIZE;
		for (i = 0; i < SC1442X_BANKSIZE - 2; i++) {
			val = sc1442x_dreadb(dev, off + i);
			if (val != ((bank + i) & 0xff)) {
				dev_err(dev->dev,
					"memory error bank %.2x offset %.2x: "
					"%.2x != %.2x\n", bank, i,
					val, (bank + i) & 0xff);
				cnt++;
			}
			sc1442x_dwriteb(dev, off + i, 0);
		}
	}

	if (cnt > 0)
		dev_err(dev->dev, "found %u memory r/w errors\n", cnt);
	return cnt ? -1 : 0;
}

int sc1442x_init_device(struct coa_device *dev)
{
	unsigned int i;
	u8 slot;

	spin_lock_init(&dev->lock);
	dev->ctrl = SC1442X_DIPSTOPPED;

	if (sc1442x_check_dram(dev) < 0)
		return -EIO;

	dev_info(dev->dev, "Loading firmware ...\n");
	sc1442x_switch_to_bank(dev, SC1442X_CODEBANK);
	sc1442x_to_cmem(dev, sc1442x_firmware, sizeof(sc1442x_firmware));

	sc1442x_clear_interrupt(dev);

	/* Init DIP */
	sc1442x_switch_to_bank(dev, SC1442X_RAMBANK0);

	/* Disable Codec */
	sc1442x_dwriteb(dev, DIP_CC_INIT, SC1442X_CC0_STANDBY);
	for (i = 1; i < SC1442X_CC_SIZE; i++)
		sc1442x_dwriteb(dev, DIP_CC_INIT + i, 0);

	sc1442x_write_bmc_config(dev, DIP_RF_INIT, false, false);
	for (slot = 0; slot < DECT_FRAME_SIZE; slot += 2)
		sc1442x_init_slot(dev, slot);

	if (dev->type == COA_TYPE_PCI) {
		/* Enable DIP interrupt */
		sc1442x_writeb(dev, SC14424_INT_PRIORITY_1, 0x70);

		/* Enable SPI */
		sc1442x_writeb(dev, SC14424_P1_DIR_REG, 0xd6);
	}
	return 0;
}
EXPORT_SYMBOL_GPL(sc1442x_init_device);

void sc1442x_shutdown_device(struct coa_device *dev)
{
	sc1442x_stop_dip(dev);

	if (dev->type == COA_TYPE_PCI) {
		/* Reset LED */
		sc1442x_writeb(dev, SC14424_P1_RESET_OUTPUT_DATA, 0x40);
	}
}
EXPORT_SYMBOL_GPL(sc1442x_shutdown_device);

MODULE_LICENSE("GPL");
