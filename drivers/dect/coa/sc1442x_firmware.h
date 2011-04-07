#ifndef SC1442X_FIRMWARE
#define SC1442X_FIRMWARE

extern const unsigned char sc1442x_firmware[509];

#define DIP_CC_INIT 0x10
#define RF_DESC 0x3A
#define BMC_CTRL_INIT 0x0
#define BMC_RX_CTRL 0x48
#define BMC_TX_CTRL 0x40
#define BMC_CTRL_MFR_OFF 0x6
#define SD_RSSI_OFF 0x0
#define SD_CSUM_OFF 0x1
#define SD_PREAMBLE_OFF 0x1
#define SD_DATA_OFF 0x6
#define SlotTable 0x2
#define PP0 0x4
#define PP2 0x6
#define PP4 0x8
#define PP6 0xB
#define PP8 0xD
#define PP10 0xF
#define PP12 0x12
#define PP14 0x14
#define PP16 0x16
#define PP18 0x19
#define PP20 0x1B
#define PP22 0x1D
#define JP0 0x3
#define JP2 0x5
#define JP4 0x7
#define JP6 0xA
#define JP8 0xC
#define JP10 0xE
#define JP12 0x11
#define JP14 0x13
#define JP16 0x15
#define JP18 0x18
#define JP20 0x1A
#define JP22 0x1C
#define RFStart 0xF0
#define SlotTable 0x2
#define SyncInit 0xCF
#define Sync 0xD0
#define SyncLock 0xE0
#define SyncLoop 0xE3
#define ClockSyncOn 0x63
#define ClockSyncOff 0x6B
#define ClockAdjust 0x67
#define PSC_ARPD1 0x80
#define PSC_S_SYNC 0x40
#define PSC_S_SYNC_ON 0x20
#define PSC_EOPSM 0x10
#define RX_P00 0x20
#define RX_P00_Sync 0x25
#define RX_P32U 0x2B
#define RX_P32P 0x30
#define RX_P32U_Enc 0x2A
#define TX_P00 0x3B
#define TX_P32U 0x40
#define TX_P32P 0x45
#define TX_P32U_Enc 0x3F
#define DCS_IV 0x50
#define DCS_CK 0x58
#define DCS_STATE 0x70
#define DCS_STATE_SIZE 0xB
#define LoadEncKey 0xBD
#define LoadEncState 0xCA

#endif /* SC1442X_FIRMWARE */
