#ifndef SC1442X_FIRMWARE
#define SC1442X_FIRMWARE

extern const unsigned char sc1442x_firmware[510];

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
#define Slot00 0x3
#define Slot01 0x5
#define Slot02 0x7
#define Slot03 0x9
#define Slot04 0xB
#define Slot05 0xD
#define Slot06 0x10
#define Slot07 0x12
#define Slot08 0x14
#define Slot09 0x16
#define Slot10 0x18
#define Slot11 0x1A
#define Slot12 0x1D
#define Slot13 0x1F
#define Slot14 0x21
#define Slot15 0x23
#define Slot16 0x25
#define Slot17 0x27
#define Slot18 0x2A
#define Slot19 0x2C
#define Slot20 0x2E
#define Slot21 0x30
#define Slot22 0x32
#define Slot23 0x34
#define RFStart 0xFE
#define RFInit 0xB9
#define SyncInit 0xDE
#define Sync 0xDF
#define SyncLock 0xEF
#define SyncLoop 0xF2
#define ClockSyncOn 0x73
#define ClockSyncOff 0x7B
#define ClockAdjust 0x77
#define PSC_ARPD1 0x80
#define PSC_S_SYNC 0x40
#define PSC_S_SYNC_ON 0x20
#define PSC_EOPSM 0x10
#define RX_P00 0x38
#define RX_P00_Sync 0x3C
#define RX_P32U 0x3F
#define RX_P32P 0x43
#define RX_P32U_Enc 0x3E
#define TX_P00 0x4D
#define TX_P32U 0x51
#define TX_P32P 0x55
#define TX_P32U_Enc 0x50
#define DCS_IV 0x50
#define DCS_CK 0x58
#define DCS_STATE 0x70
#define DCS_STATE_SIZE 0xB
#define LoadEncKey 0xCC
#define LoadEncState 0xD9

#endif /* SC1442X_FIRMWARE */
