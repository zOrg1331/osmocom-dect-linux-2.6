#ifndef SC1442X_FIRMWARE
#define SC1442X_FIRMWARE

extern const unsigned char sc1442x_firmware[509];

#define DIP_CC_INIT 0x10
#define DIP_RF_INIT 0x0
#define RF_DESC 0x4A
#define RX_DESC 0x58
#define TX_DESC 0x50
#define TRX_DESC_FN 0x6
#define SD_RSSI_OFF 0x0
#define SD_CSUM_OFF 0x1
#define SD_PREAMBLE_OFF 0x1
#define SD_DATA_OFF 0x6
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
#define RFStart 0xCF
#define SlotTable 0x2
#define SyncInit 0xAE
#define Sync 0xAF
#define SyncLock 0xBF
#define SyncLoop 0xC2
#define RecvP32U 0x20
#define RecvP32P 0x26
#define TransmitP00 0x29
#define TransmitP32U 0x2D
#define TransmitP32P 0x33

#endif /* SC1442X_FIRMWARE */
