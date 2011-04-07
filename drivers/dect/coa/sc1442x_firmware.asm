		CPU     SC14421
		ORG	0

		BR      Start

PB_LED          EQU     0x80
PB_RX_ON        EQU     0x40
PB_TX_ON        EQU     0x10
PB_RADIOPOWER   EQU     0x04
PB_DCTHRESHOLD  EQU     0x02
PB_RSSI		EQU	0x01

; synchronisation control
PSC_ARPD1	EQU	0x80
PSC_S_SYNC	EQU	0x40
PSC_S_SYNC_ON	EQU	0x20
PSC_EOPSM	EQU	0x10

; memory banks 0-7, lower and upper halfs (128 bytes each)
BANK0_LOW	EQU	0x00
BANK0_HIGH	EQU	0x10
BANK1_LOW	EQU	0x20
BANK1_HIGH	EQU	0x30
BANK2_LOW	EQU	0x40
BANK2_HIGH	EQU	0x50
BANK3_LOW	EQU	0x60
BANK3_HIGH	EQU	0x70
BANK4_LOW	EQU	0x80
BANK4_HIGH	EQU	0x90
BANK5_LOW	EQU	0xa0
BANK5_HIGH	EQU	0xb0
BANK6_LOW	EQU	0xc0
BANK6_HIGH	EQU	0xd0
BANK7_LOW	EQU	0xe0
BANK7_HIGH	EQU	0xf0

BMC_CTRL_INIT	EQU	0x00

; Codec Control
DIP_CC_INIT	EQU	0x10

; Radio configuration word
RF_DESC		EQU	0x3a

; BMC control information
BMC_CTRL_SIZE	EQU	7
BMC_TX_CTRL	EQU	0x40
BMC_RX_CTRL	EQU	0x48

; (multi) frame number for scambler and DCS
BMC_CTRL_MFR_OFF EQU	6

; Cipher IV/Key
DCS_DESC	EQU	0x50
DCS_IV		EQU	DCS_DESC
DCS_CK		EQU	DCS_DESC + 0x8

; Cipher state
DCS_STATE	EQU	0x70
DCS_STATE_SIZE	EQU	11

SD_PREAMBLE_OFF	EQU	0x01
SD_A_FIELD_OFF	EQU	0x06
SD_B_FIELD_OFF	EQU	0x0E

; status descriptor
SD_BASE_OFF	EQU	0x00
SD_RSSI_OFF	EQU	0x00
SD_CSUM_OFF	EQU	0x01
SD_DATA_OFF	EQU	0x06

; U2785 radio
U2785_CFG1_LEN	EQU	24
U2785_CFG2_LEN	EQU	9

;-------------------------------------------------------------

Start:		BR	InitDIP
;-------------------------------------------------------------

SlotTable:	SLOTZERO

Slot00:		WT	1
		WNT	1
Slot01:		WT	1
		WNT	1
Slot02:		WT	1
		WNT	1
Slot03:		WT	1
		WNT	1
Slot04:		WT	1
		WNT	1
Slot05:		WT	1
		WNT	1
		U_INT0

Slot06:		WT	1
		WNT	1
Slot07:		WT	1
		WNT	1
Slot08:		WT	1
		WNT	1
Slot09:		WT	1
		WNT	1
Slot10:		WT	1
		WNT	1
Slot11:		WT	1
		WNT	1
		U_INT1

Slot12:		WT	1
		WNT	1
Slot13:		WT	1
		WNT	1
Slot14:		WT	1
		WNT	1
Slot15:		WT	1
		WNT	1
Slot16:		WT	1
		WNT	1
Slot17:		WT	1
		WNT	1
		U_INT2

Slot18:		WT	1
		WNT	1
Slot19:		WT	1
		WNT	1
Slot20:		WT	1
		WNT	1
Slot21:		WT	1
		WNT	1
Slot22:		WT	1
		WNT	1
Slot23:		WT	1
		WNT	1
		U_INT3

		BR	SlotTable

;-------------------------------------------------------------------------------
; Receive a P00 packet
;
RX_P00:		JMP	Receive		; Receive S- and beginning of A-field		|
RX_P00_End:	B_BRFU	SD_B_FIELD_OFF	; Receive unprotected full-slot B-field		| p: 95		A: 63
		JMP	ReceiveEnd	; End reception					| p: 96		B:  0
		BR	WriteBMC1	;

RX_P00_Sync:	JMP	ReceiveSync	; Receive S- and beginning of A-field		|
		BR	RX_P00_End

; Receive a P32 packet using the the unprotected full slot B-field format in
; the D32-field
;
RX_P32U_Enc:	JMP	LoadEncKey
RX_P32U:	JMP	Receive
		B_BRFU	SD_B_FIELD_OFF	; Receive unprotected full-slot B-field		| p: 95		A: 63
		JMP	RX_P32U_BZ	; Receive B-field				| p: 96		B:  0
		BR	WriteBMC2

; Receive a P32 packet using the protected full slot B-field format in the
; D32-field
;
RX_P32P:	JMP	Receive
		B_BRFP	SD_B_FIELD_OFF	; Receive protected full slot B-field data	| p:  95	A:  63
		JMP	TransferP32P_B	; Receive the B-subfields			| p:  96-411	B:   0-315
		WT	3		;	 					| p: 412-414	B: 316-318
		B_XR			; Receive X-CRC					| p: 415	B: 319
		WT	6		;						| p: 416-419	B: 320-323	X: 0-3
					;						| p: 420-421	Z:   0-  1
		JMP	ReceiveEnd	;						| p: 422	Z: 2
		B_WRS	SD_BASE_OFF	; write status
		WT	6
		BR	label_58

;-------------------------------------------------------------------------------
; Transmit a P00 packet
;
TX_P00:		JMP	Transmit	; Transmit S- and beginning of A-field		|
		JMP	TransmitEnd	; End transmission				| p: 94		A: 62
		BR	label_53	;

; Transmit a P32 packet using the unprotected full slot B-field format in the
; D32-field
;
TX_P32U_Enc:	JMP	LoadEncKey
TX_P32U:	JMP	Transmit	; Transmit S- and beginning of A-field		|
		B_BTFU	SD_B_FIELD_OFF	; Transmit unprotected full-slot B-field data	| p: 95		A: 63
		JMP	TX_P32U_BZ	; Transmit the B- and Z-fields			| p: 96		B: 0
		BR	label_54	;

; Transmit a P32 packet using the protected full slot B-field format in the
; D32-field
;
TX_P32P:	JMP	Transmit	; Transmit S- and beginning of A-field		|
		B_BTFP	SD_B_FIELD_OFF	; Transmit protect fulls-slot B-field data	| p:  95	A:  63
		JMP	TransferP32P_B	; Transmit the B-subfields			| p:  96-411	B:   0-315
		WT	3		; 						| p: 412-414	B: 316-318
		B_XT			; Transmit X-CRC				| p: 415	B: 319
		WT	13		;						| p: 416-419	B: 320-323	X: 0-3
					;						| p: 420-423	Z: 0-3
					;						| p: 424-428	???
		B_RST			;						| p: 429
		JMP	TransmitEnd	; End transmission				| p: 430
		BR	label_58	;

;-------------------------------------------------------------------------------
WriteBMC1:	B_WRS	SD_BASE_OFF	; write status
		WT	6

label_53:	B_RST
label_54:	P_LDL	PB_RX_ON | PB_TX_ON
		WT	5
		WNT	1
		RTN

;-------------------------------------------------------------------------------
WriteBMC2:	B_WRS	SD_BASE_OFF	; write status
		WT	6
label_58:	B_RST
		P_LDL	PB_RX_ON | PB_TX_ON
		RTN
;-------------------------------------------------------------------------------
; Enable the receiver, receive the S-field and the first 61 bits of the D-field
; (93 bits total)
;
Receive:	B_RST
		B_RC	BMC_RX_CTRL
		WT	BMC_CTRL_SIZE + 1
		P_LDH	PB_RX_ON
		P_LDL	PB_RSSI		; enable RSSI measurement
		WT	25
		WNT	1		; Wait until beginning of slot			|
		WT	8		;						| p: -33--26
		B_XON			;						| p: -25
ClockSyncOn:	P_SC	PSC_S_SYNC_ON	;						| p: -24
		P_LDH	PB_DCTHRESHOLD	;						| p: -23
		WT	5		;						| p: -22--16
		B_SR			; Receive S-field				| p: -17
ClockAdjust:	EN_SL_ADJ		;						| p: -16	S: 0
		WT	12		;						| p: -15--4	S: 1-12
		P_LDL	PB_DCTHRESHOLD	;						| p:  -3	S: 13
		WT	32		;						| p:  -2-29	S: 14-45
ClockSyncOff:	P_SC	0x00		;						| p:  30	S: 46
		B_AR2	SD_A_FIELD_OFF	; Start reception of A-field/A-field CRC	| p:  31	S: 47
		WT	62		; Receive first 61 bits of A-field		| p:  32-92	A:  0-60
		RTN			; Return					| p:  93	A: 61

ReceiveSync:	B_RST
		B_RC	BMC_RX_CTRL
		WT	BMC_CTRL_SIZE + 1
		P_LDH	PB_RX_ON
		P_LDL	PB_RSSI		; enable RSSI measurement
		WT	25
		WNT	1		; Wait until beginning of slot			|
		WT	8		;						| p: -33--26
		B_XON			;						| p: -25
		P_SC	PSC_S_SYNC_ON	;						| p: -24
		P_LDH	PB_DCTHRESHOLD	;						| p: -23
		WT	5		;						| p: -22--16
		B_SR			; Receive S-field				| p: -17
		EN_SL_ADJ		;						| p: -16	S: 0
		WT	12		;						| p: -15--4	S: 1-12
		P_LDL	PB_DCTHRESHOLD	;						| p:  -3	S: 13
		WT	32		;						| p:  -2-29	S: 14-45
		P_SC	0x00		;						| p:  30	S: 46
		B_AR2	SD_A_FIELD_OFF	; Start reception of A-field/A-field CRC	| p:  31	S: 47
		WT	62		; Receive first 61 bits of A-field		| p:  32-92	A:  0-60
		RTN			; Return					| p:  93	A: 61

; Receive the B- and Z-fields of a P32 packet using the protected full slot
; B-field format in the D32-field
RX_P32U_BZ:	WT	249		;						| p:  97-345	B:   1-249
		WT	79		;						| p: 346-415	B: 250-319
					;						| p: 416-419	B: 320-323	X: 0-3
					;						| p: 420-423	Z:   0-  3
					;						| p: 424	??
ReceiveEnd:	P_LDH	PB_RSSI		;						|
		P_LDL	PB_RX_ON
		BR	SaveEncState
;-------------------------------------------------------------------------------
; Enable transmitter, transmit the S-field and the first 61 bits of the D-field
; (93 bits total)
;
Transmit:	P_LDH	0x00		;
		WT	40		;
		B_RST			;
		B_RC	BMC_TX_CTRL	;
		WNT	1		; Wait until beginning of slot
		B_ST	0x00		; Start transmission of S-field data		|
		WT	1		; Wait one bit					| p: -8		S:  0
		P_LDH	PB_TX_ON	; Enable transmitter				| p: -7		S:  1
		WT	37		; Transmit 29 bits S-field			| p: -6-30	S:  2-38
		B_AT2	SD_A_FIELD_OFF	; Start transission of A-field data/A-field CRC	| p: 31		S: 39
		WT	62		; Transmit first 61 bits of A-field		| p: 32-92	A:  0-60
		RTN			; Return					| p: 93		A: 61

;-------------------------------------------------------------------------------
;
;
TX_P32U_BZ:	WT	249		; 						| p:  97-345	B:   1-249
		WT	84		; Last bits of B-field data			| p: 346-415	B: 250-319
					; X-field					| p: 416-419	B: 320-323	X: 0-3
					; Z-field (?)					| p: 420-424	Z:   0-  3
					; 5 bits of crap?				| p: 425-429
		B_RST			; Reset BMC					| p: 430

TransmitEnd:	P_LDL	PB_TX_ON	; Disable transmitter				|
		WT	8		; Wait until transmitter is disabled		|
		P_LDL	0x00		;
		BR	SaveEncState

;-------------------------------------------------------------------------------
; Transfer a protected B-field subfield
;
; The X-CRC includes the R-CRC in its calculation, which is contained in the
; last 16 bits of the subfield.
;
TransferBP:  	B_XON			; Enable X-CRC calculation			| p: 159+i*80			  Bi: 63
		WT	15		; Transfer 15 bits R-CRC, include in X-CRC	| p: 160+i*80-164+i*80		  Bi: 64-78	R_Bi: 0-14
		B_XOFF			; Disable X-CRC	calculation			| p: 175+i*80			  Bi: 79	R_Bi: 15
		WT	61		; Transfer first 61 bits of next B-field	| p: 176+i*80-236+i*80		  Bi:  0-60
		RTN			; Return					| p: 237+i*80			  Bi: 61

; Transfer the B-field subfields of a P32 packet using protected full slot
; format
TransferP32P_B:	WT	61		; Transfer 61 bits of B-field			| p:  97-157	B:   1- 61	  B0: 1-61
		JMP	TransferBP	; End subfield, begin next subfield		| p: 158-237	B:  62-141	  B0: 62-79	B1: 0-61
		JMP	TransferBP	; End subfield, begin next subfield		| p: 238-317	B: 142-221	  B1: 62-79	B2: 0-61
		JMP	TransferBP	; End subfield, begin next subfield		| p: 318-397	B: 222-301	  B2: 62-79	B3: 0-61
		WT	1		;						| p: 398	B: 302		  B3: 62
		B_XON			; 						| p: 399	B: 303		  B3: 63
		WT	11		;						| p: 400-410	B: 304-314	R_B3:  0-10
		RTN			;						| p: 411	B: 315		R_B3: 11

;-------------------------------------------------------------------------------

RFInit:		RFEN			; Enable RF-clock
		WT	2

		MEN1N			; Transfer first radio configuration word
		M_WR	RF_DESC
		WT	U2785_CFG1_LEN + 1
		M_RST
		MEN1

		MEN1N			; Transfer second radio configuration word
		M_WR	RF_DESC + U2785_CFG1_LEN / 8
		WT	U2785_CFG2_LEN + 1
		M_RST
		MEN1
		;WT	1

		P_LDL	0x20
		WT	10
		MEN2
		WT	182
		MEN2N
		WT	16
		RTN
;--------------------------------------------------------------
;
LoadEncKey:	D_RST
		D_LDK	DCS_DESC	; load IV (64 bits) and cipher key (64 bits)
		WT	16
		D_LDK	0
		D_PREP	0
		WT	39
		D_PREP	0
		RTN

SaveEncState:	D_WRS   DCS_STATE
		WT	DCS_STATE_SIZE	; actually should be -1, but does not work
		D_WRS	0
		D_RST
		RTN

LoadEncState:	D_RST
		D_LDS	DCS_STATE
		WT	DCS_STATE_SIZE	; actually should be -1, but does not work
		D_LDS	0
		RTN
;-------------------------------------------------------------

SyncInit:	BK_C	BANK1_LOW
Sync:		JMP	RFInit
		WT	250
		P_SC	PSC_S_SYNC_ON
		P_LDH	PB_RX_ON | PB_DCTHRESHOLD
		UNLCK
		WT	64
		B_XOFF
		B_SR
		WNT	20
		JMP1	SFieldFound
		B_RST
		U_INT1
		WNT	23
		BR	Sync
;-------------------------------------------------------------

SFieldFound:	WNT	23
		P_SC	0x00
SyncLock:	JMP	RX_P00
		U_INT0
		WNT	22
SyncLoop:	BR	Sync
;-------------------------------------------------------------

InitDIP:	;B_RST
		BK_C	BANK0_LOW
		C_LD	DIP_CC_INIT
		WT	10
		B_RC	BMC_CTRL_INIT
		WT	BMC_CTRL_SIZE + 1
		B_RST
		;C_ON
		WT	10
		P_EN
		P_LD	0x04
		RCK_INT
		RFEN
RFStart:	BR	SyncInit
;-------------------------------------------------------------

		SHARED	DIP_CC_INIT,RF_DESC
		SHARED	BMC_CTRL_INIT,BMC_RX_CTRL,BMC_TX_CTRL,BMC_CTRL_MFR_OFF
		SHARED	SD_RSSI_OFF,SD_CSUM_OFF,SD_PREAMBLE_OFF,SD_DATA_OFF

		SHARED	SlotTable
		SHARED	Slot00,Slot01,Slot02,Slot03,Slot04,Slot05,Slot06,Slot07
		SHARED	Slot08,Slot09,Slot10,Slot11,Slot12,Slot13,Slot14,Slot15
		SHARED	Slot16,Slot17,Slot18,Slot19,Slot20,Slot21,Slot22,Slot23

		SHARED	RFStart,RFInit
		SHARED	SyncInit,Sync,SyncLock,SyncLoop
		SHARED	ClockSyncOn,ClockSyncOff,ClockAdjust
		SHARED	PSC_ARPD1,PSC_S_SYNC,PSC_S_SYNC_ON,PSC_EOPSM

		SHARED	RX_P00,RX_P00_Sync,RX_P32U,RX_P32P,RX_P32U_Enc
		SHARED	TX_P00,TX_P32U,TX_P32P,TX_P32U_Enc

		SHARED	DCS_IV,DCS_CK,DCS_STATE,DCS_STATE_SIZE
		SHARED	LoadEncKey,LoadEncState
