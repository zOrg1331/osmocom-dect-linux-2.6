#ifndef _LINUX_DECT_H
#define _LINUX_DECT_H

#define DECTNAMSIZ	16

#include <linux/types.h>
#include <linux/socket.h>

/* these have to be macros in order to be usable for module aliases */
#define DECT_RAW	0	/* raw frames */
#define DECT_B_SAP	1	/* DLC Broadcast Service */
#define DECT_S_SAP	2	/* DLC Data Link Service */
#define DECT_LU1_SAP	3	/* LU1 sockets */
#define DECT_PROTO_NUM	4

/**
 * struct sockaddr_dect
 *
 * @dect_family:	address family (AF_DECT)
 * @dect_index:		cluster index
 */
struct sockaddr_dect {
	sa_family_t	dect_family;
	int		dect_index;
};

/* raw sockets */

#define DECT_RAW_AUXDATA	0

/**
 * struct dect_raw_auxdata - raw socket auxiliary frame data
 *
 * @mfn:	multi-frame number
 * @frame:	frame number
 * @slot:	slot numer
 * @rssi:	receive signal strength indicator
 */
struct dect_raw_auxdata {
	__u32		mfn;
	__u8		frame;
	__u8		slot;
	__u8		rssi;
};

#define DECT_BSAP_AUXDATA	0

/**
 * struct dect_bsap_auxdata
 *
 * @long_page:	message contains a long page
 */
struct dect_bsap_auxdata {
	__u8		long_page;
};

/**
 * enum dect_sapis - S SAP Identifier
 *
 * @DECT_SAPI_CO_SIGNALLING:	connection oriented signalling
 * @DECT_SAPI_CL_SIGNALLING:	connectionless signalling
 * @DECT_SAPI_ANY:		wildcard
 */
enum dect_sapis {
	DECT_SAPI_CO_SIGNALLING = 0,
	DECT_SAPI_CL_SIGNALLING = 3,
	DECT_SAPI_ANY		= 7,
};

/**
 * enum dect_llns - Logical Link Numbers
 *
 * @DECT_LLN_CLASS_U:		Class U operation
 * @DECT_LLN_CLASS_A:		Class A operation
 * @DECT_LLN_ASSIGNABLE*:	Assignable LLN (class B operation)
 * @DECT_LLN_UNASSIGNED:	LLN unassigned (class B operation
 * @DECT_LLN_ANY:		wildcard
 */
enum dect_llns {
	DECT_LLN_CLASS_U	= 0,
	DECT_LLN_CLASS_A	= 1,
	DECT_LLN_ASSIGNABLE_MIN	= 2,
	DECT_LLN_ASSIGNABLE_MAX	= 6,
	DECT_LLN_UNASSIGNED	= 7,
	DECT_LLN_ANY		= 15,
};

/**
 * struct sockaddr_dect_ssap
 *
 * @dect_family:	family (AF_DECT)
 * @dect_lln:		logical link number
 * @dect_sapi:		service access point identifier
 * @dect_class:		class A/B
 * @dect_index:		cluster index
 * @dect_ari:		ARI
 * @dect_pmid:		PMID
 * @dect_lcn:		logical connection number
 */
struct sockaddr_dect_ssap {
	sa_family_t	dect_family;
	__u8		dect_lln:4,
			dect_sapi:3;
	__u8		dect_class;
	int		dect_index;
	__u64		dect_ari:40,
			dect_pmid:20,
			dect_lcn:3;
};

/* S-SAP primitives */
#define DECT_DL_ENC_KEY	1
#define DECT_DL_ENCRYPT	2

enum dect_cipher_states {
	DECT_CIPHER_DISABLED,
	DECT_CIPHER_ENABLED,
};

enum dect_mac_service_types {
	DECT_SERVICE_IN_MIN_DELAY		= 0x0,
	DECT_SERVICE_IPX_ENCODED_PROTECTED	= 0x1,
	DECT_SERVICE_IN_NORMAL_DELAY		= 0x2,
	DECT_SERVICE_UNKNOWN			= 0x4,
	DECT_SERVICE_C_CHANNEL_ONLY		= 0x5,
	DECT_SERVICE_IP_ERROR_DETECTION		= 0x10,
	DECT_SERVICE_IPQ_ERROR_DETECTION	= 0x14,
	/* Lifetime encoded in low three bits */
	DECT_SERVICE_IP_ERROR_CORRECTION	= 0x18,
	DECT_SERVICE_IPQ_ERROR_CORRECTION	= 0x38,
};

/**
 * struct dect_dl_encrypt - DL_ENCRYPT primitive arguments
 *
 * @status:		desired/achieved encryption status
 */
struct dect_dl_encrypt {
	enum dect_cipher_states	status;
};

/**
 * struct sockaddr_dect_lu - DLC U-plane LUx service instance address
 *
 * @dect_family:	address family (AF_DECT)
 * @dect_mci:		MAC Connection Identifier
 */
struct sockaddr_dect_lu {
	sa_family_t	dect_family;
	int		dect_index;
	__u64		dect_ari:40,
			dect_pmid:20,
			dect_lcn:3;
};

/* LU1 SAP */

#define DECT_LU1_QUEUE_STATS	0

struct dect_lu1_queue_stats {
	__u32		rx_bytes;
	__u32		rx_underflow;
	__u32		tx_bytes;
	__u32		tx_underflow;
};

#endif /* _LINUX_DECT_H */
