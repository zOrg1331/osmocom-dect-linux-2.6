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

/**
 * struct sockaddr_dect_ssap
 *
 * @dect_family:	family (AF_DECT)
 * @dect_dlei:		Data Link Endpoint Identifier
 * @dect_class:		Class A/B
 */
struct sockaddr_dect_ssap {
	sa_family_t	dect_family;
	__u64		dect_ari:40,
			dect_pmid:20,
			dect_lcn:3;
	__u8		dect_lln:4,
			dect_sapi:4;
	__u8		dect_class;
};

/**
 * struct sockaddr_dect_lu - DLC U-plane LUx service instance address
 *
 * @dect_family:	address family (AF_DECT)
 * @dect_mci:		MAC Connection Identifier
 */
struct sockaddr_dect_lu {
	sa_family_t	dect_family;
	__u64		dect_ari:40,
			dect_pmid:20,
			dect_lcn:3;
};

#endif /* _LINUX_DECT_H */
