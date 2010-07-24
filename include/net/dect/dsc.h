#ifndef _NET_DECT_DSC_H
#define _NET_DECT_DSC_H

static inline __le64 dect_dsc_iv(u32 mfn, u8 framenum)
{
	return cpu_to_le64((mfn << 4) + framenum);
}

extern void dect_dsc_keystream(uint64_t iv, const uint8_t *key,
			       uint8_t *output, unsigned int len);

#endif /* _NET_DECT_DSC_H */
