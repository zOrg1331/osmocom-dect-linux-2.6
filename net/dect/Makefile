dect-y				+= core.o identities.o dect_netlink.o af_dect.o

dect_csf-y			+= mac_csf.o transceiver.o

dect_ccf-y			+= mac_ccf.o
dect_ccf-y			+= dlc.o
dect_ccf-y			+= dlc_cplane.o dlc_b_sap.o dlc_s_sap.o
dect_ccf-y			+= dlc_uplane.o

dect-y	+= $(dect_ccf-y) $(dect_csf-y) ccp.o

obj-$(CONFIG_DECT)		+= dect.o
#obj-$(CONFIG_DECT_CSF)		+= dect_csf.o
obj-$(CONFIG_DECT_RAW)		+= raw.o
#obj-$(CONFIG_DECT_CCF)		+= dect_ccf.o
obj-$(CONFIG_DECT_B_SAP)	+= dlc_b_sap.o
obj-$(CONFIG_DECT_LU1_SAP)	+= dlc_lu1_sap.o
