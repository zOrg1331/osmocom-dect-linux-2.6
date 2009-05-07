com_on_air-objs				:= sc1442x_firmware.o sc1442x.o
com_on_air-$(CONFIG_DECT_COA_U2785)	+= radio_u2785.o
com_on_air-$(CONFIG_DECT_COA_LMX3161)	+= radio_lmx3161.o

obj-$(CONFIG_DECT_COA)			+= com_on_air.o
obj-$(CONFIG_DECT_COA_PCI)		+= com_on_air_pci.o
obj-$(CONFIG_DECT_COA_CS)		+= com_on_air_cs.o

$(obj)/sc1442x.o:			$(obj)/sc1442x_firmware.c
$(obj)/sc1442x_firmware.c:		NAME=sc1442x
clean-files				+= sc1442x_firmware.p
clean-files				+= sc1442x_firmware.bin
clean-files				+= sc1442x_firmware.h.tmp

hostprogs-$(CONFIG_DECT_COA_FIRMWARE)	+= bin2c

ifeq ($(CONFIG_DECT_COA_FIRMWARE),y)

ASL		= asl
P2BIN		= p2bin
BIN2C		= $(obj)/bin2c

quiet_cmd_asl	= ASL     $<
      cmd_asl	= $(ASL) -q -c $< -o $(<:.asm=.p) -shareout $(<:.asm=.h.tmp); \
		  $(P2BIN) $(<:.asm=.p) $(<:.asm=.bin) -r 0-507; \
		  $(BIN2C) $(<:.asm=.bin) $(NAME)_firmware > $@; \
		  ( \
			echo "\#ifndef $$(echo $(NAME) | tr a-z A-Z)_FIRMWARE"; \
			echo "\#define $$(echo $(NAME) | tr a-z A-Z)_FIRMWARE"; \
			echo;\
			echo "extern const unsigned char $(NAME)_firmware[509];"; \
			echo;\
			grep define $(<:.asm=.h.tmp); \
			echo;\
			echo "\#endif /* $$(echo $(NAME) | tr a-z A-Z)_FIRMWARE */"; \
		  ) > $(@:.c=.h)

$(obj)/%_firmware.c: $(src)/%_firmware.asm $(BIN2C)
	$(call if_changed,asl)

endif
