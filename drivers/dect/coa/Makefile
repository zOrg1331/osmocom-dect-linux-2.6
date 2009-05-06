com_on_air-objs				:= sc14421_firmware.o sc14421.o

obj-$(CONFIG_DECT_COA)			+= com_on_air.o

$(obj)/sc14421.o:			$(obj)/sc14421_firmware.c
$(obj)/sc14421_firmware.c:		NAME=sc14421
clean-files				+= sc14421_firmware.p
clean-files				+= sc14421_firmware.bin
clean-files				+= sc14421_firmware.h.tmp

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
