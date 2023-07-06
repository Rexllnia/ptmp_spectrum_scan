.PHONY:all clean 

dump_packet_path := "/home/zyf/buildroot/package/spectrum_scan/src/dump_packet.a"


all:
	$(CC) $(CFLAGS) -g  -luci -lubus -lubox -lpthread -ljson-c spctrm_scn_rlog.c spctrm_scn_common.c main.c spctrm_scn_tipc.c spctrm_scn_ubus.c spctrm_scn_wireless.c spctrm_scn_dev.c -o spectrum_scan.elf -L$(dump_packet_path) 
clean:
	rm *.o spectrum_scan.elf

