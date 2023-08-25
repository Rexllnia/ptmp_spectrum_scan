.PHONY:all clean 

all:
	$(CC) $(CFLAGS) -g -D AIRMETRO460  -luci -ldebug -lubus -lubox -lpthread -ljson-c spctrm_scn_debug.c spctrm_scn_rlog.c spctrm_scn_common.c main.c spctrm_scn_tipc.c spctrm_scn_ubus.c spctrm_scn_wireless.c spctrm_scn_dev.c blobmsg_json.a -o spectrum_scan.elf
clean:
	rm *.o spectrum_scan.elf

