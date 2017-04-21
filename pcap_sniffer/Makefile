LIBS=-lpcap -l sqlite3
SRC=main.c db_packet_store.c

psniffer: main.c db_packet_store.c
	gcc -o psniffer $(SRC) $(LIBS)
