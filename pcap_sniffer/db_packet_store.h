#ifndef DB_PACKET_STORE_H
#define DB_PACKET_STORE_H

//Data from packet's headers:
typedef struct {
	char mac_dst[20];
	char mac_src[20];
	uint32_t eth_prot;
	char ip_dst[20];
	char ip_src[20];
	uint32_t ip_prot;
	uint32_t port_dst;
	uint32_t port_src;
	uint32_t l2_size;
} pckt_hdr_data_t;

void clr_pckt_hdr_data(pckt_hdr_data_t *header_data);
int db_hdr_data_table_init(void);
void db_close(void);
int db_insert_pckt_data(pckt_hdr_data_t header_data);

#endif
