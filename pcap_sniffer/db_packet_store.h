#ifndef DB_PACKET_STORE_H
#define DB_PACKET_STORE_H

//Transaction buffer size:
#define TRANSACTION_BUF_SIZE	1000

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
int db_get_transaction_buf_entry_count(void);
void db_clear_transaction_buf(void);
void db_write_transaction_buf(pckt_hdr_data_t header_data);
int db_insert_pckt_data_trans(void);

#endif
