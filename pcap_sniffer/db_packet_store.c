#include<stdio.h> //For standard things
#include<stdlib.h>
#include<sqlite3.h> 	//provides support for sqlite3 
#include<time.h>
#include<stdint.h>
#include<string.h>

#include "db_packet_store.h"

static sqlite3 *db;
static int rc; 
static char *zErrMsg = 0;
static time_t unix_timestamp;

//Transaction buffer:
static pckt_hdr_data_t transaction_buf[TRANSACTION_BUF_SIZE];
static int transaction_entry_count = 0;

static int callback(void *NotUsed, int argc, char **argv, char **azColName)
{
   int i;
   for(i=0; i<argc; i++){
      printf("%s = %s\n", azColName[i], argv[i] ? argv[i] : "NULL");
   }
   printf("\n");
   return 0;
}

//Clear header data structure:
void clr_pckt_hdr_data(pckt_hdr_data_t *header_data)
{
	memset(header_data,0,sizeof(pckt_hdr_data_t));
}

//Initialize SQLite DB table for packet header data:
int db_hdr_data_table_init(void)
{
	//Open or create database if exists:
	rc = sqlite3_open("traffic_capture.db", &db);
	if( rc ){
	  fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
	  return 1;
	}else{
	  fprintf(stderr, "Opened database successfully\n");
	}
	
	unix_timestamp = time(NULL);
	
	//Create table for current measurement:
	char *sql = sqlite3_mprintf(
					"CREATE TABLE packets_%d("  \
					 "ID INTEGER PRIMARY KEY     AUTOINCREMENT," \
					 "MAC_DST           TEXT," \
					 "MAC_SRC           TEXT," \
					 "ETH_PROT        	INT," \
					 "IP_ADDR_DST       TEXT," \
					 "IP_ADDR_SRC       TEXT," \
					 "IP_PROT        	INT," \
					 "PORT_DST        	INT," \
					 "PORT_SRC        	INT," \
					 "L2_SIZE        	INT," \
					 "TIMESTAMP         INT);", unix_timestamp);
         
	rc = sqlite3_exec(db, sql, callback, 0, &zErrMsg);
	if( rc != SQLITE_OK ){
	fprintf(stderr, "SQL error: %s\n", zErrMsg);
		sqlite3_free(zErrMsg);
		return 1;
	}else{
		fprintf(stdout, "Table created successfully\n");
	}
	
	sqlite3_free(sql);
	return 0;
}

//Close DB connection:
void db_close(void)
{
	sqlite3_close(db);
}

//Insert header data to DB:
int db_insert_pckt_data(pckt_hdr_data_t header_data)
{	
	char *sql = sqlite3_mprintf(
						"INSERT INTO packets_%d (MAC_DST,MAC_SRC,"	\
						"ETH_PROT,IP_ADDR_DST,IP_ADDR_SRC,IP_PROT,"		\
						"PORT_DST,PORT_SRC,L2_SIZE,TIMESTAMP) VALUES ("	\
						"%Q,%Q,%d,%Q,%Q,%d,%d,%d,%d,%d);", unix_timestamp, header_data.mac_dst, \
						header_data.mac_src, header_data.eth_prot, \
						header_data.ip_dst, header_data.ip_src, \
						header_data.ip_prot, header_data.port_dst, \
						header_data.port_src, header_data.l2_size, time(NULL));
	
	rc = sqlite3_exec(db, sql, callback, 0, &zErrMsg);
	if( rc != SQLITE_OK ){
		fprintf(stderr, "SQL error: %s\n", zErrMsg);
		sqlite3_free(zErrMsg);
		return 1;
	}
	
	sqlite3_free(sql);
	return 0;
}

//Get number of entries in transaction buffer:
int db_get_transaction_buf_entry_count(void)
{
	return transaction_entry_count;
}

//Clear transaction buffer:
void db_clear_transaction_buf(void)
{
	transaction_entry_count = 0;
}

//Write entry to transaction buffer:
void db_write_transaction_buf(pckt_hdr_data_t header_data)
{
	memcpy(transaction_buf + transaction_entry_count, &header_data, sizeof(pckt_hdr_data_t));
	transaction_entry_count++;
}

//Insert into DB using transaction:
int db_insert_pckt_data_trans(void)
{
	int i;
	
	sqlite3_exec(db, "BEGIN TRANSACTION;", NULL, NULL, NULL);
	
	for (i = 0; i < TRANSACTION_BUF_SIZE; i++){
		char *sql = sqlite3_mprintf(
						"INSERT INTO packets_%d (MAC_DST,MAC_SRC,"	\
						"ETH_PROT,IP_ADDR_DST,IP_ADDR_SRC,IP_PROT,"		\
						"PORT_DST,PORT_SRC,L2_SIZE,TIMESTAMP) VALUES ("	\
						"%Q,%Q,%d,%Q,%Q,%d,%d,%d,%d,%d);", unix_timestamp, transaction_buf[i].mac_dst, \
						transaction_buf[i].mac_src, transaction_buf[i].eth_prot, \
						transaction_buf[i].ip_dst, transaction_buf[i].ip_src, \
						transaction_buf[i].ip_prot, transaction_buf[i].port_dst, \
						transaction_buf[i].port_src, transaction_buf[i].l2_size, time(NULL));
	
		rc = sqlite3_exec(db, sql, callback, 0, &zErrMsg);
		if( rc != SQLITE_OK ){
			fprintf(stderr, "SQL error: %s\n", zErrMsg);
			sqlite3_free(zErrMsg);
			sqlite3_exec(db, "END TRANSACTION;", NULL, NULL, NULL);
			return 1;
		}
		
		sqlite3_free(sql);
	}
	
	sqlite3_exec(db, "END TRANSACTION;", NULL, NULL, NULL);
	
	return 0;
}
