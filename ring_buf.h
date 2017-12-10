#ifndef __RING_BUF_H__
#define __RING_BUF_H__


typedef struct log_ring_s {
	uint8_t magic;
	uint8_t ver;
	uint16_t head;
	uint16_t tail;
	uint16_t cnt;
	uint16_t slot_size;

	char data[0];
} log_ring_t;

typedef struct log_read_info_s {
	uint16_t start;
	uint16_t cnt;
} log_read_info_t;

typedef struct log_s {
	uint32_t date;
	char msg[256];
} log_t;


#define MAX_LOG_MEM_ORDER 0


#endif
