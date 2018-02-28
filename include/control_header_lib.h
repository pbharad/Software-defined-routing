#ifndef CONTROL_HANDLER_LIB_H_
#define CONTROL_HANDLER_LIB_H_

#define CNTRL_HEADER_SIZE 8
#define CNTRL_RESP_HEADER_SIZE 8
#include <sys/queue.h>
#define PACKET_USING_STRUCT // Comment this out to use alternate packet crafting technique

#ifdef PACKET_USING_STRUCT
    struct __attribute__((__packed__)) CONTROL_HEADER
    {
        uint32_t dest_ip_addr;
        uint8_t control_code;
        uint8_t response_time;
        uint16_t payload_len;
    };

    struct __attribute__((__packed__)) CONTROL_RESPONSE_HEADER
    {
        uint32_t controller_ip_addr;
        uint8_t control_code;
        uint8_t response_code;
        uint16_t payload_len;
    };
   /* struct __attribute__((__packed__)) CONTROL_PAYLOAD
    {
	uint16_t routers;
	uint16_t interval;
	uint16_t router_id;
	uint16_t router_port;
	uint16_t data_port;
	uint16_t cost;
	uint32_t ip;
		
    };*/
#endif

    struct CONTROL_PAYLOAD
    {
	uint16_t router_id;
	uint16_t router_port;
	uint16_t data_port;
	uint16_t cost;
	uint32_t ip;
	uint16_t next_hop;
	int is_neighbor;
	uint16_t init_value;
	LIST_ENTRY(CONTROl_PAYLOAD) next;
		
    };
    LIST_HEAD(router, CONTROL_PAYLOAD) routers_list;
    LIST_HEAD(newlist, CONTROL_PAYLOAD) new_list;

struct TIMER
{
	int timer_value;
	int self;
	int first;
	uint16_t router_id;	
	LIST_ENTRY(TIMER) next;
};
LIST_HEAD(timer_head, TIMER) timers_list;
char* create_response_header(int sock_index, uint8_t control_code, uint8_t response_code, uint16_t payload_len);

#endif

