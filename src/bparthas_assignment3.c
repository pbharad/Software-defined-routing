/**
 * @bparthas_assignment3
 * @author  Bharadwaj Parthasarathy <bparthas@buffalo.edu>
 * @version 1.0
 *
 * @section LICENSE
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details at
 * http://www.gnu.org/copyleft/gpl.html
 *
 * @section DESCRIPTION
 *
 * This contains the main function. Add further description here....
 */

/**
 * main function
 *
 * @param  argc Number of arguments
 * @param  argv The argument list
 * @return 0 EXIT_SUCCESS
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include "../include/control_header_lib.h"
#define AUTHOR_STATEMENT "I, bparthas, have read and understood the course academic integrity policy."
fd_set readfs;
int max_fd = 1;
int control_accept;
int data_accept;
int control_port;
int control_socket;
int router_socket;
int data_socket;
uint16_t routers;
uint16_t interval = 0;
int router_flag = 0;
int data_flag = 0;
int current_router;
uint32_t current_ip;
int current_router_port;
int current_data_port;
struct timeval timeout,current,previous;
struct TIMER timeout_value[5];
int next_timer_value();
void add_timer_values(uint16_t router_id);
uint16_t current_time;
uint16_t previous_time;
int main(int argc, char **argv)
{
	/*Start Here*/
	if(argv[1] != NULL){
		control_port = atoi(argv[1]);
	}
	control_socket = controller_connection(control_port);
	run_select();
	return 0;
}
ssize_t recvALL(int sock_index, char *buffer, ssize_t nbytes)
{
	ssize_t bytes = 0;
    bytes = recv(sock_index, buffer, nbytes, 0);

    if(bytes == 0) return -1;
    while(bytes != nbytes)
        bytes += recv(sock_index, buffer+bytes, nbytes-bytes, 0);
    return bytes;
}

ssize_t sendALL(int sock_index, char *buffer, ssize_t nbytes)
{
    ssize_t bytes = 0;
    bytes = send(sock_index, buffer, nbytes, 0);

    if(bytes == 0) return -1;
    while(bytes != nbytes)
        bytes += send(sock_index, buffer+bytes, nbytes-bytes, 0);

    return bytes;
}
int controller_connection(int port)
{	
	int sock;
   	struct sockaddr_in control_addr;
    	socklen_t addrlen = sizeof(control_addr);
    	sock = socket(AF_INET, SOCK_STREAM, 0);
    	if(sock < 0)
       	printf(" \n socket() failed \n");
    	control_addr.sin_family = AF_INET;
    	control_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    	control_addr.sin_port = htons(port);
    	if(bind(sock, (struct sockaddr *)&control_addr, sizeof(control_addr)) < 0)
        printf("bind() failed");
    	if(listen(sock, 5) < 0)
        printf("listen() failed");
	if(max_fd < sock)
	{
		max_fd = sock;
	}
    	return sock;
}

void run_select()
{	
	while(1)
	{
	FD_ZERO(&readfs);
	FD_SET(control_socket,&readfs);
	if(router_flag == 1)
	{
		FD_SET(router_socket,&readfs);
	}
	if(data_flag == 1)
	{
		FD_SET(data_socket,&readfs);
	}
	int activity = select(max_fd+1,&readfs,NULL,NULL,(interval)?&timeout:NULL); //set timeout here
	if(activity < 0)	
	{	
		printf(" 1 .Error");
		exit(1);
	}
	else if(activity == 0)
	{
		decrement_timer_value();
		timeout.tv_sec = next_timer_value();	
	}
	else
	{	
		if(interval > 0)
		{
			decrement_timer_value();
			timeout.tv_sec = next_timer_value();	
		}

			if(FD_ISSET(control_socket,&readfs))
			{
				control_accept = controller_new_connection(control_socket);			
    				FD_SET(control_accept,&readfs);
			}
			if(FD_ISSET(data_socket,&readfs))
			{
				data_accept = controller_new_connection(data_socket);			
				FD_SET(data_accept,&readfs);
			}
			if(FD_ISSET(router_socket,&readfs))
			{
				struct sockaddr_in sender;
				socklen_t sendsize = sizeof(sender);
				bzero(&sender, sizeof(sender));
				char message[1024];
				memset(message,0,1024);
				int len = recvfrom(router_socket, message, sizeof(message) - 1, 0, (struct sockaddr*)&sender, &sendsize);
				if(len < 0)
				{
					printf("\n Error \n");
				}
				update_routing_table(message);
				
			}

			if(FD_ISSET(control_accept,&readfs))
			{
				process_control_message(control_accept);
			}
			if(FD_ISSET(data_accept,&readfs))
			{

			
			}
	}

}
}

int controller_new_connection(int socket)
{
	int fdaccept, caddr_len;
    	struct sockaddr_in remote_controller_addr;
    	caddr_len = sizeof(remote_controller_addr);
    	fdaccept = accept(socket, (struct sockaddr *)&remote_controller_addr, &caddr_len);
    	if(fdaccept < 0)
        printf("accept() failed");
	if(max_fd < fdaccept){
		max_fd = fdaccept;
	}
	return fdaccept;

}

void process_control_message(int sock_index){
    char *cntrl_header, *cntrl_payload;
    uint8_t control_code;
    uint16_t payload_len;
	
    /* Get control header */
    cntrl_header = (char *) malloc(sizeof(char)*CNTRL_HEADER_SIZE);
    bzero(cntrl_header, CNTRL_HEADER_SIZE);

    if(recvALL(sock_index, cntrl_header, CNTRL_HEADER_SIZE) < 0){
        printf("\n 3 . Error \n");
    }

    /* Get control code and payload length from the header */
    #ifdef PACKET_USING_STRUCT
        /** ASSERT(sizeof(struct CONTROL_HEADER) == 8) 
 *           * This is not really necessary with the __packed__ directive supplied during declaration (see control_header_lib.h).
 *                     * If this fails, comment #define PACKET_USING_STRUCT in control_header_lib.h
 *                               */
        //BUILD_BUG_ON(sizeof(struct CONTROL_HEADER) != CNTRL_HEADER_SIZE); // This will FAIL during compilation itself; See comment above.

        struct CONTROL_HEADER *header = (struct CONTROL_HEADER *) cntrl_header;
        control_code = header->control_code;
        payload_len = ntohs(header->payload_len);
    #endif
    #ifndef PACKET_USING_STRUCT
        memcpy(&control_code, cntrl_header+CNTRL_CONTROL_CODE_OFFSET, sizeof(control_code));
        memcpy(&payload_len, cntrl_header+CNTRL_PAYLOAD_LEN_OFFSET, sizeof(payload_len));
        payload_len = ntohs(payload_len);
    #endif

    free(cntrl_header);

    /* Get control payload */
    if(payload_len != 0){
        cntrl_payload = (char *) malloc(sizeof(char)*payload_len);
        bzero(cntrl_payload, payload_len);

        if(recvALL(sock_index, cntrl_payload, payload_len) < 0){
            printf("\n  2. Error \n");
        }

    }

    /* Triage on control_code */
    switch(control_code){
        case 0: author_response(sock_index);
                break;

        case 1: init_response(sock_index, cntrl_payload);
                break;

	case 2: send_routing_table(sock_index);
		break;

	case 3: update_values(sock_index,cntrl_payload);
		break;
	
	case 4: crash_router(sock_index);
		break;
    }

    if(payload_len != 0) free(cntrl_payload);
}
void author_response(int sock_index)
{
	uint16_t payload_len, response_len;
	char *cntrl_response_header, *cntrl_response_payload, *cntrl_response;

	payload_len = sizeof(AUTHOR_STATEMENT)-1; // Discount the NULL chararcter
	cntrl_response_payload = (char *) malloc(payload_len);
	memcpy(cntrl_response_payload, AUTHOR_STATEMENT, payload_len);

	cntrl_response_header = create_response_header(sock_index, 0, 0, payload_len);

	response_len = CNTRL_RESP_HEADER_SIZE+payload_len;
	cntrl_response = (char *) malloc(response_len);
	/* Copy Header */
	memcpy(cntrl_response, cntrl_response_header, CNTRL_RESP_HEADER_SIZE);
	free(cntrl_response_header);
	/* Copy Payload */
	memcpy(cntrl_response+CNTRL_RESP_HEADER_SIZE, cntrl_response_payload, payload_len);
	free(cntrl_response_payload);

	sendALL(sock_index, cntrl_response, response_len);

	free(cntrl_response);
}

void init_response(int sock_index, char *cntrl_payload)
{
	
/*	#ifdef PACKET_USING_STRUCT
        ** ASSERT(sizeof(struct CONTROL_HEADER) == 8) 
 *           * This is not really necessary with the __packed__ directive supplied during declaration (see control_header_lib.h).
 *                     * If this fails, comment #define PACKET_USING_STRUCT in control_header_lib.h
 *                               */
        //BUILD_BUG_ON(sizeof(struct CONTROL_HEADER) != CNTRL_HEADER_SIZE); // This will FAIL during compilation itself; See comment above.*/
	/*printf("\n here new \n");
        struct CONTROL_PAYLOAD *payload = (struct CONTROL_PAYLOAD *) cntrl_payload;
        routers  = ntohs(payload->routers);
	interval = ntohs(payload->interval);	
	printf("\n Router details : %d \t %d",routers,interval);
	for(int i=0;i<routers;i++){
		printf("\n router_id : %d \t router_port : %d \n",ntohs(payload->router_id),ntohs(payload->router_port));
	}
    #endif*/
    //#ifndef PACKET_USING_STRUCT
        memcpy(&routers, cntrl_payload, sizeof(routers));
        memcpy(&interval, cntrl_payload+2, sizeof(interval));
	routers = ntohs(routers);
	interval = ntohs(interval);
	timeout.tv_sec = interval;
	int offset = cntrl_payload+4;
	LIST_INIT(&routers_list);
	LIST_INIT(&timers_list);
	previous_time = interval;
	for(int i=0;i<routers;i++){
		struct CONTROL_PAYLOAD *router_details = malloc(sizeof(struct CONTROL_PAYLOAD));
		uint16_t router_id;
		uint16_t router_port;
		uint16_t data_port;
		uint16_t cost;
		uint32_t ip;
        	memcpy(&router_id, offset, sizeof(router_id));
		router_details->router_id = ntohs(router_id);	
		offset = offset + 2;
        	memcpy(&router_port, offset, sizeof(router_port));
		router_details->router_port = ntohs(router_port);	
		offset = offset + 2;
        	memcpy(&data_port, offset, sizeof(data_port));
		router_details->data_port = ntohs(data_port);	
		offset = offset + 2;
        	memcpy(&cost, offset, sizeof(cost));
		router_details->cost = ntohs(cost);
		router_details->init_value = ntohs(cost);
		offset = offset + 2;
        	memcpy(&ip, offset, sizeof(ip));
		if(ntohs(cost) == 0)
		{
			current_router_port = ntohs(router_port);
			current_data_port = ntohs(data_port);
			current_router = ntohs(router_id);
			current_ip = ntohl(ip); 
		}	
		offset = offset + 4;
		struct in_addr ip_addr;
		ip_addr.s_addr = ip;		
		router_details->ip = ntohl(ip);
		if(ntohs(cost) != 0 && ntohs(cost) != 65535)
		{
			router_details->is_neighbor = 1;	
			router_details->next_hop = router_details->router_id; 
		}
		else
		{
			router_details->is_neighbor = 0;
			if(ntohs(cost) == 0)
			{
				router_details->next_hop = current_router;	
			}
			if(ntohs(cost) == 65535)
			{
				router_details->next_hop = ntohs(cost);
			}
		}
		LIST_INSERT_HEAD(&routers_list,router_details,next);	
	}
	struct TIMER *timer_details = malloc(sizeof(struct TIMER));
	timer_details->timer_value = interval;
	timer_details->self = 1;
	timer_details->router_id = current_router;
	LIST_INSERT_HEAD(&timers_list,timer_details,next);
	struct CONTROL_PAYLOAD *router_neigh = malloc(sizeof(struct CONTROL_PAYLOAD));
	start_udp_connection(current_router_port);
	data_socket = controller_connection(current_data_port);
	data_flag = 1;
	FD_SET(data_socket,&readfs);
	char *cntrl_response_header;
	cntrl_response_header = create_response_header(sock_index, 1, 0, 0);
	sendALL(sock_index, cntrl_response_header,CNTRL_RESP_HEADER_SIZE);	
    //#endif
}

void start_udp_connection(int router_port)
{	
	struct sockaddr_in control_addr;
	memset(&control_addr, 0, sizeof(control_addr));
    	int udp_sock = socket(AF_INET, SOCK_DGRAM, 0);
    	if(udp_sock < 0)
       	printf(" \n socket() failed \n");
    	control_addr.sin_family = AF_INET;
    	control_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    	control_addr.sin_port = htons(router_port);
    	if(bind(udp_sock, (struct sockaddr *)&control_addr, sizeof(control_addr)) < 0)
        printf("bind() failed");
	router_socket = udp_sock;
	if(max_fd < router_socket)
	{
		max_fd = router_socket;
	}
	router_flag = 1;
	FD_SET(router_socket,&readfs);
	
}

send_routing_updates()
{
	uint16_t payload_len, response_len;
	char *cntrl_response_header, *cntrl_payload_response, *cntrl_response;

	payload_len = 68;
	cntrl_payload_response = (char *) malloc(payload_len);
	struct CONTROL_PAYLOAD *router_details = malloc(sizeof(struct CONTROL_PAYLOAD));
	uint16_t updateFields = htons(5);
	uint16_t routerPort = htons(current_router_port);
	uint32_t ip_addr = htonl(current_ip);
	
	memcpy(cntrl_payload_response,&updateFields,sizeof(updateFields));
	memcpy(cntrl_payload_response+2,&routerPort,sizeof(routerPort));
	memcpy(cntrl_payload_response+4,&ip_addr,sizeof(ip_addr)); //check this
	int offset = 8;
	LIST_FOREACH(router_details, &routers_list,next){
		uint32_t router_ip = htonl(router_details->ip);
		uint16_t router_id = htons(router_details->router_id);
		uint16_t padding = htons(0);
		uint16_t next_hop = htons(router_details->next_hop);
		uint16_t cost = htons(router_details->cost);
		uint16_t router_port = htons(router_details->router_port); 
		memcpy(cntrl_payload_response+offset,&router_ip,sizeof(router_ip));
		offset = offset + 4;
		memcpy(cntrl_payload_response+offset,&router_port,sizeof(router_port));
		offset = offset + 2;
		memcpy(cntrl_payload_response+offset,&padding,sizeof(padding));
		offset = offset + 2;
		memcpy(cntrl_payload_response+offset,&router_id,sizeof(router_id));
		offset = offset + 2;
		memcpy(cntrl_payload_response+offset,&cost,sizeof(cost));
		offset = offset + 2;
	}
	struct CONTROL_PAYLOAD *router_neigh = malloc(sizeof(struct CONTROL_PAYLOAD));
        LIST_FOREACH(router_neigh, &routers_list, next) {
		if(router_neigh->is_neighbor)
		{
			struct in_addr ip_addr;
    			ip_addr.s_addr = htonl(router_neigh->ip);
			char *s = inet_ntoa(ip_addr);
			struct sockaddr_in dest;
			memset( &dest, 0, sizeof(dest));
			dest.sin_family = AF_INET;
			dest.sin_addr.s_addr = inet_addr(s);
			dest.sin_port = htons(router_neigh->router_port);	
			int length = sendto(router_socket,cntrl_payload_response,68,0,(struct sockaddr *)&dest, sizeof(dest));
		}
    	}

}
uint16_t cost_of_router(uint16_t router)
{
	
	struct CONTROL_PAYLOAD *router_details = malloc(sizeof(struct CONTROL_PAYLOAD));
	LIST_FOREACH(router_details, &routers_list,next){
		if(router_details->router_id == router)
		{
			return router_details->init_value;
		}
	}
	return ntohs(0);

}
void update_routing_table(char *message)
{
	uint16_t from_router;
	LIST_INIT(&new_list);
	int offset = 18;	
	for(int i=0;i<5;i++){
		uint16_t cost;
		memcpy(&cost,message+offset,sizeof(cost));
		if(ntohs(cost) == 0)
		{	
			memcpy(&from_router,message+offset-2,sizeof(from_router));
			break;
		}
		offset = offset + 12;
	}	
	from_router = ntohs(from_router);
	//add_timer_values(from_router);
	offset = 8;
	for(int i=0;i<5;i++){
		struct CONTROL_PAYLOAD *new_details = malloc(sizeof(struct CONTROL_PAYLOAD));
		uint16_t router_id;
		uint16_t router_port;
		uint16_t cost;
		uint32_t ip;
		
		offset = offset + 8;
        	memcpy(&router_id, message+offset, sizeof(router_id));
		new_details->router_id = ntohs(router_id);	
		offset = offset + 2;
        	memcpy(&cost, message+offset, sizeof(cost));
		new_details->cost = ntohs(cost);
		offset = offset + 2;
		LIST_INSERT_HEAD(&new_list,new_details,next);
	}

	struct  CONTROL_PAYLOAD *router_details = malloc(sizeof(struct CONTROL_PAYLOAD));
	LIST_FOREACH(router_details, &routers_list,next){
		uint16_t router_id = router_details->router_id;
		uint16_t cost = router_details->cost;
		if(router_id != from_router &&  router_id != current_router)
		{
			struct CONTROL_PAYLOAD *recv_details = malloc(sizeof(struct CONTROL_PAYLOAD));
			LIST_FOREACH(recv_details,&new_list,next)
			{	
				if(recv_details->router_id == router_id)
				{
					uint16_t new_cost = cost_of_router(from_router);	
					if(cost > (recv_details->cost))
					{
						new_cost = recv_details->cost + new_cost; 
						if(new_cost < cost)
						{
							router_details->cost = new_cost;
							router_details->next_hop = from_router;
						}
					}
					break;
				}	
			}
		}
	
	}		
}

void update_values(int socket, char *cntrl_payload){
        uint16_t router_id;
	uint16_t cost;
	memcpy(&router_id, cntrl_payload, sizeof(router_id));
        memcpy(&cost, cntrl_payload+2, sizeof(cost));
	router_id= ntohs(router_id);
	cost = ntohs(cost);
	struct CONTROL_PAYLOAD *router_details = malloc(sizeof(struct CONTROL_PAYLOAD));
	uint16_t cost_change = 0;
	LIST_FOREACH(router_details, &routers_list,next){
		if(router_details->router_id == router_id)
		{
				router_details->cost = cost;
				router_details->init_value = cost;
		}
	}
	char *cntrl_response_header;
	cntrl_response_header = create_response_header(socket, 3, 0, 0);
	sendALL(socket, cntrl_response_header,CNTRL_RESP_HEADER_SIZE);	
}

void crash_router(int socket)
{
	char *cntrl_response_header;
	cntrl_response_header = create_response_header(socket, 4, 0, 0);
	sendALL(socket, cntrl_response_header,CNTRL_RESP_HEADER_SIZE);	
	exit(1);
}

void send_routing_table(int socket)
{
	uint16_t payload_len, response_len;
	char *cntrl_response_header, *cntrl_payload_response, *cntrl_response;

	payload_len = 40;
	cntrl_payload_response = (char *) malloc(payload_len);
	struct CONTROL_PAYLOAD *router_details = malloc(sizeof(struct CONTROL_PAYLOAD));
	char *cntrl_resp_header = (char *) malloc(sizeof(char)*CNTRL_RESP_HEADER_SIZE);	
	int offset = 0;
	LIST_FOREACH(router_details, &routers_list,next){
		uint16_t router_id = htons(router_details->router_id);
		uint16_t padding = htons(0);
		uint16_t next_hop = htons(router_details->next_hop);
		uint16_t cost = htons(router_details->cost);
		memcpy(cntrl_payload_response+offset,&router_id,sizeof(router_id));
		offset = offset + 2;
		memcpy(cntrl_payload_response+offset,&padding,sizeof(padding));
		offset = offset + 2;
		memcpy(cntrl_payload_response+offset,&next_hop,sizeof(next_hop));
		offset = offset + 2;
		memcpy(cntrl_payload_response+offset,&cost,sizeof(cost));
		offset = offset + 2;
	}
	cntrl_response_header = create_response_header(socket, 2, 0, payload_len);
	response_len = CNTRL_RESP_HEADER_SIZE+payload_len;
	cntrl_response = (char *) malloc(response_len);
	/* Copy Header */
	memcpy(cntrl_response, cntrl_response_header, CNTRL_RESP_HEADER_SIZE);
	free(cntrl_response_header);
	/* Copy Payload */
	memcpy(cntrl_response+CNTRL_RESP_HEADER_SIZE, cntrl_payload_response, payload_len);
	free(cntrl_payload_response);
	sendALL(socket, cntrl_response, response_len);

	free(cntrl_response);

}

void decrement_timer_value()
{	
	uint16_t time_new = timeout.tv_sec;
	int dec_value = previous_time - time_new;
	struct TIMER *timer_details = malloc(sizeof(struct TIMER));
	uint16_t router_id = 0;
	LIST_FOREACH(timer_details, &timers_list,next){
		int time = timer_details->timer_value;
		time = time - dec_value;
		if(time == 0)
		{
			if(timer_details->self == 1)
			{
				send_routing_updates();
				timer_details->timer_value = interval;
			}else
			{
				router_id = timer_details->router_id;
				LIST_REMOVE(timer_details,next);
				
			}
	
		}else
		{
			timer_details->timer_value = time;
		}
	}
	if(router_id > 0)
	{
		struct CONTROL_PAYLOAD *router_details = malloc(sizeof(struct CONTROL_PAYLOAD));
		LIST_FOREACH(router_details, &routers_list,next){
			if(router_details->router_id == router_id)
			{
				router_details->is_neighbor = 0;
				router_details->cost = 65535;
			//	router_details->next_hop = 65535;
				break;
			}
		}
		
	}
}

void add_timer_values(uint16_t router_id)
{
	struct TIMER *timer_details = malloc(sizeof(struct TIMER));
	LIST_FOREACH(timer_details, &timers_list,next){
		if(timer_details->router_id == router_id)
		{
			timer_details->timer_value = interval * 3;	
			break;
		}
	}
	struct TIMER *new_details = malloc(sizeof(struct TIMER));
	new_details->router_id = router_id;
	new_details->self = 0;
	new_details->timer_value = interval*3;
	LIST_INSERT_HEAD(&timers_list,new_details,next);


}

int next_timer_value()
{
	uint16_t min_val = interval;
	struct TIMER *timer_details = malloc(sizeof(struct TIMER));
	LIST_FOREACH(timer_details, &timers_list,next){
		if(timer_details->timer_value < min_val)
		{
			min_val = timer_details->timer_value;
		}
	}
	if(min_val <= 0)
	{
		min_val = interval;
	}
	previous_time = min_val;
	return min_val;
}
