#ifndef _HELPERS_
#define _HELPERS_

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#define IP_SERVER "34.254.242.81"
#define PORT_SERVER 8080
#define MAX_COMMAND_LINE_LEN 200
#define MAX_PACKET_LEN 7000
#define JWT_LEN 300

#define DIE(assertion, call_description)                                         \
  	do {                                                                         \
    	if (assertion) {                                                         \
      		fprintf(stderr, "(%s, %d): ", __FILE__, __LINE__);                   \
      		perror(call_description);                                            \
      		exit(errno);                                                         \
    	}                                                                        \
  	} while (0)

int open_connection(char *ip, int port);

char *create_post_request(char *path, char *payload, char *jwt_token);

char *create_get_request(char *path, char *login_cookie, char *jwt_cookie);

char *create_delete_request(char *path, char *auth_cookie, char *jwt_token);

struct sockaddr_in server_address_struct(char* ip, int port);

char *json_auth(char *username, char *password);

char *json_book(char *title, char *author, char *genre, int page_count, char* publisher);

char *get_auth_cookie(char *response);

char *get_jwt_token(char *response);

int reconnect_and_login(int sockfd, char *logged_in_username, char *logged_in_password, 
                        time_t *last_request_sent, int *first_request_sent, char **auth_cookie);

int reconnect_and_enter_library(int sockfd, char *logged_in_username, char *logged_in_password, 
                        time_t *last_request_sent, int *first_request_sent, char **auth_cookie, char **jwt_token);

void recv_all_message(int sockfd, char **response, struct sockaddr_in server_address, socklen_t *addr_len);

void send_request_and_receive_response(int sockfd, char **request, char **response, time_t *last_request_sent, 
                                       int *first_request_sent, struct sockaddr_in server_address, socklen_t *addr_len);

#endif