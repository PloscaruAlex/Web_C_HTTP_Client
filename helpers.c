#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <unistd.h>
#include <time.h>
#include <ctype.h>
#include "parson.h"
#include "helpers.h"

struct sockaddr_in server_address_struct(char* ip, int port) {
    struct sockaddr_in server_address;
    memset(&server_address, 0, sizeof(server_address));
    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(port);
    inet_aton(ip, &server_address.sin_addr);
    return server_address;
}

int open_connection(char *ip, int port) {
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    DIE(sockfd < 0, "socket");

    struct sockaddr_in server_address = server_address_struct(ip, port);
    int res = connect(sockfd, (struct sockaddr *) &server_address, sizeof(struct sockaddr));
    DIE(res < 0, "connect");
    return sockfd;
}

char *create_post_request(char *path, char *payload, char* jwt_token) {
    char *header = calloc(MAX_PACKET_LEN, sizeof(char));
    sprintf(header, "POST %s HTTP/1.1\r\n", path);

    char *host = calloc(MAX_COMMAND_LINE_LEN, sizeof(char));
    sprintf(host, "Host: %s:%d\r\n", IP_SERVER, PORT_SERVER);
    strcat(header, host);
    free(host);

    strcat(header, "Content-Type: application/json\r\n");

    if (jwt_token != NULL) {
        strcat(header, "Authorization: Bearer ");
        strcat(header, jwt_token);
        strcat(header, "\r\n");
    }
    char *content_len = calloc(MAX_COMMAND_LINE_LEN, sizeof(char));
    sprintf(content_len, "Content-Length: %d\r\n", strlen(payload));
    strcat(header, content_len);
    free(content_len);

    strcat(header, "\r\n");
    char *request = calloc(MAX_PACKET_LEN, sizeof(char));
    strcat(request, header);
    strcat(request, payload);
    free(header);
    return request;
}

char *create_get_request(char *path, char *auth_cookie, char *jwt_token) {
    char *request = calloc(MAX_PACKET_LEN, sizeof(char));
    sprintf(request, "GET %s HTTP/1.1\r\n", path);
    char *host = calloc(MAX_COMMAND_LINE_LEN, sizeof(char));
    sprintf(host, "Host: %s:%d\r\n", IP_SERVER, PORT_SERVER);
    strcat(request, host);
    free(host);
    if (auth_cookie != NULL) {
        strcat(request, "Cookie: ");
        strcat(request, auth_cookie);
        strcat(request, "\r\n");
    }
    if (jwt_token != NULL) {
        strcat(request, "Authorization: Bearer ");
        strcat(request, jwt_token);
        strcat(request, "\r\n");
    }
    strcat(request, "Content-Length: 0\r\n");
    strcat(request, "\r\n");
    return request;
}

char *create_delete_request(char *path, char *auth_cookie, char *jwt_token) {
    char *request = calloc(MAX_PACKET_LEN, sizeof(char));
    sprintf(request, "DELETE %s HTTP/1.1\r\n", path);
    char *host = calloc(MAX_COMMAND_LINE_LEN, sizeof(char));
    sprintf(host, "Host: %s:%d\r\n", IP_SERVER, PORT_SERVER);
    strcat(request, host);
    free(host);
    if (auth_cookie != NULL) {
        strcat(request, "Cookie: ");
        strcat(request, auth_cookie);
        strcat(request, "\r\n");
    }
    if (jwt_token != NULL) {
        strcat(request, "Authorization: Bearer ");
        strcat(request, jwt_token);
        strcat(request, "\r\n");
    }
    strcat(request, "Content-Length: 0\r\n");
    strcat(request, "\r\n");
    return request;
}

char *json_auth(char *username, char *password) {
    JSON_Value *root_value = json_value_init_object();
    JSON_Object *root_object = json_value_get_object(root_value);
    char *payload = NULL;
    json_object_set_string(root_object, "username", username);
    json_object_set_string(root_object, "password", password);
    payload = json_serialize_to_string_pretty(root_value);
    json_value_free(root_value);
    strcat(payload, "\n");
    return payload;
}

char *json_book(char *title, char *author, char *genre, int page_count, char* publisher) {
    JSON_Value *root_value = json_value_init_object();
    JSON_Object *root_object = json_value_get_object(root_value);
    char *payload = NULL;
    json_object_set_string(root_object, "title", title);
    json_object_set_string(root_object, "author", author);
    json_object_set_string(root_object, "genre", genre);
    json_object_set_number(root_object, "page_count", page_count);
    json_object_set_string(root_object, "publisher", publisher);
    payload = json_serialize_to_string_pretty(root_value);
    json_value_free(root_value);
    strcat(payload, "\n");
    return payload;
}

char *get_auth_cookie(char *response) {
    char *start_of_cookie = strstr(response, "connect.sid");
    int end_of_cookie = strchr(start_of_cookie, ';') - start_of_cookie;
    char *cookie = calloc(MAX_COMMAND_LINE_LEN, sizeof(char));
    memcpy(cookie, start_of_cookie, end_of_cookie);
    return cookie;
}

char *get_jwt_token(char *response) {
    char *payload = strstr(response, "{\"token");
    char *start_of_jwt = strchr(payload, ':') + 2;
    int end_of_jwt = strrchr(start_of_jwt, '"') - start_of_jwt;
    char *token = calloc(JWT_LEN, sizeof(char));
    memcpy(token, start_of_jwt, end_of_jwt);
    return token;
}

int reconnect_and_login(int sockfd, char *logged_in_username, char *logged_in_password, 
                        time_t *last_request_sent, int *first_request_sent, char **auth_cookie) {
    int res = 0;
    char *request = calloc(MAX_PACKET_LEN, sizeof(char));
    char *response = calloc(MAX_PACKET_LEN, sizeof(char));

    close(sockfd);
    sockfd = open_connection(IP_SERVER, PORT_SERVER);
    char *payload = json_auth(logged_in_username, logged_in_password);
    request = create_post_request("/api/v1/tema/auth/login", payload, NULL);
    struct sockaddr_in server_address = server_address_struct(IP_SERVER, PORT_SERVER);
    socklen_t addr_len = 0;

    res = sendto(sockfd, request, strlen(request), 0, (struct sockaddr *) &server_address, sizeof(struct sockaddr));
    *last_request_sent = time(NULL);
    *first_request_sent = 1;
    res = recvfrom(sockfd, response, MAX_PACKET_LEN, 0, (struct sockaddr *) &server_address, &addr_len);
    DIE(res <= 0, "recv");
    if (*auth_cookie != NULL) {
        free(*auth_cookie);
    }
    *auth_cookie = get_auth_cookie(response);
    
    json_free_serialized_string(payload);
    free(request);
    free(response);
    return sockfd;
}

int reconnect_and_enter_library(int sockfd, char *logged_in_username, char *logged_in_password, 
                        time_t *last_request_sent, int *first_request_sent, char **auth_cookie, char **jwt_token) {
    int res = 0;
    char *request = calloc(MAX_PACKET_LEN, sizeof(char));
    char *response = calloc(MAX_PACKET_LEN, sizeof(char));

    sockfd = reconnect_and_login(sockfd, logged_in_username, logged_in_password, last_request_sent, first_request_sent, auth_cookie);

    struct sockaddr_in server_address = server_address_struct(IP_SERVER, PORT_SERVER);
    socklen_t addr_len = 0;

    request = create_get_request("/api/v1/tema/library/access", *auth_cookie, NULL);
    res = sendto(sockfd, request, strlen(request), 0, (struct sockaddr *) &server_address, sizeof(struct sockaddr));
    *last_request_sent = time(NULL);
    *first_request_sent = 1;
    res = recvfrom(sockfd, response, MAX_PACKET_LEN, 0, (struct sockaddr *) &server_address, &addr_len);
    res += recvfrom(sockfd, response + res, MAX_PACKET_LEN, 0, (struct sockaddr *) &server_address, &addr_len);
    DIE(res <= 0, "recv");

    if (*jwt_token != NULL) {
        free(*jwt_token);
    }
    *jwt_token = get_jwt_token(response);

    free(request);
    free(response);
    return sockfd;
}

void recv_all_message(int sockfd, char **response, struct sockaddr_in server_address, socklen_t *addr_len) {
    int res = 0;
    int recv = 0;
    int received_until_now = 0;
    int total_to_be_recv = 0;
    char *buffer = calloc(MAX_PACKET_LEN, sizeof(char)); 
    do {
        res = recvfrom(sockfd, buffer, MAX_PACKET_LEN, 0, (struct sockaddr *) &server_address, addr_len);
        DIE(res <= 0, "recv");
        memcpy(*response + recv, buffer, res);
        recv += res;
        if (strncmp(buffer, "HTTP", 4) == 0) {
            char *content_len = strstr(buffer, "Content-Length: ");
            char *number = content_len + strlen("Content-Length: ");
            char *number_end = strstr(number, "\r\n");
            char *len_str = calloc(10, sizeof(char));
            memcpy(len_str, number, number_end - number);
            total_to_be_recv = atoi(len_str);

            char *payload_response = strstr(buffer, "\r\n\r\n") + 4;
            received_until_now += strlen(payload_response);
        } else {
            received_until_now += res;  
        }
        memset(buffer, 0, res);
    } while (total_to_be_recv > received_until_now);
    free(buffer);
}

void send_request_and_receive_response(int sockfd, char **request, char **response, time_t *last_request_sent, 
                                       int *first_request_sent, struct sockaddr_in server_address, socklen_t *addr_len) {
    int res = 0;
    res = sendto(sockfd, *request, strlen(*request), 0, (struct sockaddr *) &server_address, sizeof(struct sockaddr));
    DIE(res <= 0, "send");
    *last_request_sent = time(NULL);
    *first_request_sent = 1;
    recv_all_message(sockfd,response, server_address, addr_len);
}
