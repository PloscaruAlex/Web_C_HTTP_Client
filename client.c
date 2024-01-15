#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <arpa/inet.h>
#include <time.h>
#include <ctype.h>
#include "parson.h"
#include "helpers.h"

int main(int argc, char *argv[]) {
    int sockfd = open_connection(IP_SERVER, PORT_SERVER);

    int res;
    struct sockaddr_in server_address = server_address_struct(IP_SERVER, PORT_SERVER);
    socklen_t addr_len = 0;
    time_t last_request_sent = time(NULL);
    int first_request_sent = 0;
    int logged_in = 0;
    int entered_library = 0;
    char *logged_in_username = calloc(MAX_COMMAND_LINE_LEN, sizeof(char));
    char *logged_in_password = calloc(MAX_COMMAND_LINE_LEN, sizeof(char));

    char *command = calloc(MAX_COMMAND_LINE_LEN, sizeof(char));
    char *username = calloc(MAX_COMMAND_LINE_LEN, sizeof(char));
    char *password = calloc(MAX_COMMAND_LINE_LEN, sizeof(char));
    char *request = calloc(MAX_PACKET_LEN, sizeof(char));
    char *response = calloc(MAX_PACKET_LEN, sizeof(char));
    char *auth_cookie = NULL;
    char *jwt_token = NULL;

    while (1) {
        scanf("%s", command);
        if (strncmp(command, "register", 8) == 0) {
            printf("username=");
            scanf("%s", username);
            printf("password=");
            scanf("%s", password);

            char *payload = json_auth(username, password);

            request = create_post_request("/api/v1/tema/auth/register", payload, NULL);

            if (first_request_sent && (time(NULL) - last_request_sent > 4)) {
                close(sockfd);
                sockfd = open_connection(IP_SERVER, PORT_SERVER);
            }
            send_request_and_receive_response(sockfd, &request, &response, &last_request_sent, &first_request_sent, server_address, &addr_len);

            if (strncmp(response, "HTTP/1.1 400", 12) == 0) {
                printf("[400] - BAD REQUEST - Utilizatorul deja exista.\n\n");
            } else if (strncmp(response, "HTTP/1.1 500", 12) == 0) {
                printf("[500] - SERVER PROBLEM - Reincercati.\n\n");
            } else {
                printf("[200] - OK - Utilizator creat cu succes.\n\n");
            }

            json_free_serialized_string(payload);
            memset(username, 0, strlen(username));
            memset(password, 0, strlen(password));
            memset(response, 0, strlen(response));
            memset(request, 0, strlen(request));
        } else if (strncmp(command, "login", 5) == 0) {
            if (logged_in) {
                printf("Sunteti deja autentificat cu username-ul: %s.\n", logged_in_username);
                printf("Daca doriti sa va autentificati cu alt cont va rugam prima oara sa dati logout.\n\n");
                continue;
            }
            printf("username=");
            scanf("%s", username);
            printf("password=");
            scanf("%s", password);

            char *payload = json_auth(username, password);

            request = create_post_request("/api/v1/tema/auth/login", payload, NULL);

            if (first_request_sent && (time(NULL) - last_request_sent > 4)) {
                close(sockfd);
                sockfd = open_connection(IP_SERVER, PORT_SERVER);
            }

            send_request_and_receive_response(sockfd, &request, &response, &last_request_sent, &first_request_sent, server_address, &addr_len);

            if (strncmp(response, "HTTP/1.1 500", 12) == 0) {
                printf("[500] - SERVER PROBLEM - Reincercati.\n\n");
            } else if (strncmp(response, "HTTP/1.1 400", 12) == 0) {
                if (strncmp("{\"error\":\"No account with this username!\"}", 
                        strstr(response, "{\"error"), strlen("{\"error\":\"No account with this username!\"}")) == 0) {
                    printf("[400] - BAD REQUEST - Nu exista niciun cont cu acest username.\n\n");
                } else {
                    printf("[400] - BAD REQUEST - Credentialele nu se potrivesc.\n\n");
                }
            } else {
                auth_cookie = get_auth_cookie(response);
                memcpy(logged_in_username, username, strlen(username));
                memcpy(logged_in_password, password, strlen(password));
                logged_in = 1;
                
                printf("[200] - OK - Sunteti autentificat cu succes. Bun venit!\n\n");
            }
            
            json_free_serialized_string(payload);
            payload = NULL;
            memset(username, 0, strlen(username));
            memset(password, 0, strlen(password));
            memset(response, 0, strlen(response));
            memset(request, 0, strlen(request));
        } else if (strncmp(command, "enter_library", 13) == 0) {
            if (!logged_in) {
                printf("[400] - BAD REQUEST - Va rugam prima oara sa va autentificati.\n\n");
                continue;
            }
            if (first_request_sent && (time(NULL) - last_request_sent > 4)) {
                sockfd = reconnect_and_login(sockfd, logged_in_username, logged_in_password, &last_request_sent, &first_request_sent, &auth_cookie);
            }

            request = create_get_request("/api/v1/tema/library/access", auth_cookie, jwt_token);

            send_request_and_receive_response(sockfd, &request, &response, &last_request_sent, &first_request_sent, server_address, &addr_len);
            if (strncmp(response, "HTTP/1.1 500", 12) == 0) {
                printf("[500] - SERVER PROBLEM - Reincercati.\n\n");
            } else {
                jwt_token = get_jwt_token(response);
                entered_library = 1;

                printf("[200] - OK - Ati accesat biblioteca.\n\n");
            }
            
            memset(response, 0, strlen(response));
            memset(request, 0, strlen(request));
        } else if (strncmp(command, "get_books", 9) == 0) {
            if (!logged_in) {
                printf("[400] - BAD REQUEST - Va rugam prima oara sa va autentificati.\n\n");
                continue;
            }
            if (!entered_library) {
                printf("[400] - BAD REQUEST - Prima oara trebuie sa primiti acces la biblioteca.\n\n");
                continue;
            }
            if (first_request_sent && (time(NULL) - last_request_sent > 4)) {
                sockfd = reconnect_and_enter_library(sockfd, logged_in_username, logged_in_password, &last_request_sent, &first_request_sent, &auth_cookie, &jwt_token);
            }
            request = create_get_request("/api/v1/tema/library/books", auth_cookie, jwt_token);

            send_request_and_receive_response(sockfd, &request, &response, &last_request_sent, &first_request_sent, server_address, &addr_len);
            if (strncmp(response, "HTTP/1.1 500", 12) == 0) {
                printf("[500] - SERVER PROBLEM - Reincercati.\n\n");
            } else {
                printf("[200] - OK - Aceasta este lista de carti:\n");
                printf("%s\n\n", strstr(response, "\r\n\r\n") + 4);
            }

            memset(response, 0, strlen(response));
            memset(request, 0, strlen(request));
        } else if (strncmp(command, "get_book", 8) == 0) {
            if (!logged_in) {
                printf("[400] - BAD REQUEST - Va rugam prima oara sa va autentificati.\n\n");
                continue;
            }
            if (!entered_library) {
                printf("[400] - BAD REQUEST - Prima oara trebuie sa primiti acces la biblioteca.\n\n");
                continue;
            }
            char *id_str = calloc(10, sizeof(char));
            printf("id=");
            scanf("%s", id_str);
            int contains_only_numbers = 1;
            int n = strlen(id_str);
            for (int i = 0; i < n; ++i) {
                if (!isdigit(id_str[i])) {
                    contains_only_numbers = 0;
                    break;
                }
            }
            if (!contains_only_numbers) {
                printf("[400] - BAD REQUEST - Id trebuie sa contina doar numere.\n\n");
                continue;
            }
            int id = atoi(id_str);
            free(id_str);

            if (first_request_sent && (time(NULL) - last_request_sent > 4)) {
                sockfd = reconnect_and_enter_library(sockfd, logged_in_username, logged_in_password, &last_request_sent, &first_request_sent, &auth_cookie, &jwt_token);
            }
            char *path = calloc(MAX_COMMAND_LINE_LEN, sizeof(char));
            sprintf(path, "/api/v1/tema/library/books/%d", id);
            request = create_get_request(path, auth_cookie, jwt_token);

            send_request_and_receive_response(sockfd, &request, &response, &last_request_sent, &first_request_sent, server_address, &addr_len);
            if (strncmp(response, "HTTP/1.1 40", 11) == 0) {
                printf("[404] - NOT FOUND - Cartea cu id = %d nu exista.\n\n", id);
            } else if (strncmp(response, "HTTP/1.1 500", 12) == 0) {
                printf("[500] - SERVER PROBLEM - Reincercati.\n\n");
            } else {
                printf("[200] - OK - Aceasta este cartea cu id = %d:\n", id);
                printf("%s\n\n", strstr(response, "\r\n\r\n") + 4);
            }

            memset(response, 0, strlen(response));
            memset(request, 0, strlen(request));

        } else if (strncmp(command, "add_book", 8) == 0) {
            if (!logged_in) {
                printf("[400] - BAD REQUEST - Va rugam prima oara sa va autentificati.\n\n");
                continue;
            }
            if (!entered_library) {
                printf("[400] - BAD REQUEST - Prima oara trebuie sa primiti acces la biblioteca.\n\n");
                continue;
            }
            char *title = calloc(MAX_COMMAND_LINE_LEN, sizeof(char));
            char *author = calloc(MAX_COMMAND_LINE_LEN, sizeof(char));
            char *genre = calloc(MAX_COMMAND_LINE_LEN, sizeof(char));
            char *page_count_str = calloc(10, sizeof(char));
            char *publisher = calloc(MAX_COMMAND_LINE_LEN, sizeof(char));
            printf("title=");
            getchar();
            scanf("%[^\n]", title);
            printf("author=");
            getchar();
            scanf("%[^\n]", author);
            printf("genre=");
            getchar();
            scanf("%[^\n]", genre);
            printf("publisher=");
            getchar();
            scanf("%[^\n]", publisher);
            printf("page_count=");
            scanf("%s", page_count_str);

            int contains_only_numbers = 1;
            int n = strlen(page_count_str);
            for (int i = 0; i < n; ++i) {
                if (!isdigit(page_count_str[i])) {
                    contains_only_numbers = 0;
                    break;
                }
            }
            if (!contains_only_numbers) {
                printf("[400] - BAD REQUEST - page_count trebuie sa contina doar numere.\n\n");
                continue;
            }
            int page_count = atoi(page_count_str);

            if (first_request_sent && (time(NULL) - last_request_sent > 4)) {
                sockfd = reconnect_and_enter_library(sockfd, logged_in_username, logged_in_password, &last_request_sent, &first_request_sent, &auth_cookie, &jwt_token);
            }

            char *payload = json_book(title, author, genre, page_count, publisher);

            request = create_post_request("/api/v1/tema/library/books", payload, jwt_token);

            send_request_and_receive_response(sockfd, &request, &response, &last_request_sent, &first_request_sent, server_address, &addr_len);
            if (strncmp(response, "HTTP/1.1 500", 12) == 0) {
                printf("[500] - SERVER PROBLEM - Reincercati.\n\n");
            } else if (strncmp(response, "HTTP/1.1 400", 12) == 0) {
                printf("[400] - BAD REQUEST - Datele introduse sunt invalide.\n\n");
            } else {
                printf("[200] - OK - Carte adaugata cu succes.\n\n");
            }

            free(title);
            free(author);
            free(genre);
            free(publisher);
            free(page_count_str);
            json_free_serialized_string(payload);
            memset(response, 0, strlen(response));
            memset(request, 0, strlen(request));
        } else if (strncmp(command, "delete_book", 11) == 0) {
            if (!logged_in) {
                printf("[400] - BAD REQUEST - Va rugam prima oara sa va autentificati.\n\n");
                continue;
            }
            if (!entered_library) {
                printf("[400] - BAD REQUEST - Prima oara trebuie sa primiti acces la biblioteca.\n\n");
                continue;
            }
            char *id_str = calloc(10, sizeof(char));
            printf("id=");
            scanf("%s", id_str);
            int contains_only_numbers = 1;
            int n = strlen(id_str);
            for (int i = 0; i < n; ++i) {
                if (!isdigit(id_str[i])) {
                    contains_only_numbers = 0;
                    break;
                }
            }
            if (!contains_only_numbers) {
                printf("[400] - BAD REQUEST - Id trebuie sa contina doar numere.\n\n");
                continue;
            }
            int id = atoi(id_str);
            free(id_str);

            if (first_request_sent && (time(NULL) - last_request_sent > 4)) {
                sockfd = reconnect_and_enter_library(sockfd, logged_in_username, logged_in_password, &last_request_sent, &first_request_sent, &auth_cookie, &jwt_token);
            }
            char *path = calloc(MAX_COMMAND_LINE_LEN, sizeof(char));
            sprintf(path, "/api/v1/tema/library/books/%d", id);
            request = create_delete_request(path, auth_cookie, jwt_token);
            free(path);

            send_request_and_receive_response(sockfd, &request, &response, &last_request_sent, &first_request_sent, server_address, &addr_len);
            if (strncmp(response, "HTTP/1.1 404", 12) == 0) {
                printf("[404] - NOT FOUND - Cartea cu id = %d nu exista.\n\n", id);
            } else if (strncmp(response, "HTTP/1.1 500", 12) == 0) {
                printf("[500] - SERVER PROBLEM - Reincercati.\n\n");
            } else {
                printf("[200] - OK - Carte stearsa cu succes.\n\n");
            }

            memset(response, 0, strlen(response));
            memset(request, 0, strlen(request));
        } else if (strncmp(command, "logout", 6) == 0) {
            if (!logged_in) {
                printf("[400] - BAD REQUEST - Nu sunteti autentificat.\n\n");
                continue;
            }
              if (first_request_sent && (time(NULL) - last_request_sent > 4)) {
                sockfd = reconnect_and_login(sockfd, logged_in_username, logged_in_password, &last_request_sent, &first_request_sent, &auth_cookie);
            }

            request = create_get_request("/api/v1/tema/auth/logout", auth_cookie, NULL);

            send_request_and_receive_response(sockfd, &request, &response, &last_request_sent, &first_request_sent, server_address, &addr_len);
            if (strncmp(response, "HTTP/1.1 500", 12) == 0) {
                printf("[500] - SERVER PROBLEM - Reincercati.\n\n");
            } else {
                logged_in = 0;
                entered_library = 0;
                memset(logged_in_username, 0, strlen(logged_in_username));
                memset(logged_in_password, 0, strlen(logged_in_password));
                if (auth_cookie != NULL) {
                    free(auth_cookie);
                    auth_cookie = NULL;
                }
                if (jwt_token != NULL) {
                    free(jwt_token);
                    jwt_token = NULL;
                }

                printf("[200] - OK - La revedere!\n\n");
            }
            
            memset(response, 0, strlen(response));
            memset(request, 0, strlen(request));
        } else if (strncmp(command, "exit", 4) == 0) {
            printf("Inchiderea programului.\n");
            break;
        } else {
            printf("Comanda necunoscuta.\n\n");
        }
    }

    free(username);
    free(password);
    free(command);
    free(request);
    free(response);
    free(logged_in_username);
    free(logged_in_password);
    if (auth_cookie != NULL) {
        free(auth_cookie);
        auth_cookie = NULL;
    }
    if (jwt_token != NULL) {
        free(jwt_token);
        jwt_token = NULL;
    }
    close(sockfd);
    return 0;
}