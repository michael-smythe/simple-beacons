#ifndef SBC_H
#define SBC_H

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <malloc.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <resolv.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/types.h>
#include <unistd.h>

// Internal codes for failing, recovering, and successful operations
#define FAIL       -1
#define RECOVER     1
#define SUCCESS     2

// The defualt port and location of the openssl certificate.
#define SERVE_PORT  993
#define CERT        "../src/mycert.pem"

//Prototype functions
int entersession(SSL *, char *);
void displayhelp(void);
int cmdloop(SSL *);
int newconn(SSL *);
int cmdshell(SSL *);
int getfile(SSL *);
int putfile(SSL *);
int tunnel(SSL *);
int forward_tunnel(SSL *, int, char *, char *, char *);
int reverse_tunnel(SSL *, int, char *, char *, char *);
int winset(SSL *);
void trim(char *);
void clearstdin(void);
int setuplistner(int, int *);
int resolveandconnect(int *, int8_t *, int);
int parseargs(int, char **, char **, int *);
ssize_t ssl_readall(SSL *, uint8_t *, size_t);
ssize_t ssl_writeall(SSL *, uint8_t *, size_t);
ssize_t writeall(int, uint8_t *, size_t);
ssize_t readall(int, uint8_t *, size_t);
void loadcert(SSL_CTX *, char *, char *);
SSL_CTX* initCTX(void);

#endif /* SBC_H */