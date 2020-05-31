#ifndef SBS_H
#define SBS_H

#include <arpa/inet.h>
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
#include <signal.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

// Internal codes for exiting, failing, recovering, and successful operations
#define EXIT       -2
#define FAIL       -1
#define RECOVER     1
#define SUCCESS     2

// The authentication string that the client will present in order to enter a session
#define AUTH       "ASimplePasswordForASimpleTool"

// The enum of the command name as it relates to a number
#define NEW         1
#define CMD         2
#define GET         3
#define PUT         4
#define TUN         5
#define WIN         6
#define BYE         7

// Prototype functions
int newconn(SSL *, pid_t *);
int cmdshell(SSL *);
int getfile(SSL *);
int putfile(SSL *);
int tunnel(SSL *);
int forward_tunnel(SSL *, int);
int reverse_tunnel(SSL *, int);
int winset(SSL *, int *);
int entersession(SSL *, int *, int *);
int resolveandconnect(int *, int8_t *, int);
ssize_t ssl_readall(SSL *, uint8_t *, size_t);
ssize_t ssl_writeall(SSL *, uint8_t *, size_t);
ssize_t readall(int, uint8_t *, size_t, size_t *);
ssize_t writeall(int, uint8_t *, size_t, size_t *);
SSL_CTX* initCTX(void);

#endif /* SBS_H */