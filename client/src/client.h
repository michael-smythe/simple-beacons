#ifndef SBC_H
#define SBC_H

#include <errno.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netdb.h>
#include <resolv.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <getopt.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define FAILURE -1

#define SERVE_PORT 993

#define CALL_HOST "localhost"
#define CALL_DELAY 5

#define NEW 1
#define CMD 2
#define GET 3
#define PUT 4
#define TUN 5
#define WIN 6
#define BYE 7

#endif /* SBC_H */