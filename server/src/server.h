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
#include <sys/poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define EXIT       -2
#define FAIL       -1
#define RECOVER     1
#define SUCCESS     2

#define AUTH       "ASimplePasswordForASimpleTool"

#define NEW         1
#define CMD         2
#define GET         3
#define PUT         4
#define TUN         5
#define WIN         6
#define BYE         7

#endif /* SBS_H */