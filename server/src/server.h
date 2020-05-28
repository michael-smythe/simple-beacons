#ifndef SBS_H
#define SBS_H

#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <signal.h>
#include <sys/socket.h>
#include <resolv.h>
#include <fcntl.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdlib.h>
#include <getopt.h>
#include <sys/poll.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define FAILURE    -1
#define AUTH       "ASimplePasswordForASimpleTool"

#define NEW 1
#define CMD 2
#define GET 3
#define PUT 4
#define TUN 5
#define BYE 6

#endif /* SBS_H */