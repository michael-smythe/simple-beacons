#ifndef SBS_H
#define SBS_H

#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <sys/socket.h>
#include <resolv.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <getopt.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define FAILURE    -1
#define ADDR       "127.0.0.1"
#define PORT        993
#define AUTH       "ASimplePasswordForASimpleTool"

#define NEW 1
#define CMD 2
#define GET 3
#define PUT 4
#define TUN 5
#define WIN 6
#define BYE 7

#endif /* SBS_H */