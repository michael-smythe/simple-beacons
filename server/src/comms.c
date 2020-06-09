#include "server.h"

/**
 * Helper function to ensure the entire buffer gets read during non-blocking SSL_reads.
 */
ssize_t ssl_readall(SSL *ssl, uint8_t *buf, size_t len) {
    int r = 0;
    size_t recvd = 0;

    while (recvd < len) {
      r = SSL_read(ssl, &buf[recvd], len-recvd);
      if (r <= 0) {
        if (SSL_get_error(ssl, r) == SSL_ERROR_WANT_READ) {
          continue;
        }
        return FAIL;
      }
      recvd += r;
    }
    return r;
}

/**
 * Helper function to ensure the entire buffer gets read during non-blocking SSL_writes.
 */
ssize_t ssl_writeall(SSL *ssl, uint8_t *msg, size_t len) {
  int s = 0;
  size_t sent = 0;

  while (sent < len) {
    if ((s = SSL_write(ssl,  &msg[sent], len-sent)) <= 0) {
      if (SSL_get_error(ssl, s) == SSL_ERROR_WANT_WRITE) {
        continue;
      }
      return FAIL;
    }
    sent += s;
  }

  return s;
}

/**
 * Helper function to ensure the entire buffer is read from a traditional fd socket
 */
ssize_t readall(int fd, uint8_t *buf, size_t len) {
  ssize_t r = 0;
  size_t readin = 0;

  while(readin < len) {
    if ((r = read(fd, &buf[readin], len-readin)) <= 0) {
      if (errno == EAGAIN || errno == EWOULDBLOCK) {
        continue;
      }
      break;
    }
    readin += r;
  }

  return r;
}

/**
 * Helper function to ensure the entire buffer is written to a traditional fd socket
 */
ssize_t writeall(int fd, uint8_t *buf, size_t len) {
  ssize_t w = 0;
  size_t written = 0;
  
  while(written < len) {
    if ((w = write(fd, &buf[written], len-written)) <= 0) {
      if (errno == EAGAIN || errno == EWOULDBLOCK) {
        continue;
      }
      break;
    }
    written += w;
  }

  return w;
}

/**
 * Resolve and connect an address and port connection. Setup socket timeouts and keepalives as well.
 * Ensure that the resulting socket is set to non-blocking mode.
 */
int resolveandconnect(int *sockfd, int8_t *addr, int port) {
  int keepcnt = 5;
  int keepidle = 30; 
  int keepintvl = 30;
  int keepalive = 1;
  int connected = 0;
  char portstr[6];
  struct addrinfo hints, *serveraddr, *p;
  struct timeval timeout;

  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;

  snprintf(portstr, 6,"%d", port);

  if (getaddrinfo((char *)addr, portstr, &hints, &serveraddr) != 0) {return FAIL;}

  for(p = serveraddr; p != NULL; p = p->ai_next) {
    // Check to see if the addrsocket works
    if (((*sockfd) = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) {
      continue;
    }

    if (connect((*sockfd), p->ai_addr, p->ai_addrlen) < 0) {
      continue;         
    }
    connected = 1;
    break;
  }

  freeaddrinfo(serveraddr);  // All done with the struct at this point

  if (connected == 0) {return FAIL;}

  // Set socket timeout
  timeout.tv_sec = 30;
  timeout.tv_usec = 0;
  if (setsockopt(*sockfd, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout)) < 0) {return FAIL;}
  if (setsockopt(*sockfd, SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout, sizeof(timeout)) < 0) {return FAIL;}

  // Set keepalives
  if (setsockopt(*sockfd, SOL_SOCKET, SO_KEEPALIVE, &keepalive, sizeof(int)) < 0) {return FAIL;}
  if (setsockopt(*sockfd, IPPROTO_TCP, TCP_KEEPCNT, &keepcnt, sizeof(int)) < 0) {return FAIL;}
  if (setsockopt(*sockfd, IPPROTO_TCP, TCP_KEEPIDLE, &keepidle, sizeof(int)) < 0) {return FAIL;}
  if (setsockopt(*sockfd, IPPROTO_TCP, TCP_KEEPINTVL, &keepintvl, sizeof(int)) < 0) {return FAIL;}

  if (fcntl(*sockfd, F_SETFL, O_NONBLOCK) < 0) {return -1;}

  return SUCCESS;
}

/**
 * Set up a listening socket on a specified port
 */
int setuplistener(int port, int *sockfd) {
  int status;
  int optval = 1;
  char portstr[6];
  struct addrinfo hints, *servinfo, *p;

  // Populate the hints for the following getaddrinfo()
  memset(&hints, 0, sizeof hints);    // Ensure the struct is empty
  hints.ai_family = AF_UNSPEC;        // Indiferent to IPv4 or IPv6
  hints.ai_socktype = SOCK_STREAM;    // TCP stream socket
  hints.ai_flags = AI_PASSIVE;        // Populate the IP for me

  // Get a string version of the port to bind to
  snprintf(portstr, 6,"%d", port);

  // Get address info
  if ((status = getaddrinfo(NULL, portstr, &hints, &servinfo)) != 0) {
    return FAIL;
  };

  // Loop through all returned interfaces and bind to the first viable one
  for(p = servinfo; p != NULL; p = p->ai_next) {
    // Check to see if the addrsocket works
    if ((*sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) {
      continue;
    }

    // Attempt to set socket to reuseaddr
    if (setsockopt(*sockfd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(int)) == -1) {
      return FAIL;
    }

    // Bind to the specified port using the socket
    if (bind(*sockfd, p->ai_addr, p->ai_addrlen) == -1) {
      close(*sockfd);
      continue;
    }
    break;
  }

  freeaddrinfo(servinfo);  // All done with the struct at this point

  // Report errors if we are unable to bind
  if (p == NULL) {
    return FAIL;
  }

  // Attempt to listen
  if (listen(*sockfd, 2) == -1) {
    return FAIL;
  }

  // The socket is now listening and ready to be utilized
  return SUCCESS; 
}