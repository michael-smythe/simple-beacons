#include "server.h"

/**
 * Setup a forward tunnel when called from the tunnel function. The server will connect out to the 
 * specified target address and port when the client indicates it has recieved a connection and tunnel
 * traffic to the end destination.
 * The server will remain in the forward tunnel mode until the client indicates that the user has
 * shutdown the tunnel, or it detects a read/write error on either of the sockets. In the event of 
 * a socket error while in the loop the server will revert to its beaconing behavior.
 */
int forward_tunnel(SSL *ssl, int efd) {
  int sfd;
  int res;
  int r;
  int n, max = 128;
  int ssl_fd = SSL_get_fd(ssl);
  uint8_t ans[16] = {0};
  uint8_t buf[4096] = {0};
  char port[7];
  char addr[INET6_ADDRSTRLEN];
  struct epoll_event event;
  struct epoll_event *events;

  // Buffer for the events to be tracked
  if ((events = calloc(max, sizeof(event))) == NULL) {
    if (ssl_writeall(ssl, (uint8_t *)"531", 4) < 0) {return FAIL;}
    return FAIL;
  }

  // Tell the client that we are about to setup a forward tunnel
  if (ssl_writeall(ssl, (uint8_t *)"510", 4) < 0) {return FAIL;}

  // Read in the target address and port from the client.
  if (ssl_readall(ssl, (uint8_t *)addr, sizeof(addr)) < 0) {return FAIL;}
  if (ssl_readall(ssl, (uint8_t *)port, sizeof(port)) < 0) {return FAIL;}

  // Register the default descriptor to track - ssl in this case
  event.data.fd = ssl_fd;
  event.events = EPOLLIN | EPOLLET;
  if (epoll_ctl(efd, EPOLL_CTL_ADD, ssl_fd, &event) == -1) {return FAIL;}

  // Enter into the forward tunnel loop
  while(1) {
    // Wait for events 
    n = epoll_wait(efd, events, max, -1);
    
    // Loop over the alerts
    for (int i = 0; i < n; i++) {
      if (events[i].events & EPOLLERR || events[i].events & EPOLLHUP || (!events[i].events & EPOLLIN)) {
        close(events[i].data.fd);
        return FAIL;
      } 
      // This branch handles outoing data from the client desting for the target
      else if (ssl_fd == events[i].data.fd) { 
        // Check to see the state of the socket on the client side 1) new, 2) connected, 3) shutdown.
        memset(ans, 0, sizeof(ans));
        if (ssl_readall(ssl, ans, 4) < 0) {return FAIL;}
        // This branch handles new connections
        if (strcmp((char *)ans, "511") == 0) { 
          // Connect to the target address and register/add the resulting fd to the event list          
          if (resolveandconnect(&sfd, (int8_t *)&addr, atoi(port)) != SUCCESS) {return FAIL;}
          memset(&event, 0, sizeof(event));
          event.data.fd = sfd;
          event.events = EPOLLIN | EPOLLET;
          if (epoll_ctl(efd, EPOLL_CTL_ADD, sfd, &event) == -1) {return FAIL;}
        } 
        // This branch handles established connections
        else if (strcmp((char *)ans, "512") == 0) {
          // Clear the buffers.
          memset(buf, 0, sizeof(buf));
          memset(ans, 0, sizeof(ans));
          // Check the size of the incoming message
          if (ssl_readall(ssl, buf, sizeof(ans)) < 0) {return FAIL;}
          res = atoi((char *)buf);
          // Read the size of the message into the buffer and echo to the target
          memset(buf, 0, sizeof(buf));
          if (ssl_readall(ssl, buf, res) < 0) {return FAIL;}
          if (writeall(sfd, buf, res) < 0) {continue;}
        } 
        // This branch handles shutting down connections
        else if (strcmp((char *)ans, "513") == 0) {
          // Remove the fd for the connected socket and close down the fd indicated. 
          close(sfd);
          continue;
        } 
        // This branch handles shutting down the entire tunnel 
        else if (strcmp((char *)ans, "514") == 0) { 
          close(sfd);
          free(events);              
          return SUCCESS;
        } 
        // This branch should not be reached. Fail, and resume beaconing.
        else { 
          return FAIL;
        }
      }
      // This branch handles incoming data from the tunnel target 
      else if (sfd == events[i].data.fd) {
        // Clear the buffers
        memset(buf, 0, sizeof(buf));
        memset(ans, 0, sizeof(ans));
        // Read the size of the message
        r = read(sfd, buf, sizeof(buf));
        sprintf((char *)ans, "%d", r);
        // Echo the target messages back to the client.
        ssl_writeall(ssl, ans, sizeof(ans));
        ssl_writeall(ssl, buf, (size_t)r);
      } 
      // We should never hit this branch but if we do just see if we can carry on.
      else {  
        continue;   
      } // Done checking specific event
    } // Done checking updated events
  } // Loop for forward tunnel
}

/**
 * Setup a reverse tunnel when called from the tunnel function. The server will open a listner and wait
 * for connections. Upon recieving a connection it will alert the client to make a connection to the target
 * address and port and facilitate tunneling traffic to the end destination.
 * The server will remain in the forward tunnel mode until the client indicates that the user has
 * shutdown the tunnel, or it detects a read/write error on either of the sockets. In the event of 
 * a socket error while in the loop the server will revert to its beaconing behavior.
 */
int reverse_tunnel(SSL *ssl, int efd) {
  int res;
  int len;
  int sport;
  int sfd, ffd;
  int keepcnt = 5;
  int keepidle = 30; 
  int keepintvl = 30;
  int keepalive = 1;
  int n, max = 128;
  int ssl_fd = SSL_get_fd(ssl);
  uint8_t port[7] = {0};
  uint8_t tarport[7] = {0};
  uint8_t ans[16] = {0};
  uint8_t buf[4096] = {0};
  char taraddr[INET6_ADDRSTRLEN];
  struct timeval timeout;      
  struct epoll_event event;
  struct epoll_event *events;
  struct sockaddr_storage peer;   
  struct sockaddr_storage target;       
  socklen_t socklen = sizeof(target);     
  socklen_t peerlen;                      

  // Buffer for the events to be tracked
  if ((events = calloc(max, sizeof(event))) == NULL) {
    if (ssl_writeall(ssl, (uint8_t *)"531", 4) < 0) {return FAIL;}
    return FAIL;
  }

  // Tell the client that we are about to setup a forward tunnel
  if (ssl_writeall(ssl, (uint8_t *)"520", 4) < 0) {return FAIL;}

  // Read the listening port into memory
  if (ssl_readall(ssl, (uint8_t *)port, 7) < 0) {return FAIL;}

  // Setup the listner
  if (setuplistener(atoi((char *)port), &sfd) != SUCCESS) {return FAIL;}

  // Register the default descriptor to track - ssl in this case
  event.data.fd = sfd;
  event.events = EPOLLIN | EPOLLET;
  if (epoll_ctl(efd, EPOLL_CTL_ADD, sfd, &event) == -1) {return FAIL;}

  // Add the event to the event queue - client socket
  memset(&event, 0, sizeof(event));
  event.data.fd = ssl_fd;
  event.events = EPOLLIN | EPOLLET;
  if (epoll_ctl(efd, EPOLL_CTL_ADD, ssl_fd, &event) == -1) {goto loop_fail;}

  // Enter into the reverse tunnel loop
  while(1) {
    // Wait for events 
    n = epoll_wait(efd, events, max, -1);

    // Loop over the alerts
    for (int i = 0; i < n; i++) {
      if (events[i].events & EPOLLERR || events[i].events & EPOLLHUP || (!events[i].events & EPOLLIN)) {
        close(events[i].data.fd);
        return FAIL;
      } 
      // This branch handles inbound connections
      else if (sfd == events[i].data.fd) { 
        // Accept the connection
        if ((ffd = accept(sfd, (struct sockaddr *)&target, &socklen)) < 0) {goto loop_fail;}
        
        // Set keepalives
        if (setsockopt(ffd, SOL_SOCKET, SO_KEEPALIVE, &keepalive, sizeof(int)) < 0) {goto loop_fail;}
        if (setsockopt(ffd, IPPROTO_TCP, TCP_KEEPCNT, &keepcnt, sizeof(int)) < 0) {goto loop_fail;}
        if (setsockopt(ffd, IPPROTO_TCP, TCP_KEEPIDLE, &keepidle, sizeof(int)) < 0) {goto loop_fail;}
        if (setsockopt(ffd, IPPROTO_TCP, TCP_KEEPINTVL, &keepintvl, sizeof(int)) < 0) {goto loop_fail;}

        // Set socket timeout values
        timeout.tv_sec = 0;
        timeout.tv_usec = 250;
        if (setsockopt(ffd, SOL_SOCKET, SO_RCVTIMEO, (void *)&timeout, sizeof(timeout)) < 0) {goto loop_fail;}
        if (setsockopt(ffd, SOL_SOCKET, SO_SNDTIMEO, (void *)&timeout, sizeof(timeout)) < 0) {goto loop_fail;}

        // Put the socket into non-blocking mode
        if (fcntl(ffd, F_SETFL, O_NONBLOCK) < 0) {goto loop_fail;}

        // Get who we are speaking to
        peerlen = sizeof(peer);
        getpeername(ffd, (struct sockaddr*)&peer, &peerlen);
        if (peer.ss_family == AF_INET) {
          struct sockaddr_in *p = (struct sockaddr_in *)&peer;
          sport = ntohs(p->sin_port);
          inet_ntop(AF_INET, &p->sin_addr, taraddr, sizeof(taraddr));
        } else { // AF_INET6
          struct sockaddr_in6 *p = (struct sockaddr_in6 *)&peer;
          sport = ntohs(p->sin6_port);
          inet_ntop(AF_INET6, &p->sin6_addr, taraddr, sizeof(taraddr));
        } 

        // Add the event to the event queue - connected socket
        memset(&event, 0, sizeof(event));
        event.data.fd = ffd;
        event.events = EPOLLIN | EPOLLET;
        if (epoll_ctl(efd, EPOLL_CTL_ADD, ffd, &event) == -1) {goto loop_fail;}

        // Let the client know we recieved a connection
        if (ssl_writeall(ssl, (uint8_t *)"521", 4) < 0) {goto loop_fail;}
        if (ssl_writeall(ssl, (uint8_t *)taraddr, sizeof(taraddr)) < 0) {goto loop_fail;}
        sprintf((char *)tarport, "%d", sport);
        if (ssl_writeall(ssl, (uint8_t *)tarport, sizeof(tarport)) < 0) {goto loop_fail;}
      }
      // This branch handles incoming data the remote target
      else if (ffd == events[i].data.fd) {
        // Clear the buffers
        memset(buf, 0, sizeof(buf));
        memset(ans, 0, sizeof(ans));
        // Read the size of the message
        res = read(ffd, buf, sizeof(buf));
        if (res < 0) {
          if (errno != EAGAIN || errno != EWOULDBLOCK) {
            goto loop_fail;
          }
          continue;
        } else if (res == 0) {
          ssl_writeall(ssl, (uint8_t *)"523", 4);
          close(ffd);
          continue;
        }
        // Tell the client we are still connected
        if (ssl_writeall(ssl, (uint8_t *)"522", 4) < 0) {goto loop_fail;}
        // Tell the client to expect the following size packet
        sprintf((char *)ans, "%d", res);
        if (ssl_writeall(ssl, (uint8_t *)ans, sizeof(ans)) < 0) {goto loop_fail;}
        // Deliver the message
        if (ssl_writeall(ssl, buf, res) < 0) {goto loop_fail;}
      }
      // This branch handles incoming data the local target
      else if (ssl_fd) {
        // Clear the buffers
        memset(buf, 0, sizeof(buf));
        memset(ans, 0, sizeof(ans));
        // Read into memory the size of message
        if (ssl_readall(ssl, ans, sizeof(ans)) < 0) {goto loop_fail;}
        if (strcmp((char *)ans, "E514") == 0) {
          close(ffd);
          close(sfd);
          free(events);              
          return SUCCESS;
        }
        len = atoi((char *)ans);
        // Echo the messages from the target back to our connected socket
        if (ssl_readall(ssl, buf, len) < 0) {goto loop_fail;}
        if (writeall(ffd, buf, len) < 0) {goto loop_fail;}
      }
      // We should never hit this branch but if we do just see if we can carry on.
      else {  
        continue;   
      } // Done checking specific event
    } // Done checking updated events
  } // Loop for reverse tunnel

  loop_fail:
  if (ffd > 0) {
    close(ffd);
  }
  if (sfd > 0) {
    close(sfd);
  }
  free(events);
  return FAIL;
}
