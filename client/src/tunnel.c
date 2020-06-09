#include "client.h"

/**
 * Setup a forward tunnel when called from the tunnel function. The client will open a listener and wait for
 * connections. Upon recieving a connection it will alert the server to make a connection to the target address 
 * and port and facilitate tunneling traffic to the end destination. 
 * The client will remain in this mode until the user indicates they would like to shutdown the tunnel
 * or it detects a read/write error on either of the sockets. In the event of a socket error while in the 
 * loop the server will revert to its beaconing behavior.
 */ 
int forward_tunnel(SSL *ssl, int efd, char *lport, char *dport, char *addr) {
  int res;
  int len;
  int tunport;
  int sfd, ffd;
  int keepcnt = 5;
  int keepidle = 30; 
  int keepintvl = 30;
  int keepalive = 1;
  int n, max = 128;
  int ssl_fd = SSL_get_fd(ssl);
  uint8_t ans[16] = {0};
  uint8_t buf[4096] = {0};
  char tunaddr[INET6_ADDRSTRLEN];
  struct timeval timeout;      
  struct epoll_event event;
  struct epoll_event *events;
  struct sockaddr_storage peer;   
  struct sockaddr_storage target;       
  socklen_t socklen = sizeof(target);     
  socklen_t peerlen;                      

  // Signal to the server that we are using a forward tunnel
  if (ssl_writeall(ssl, (uint8_t *)"51", 3) < 0) {return FAIL;}

  // Ensure that the server is gtg.
  if (ssl_readall(ssl, ans, 4) < 0) {return FAIL;}
  if (strcmp((char *)ans, "510") != 0) {
    fprintf(stderr, "[-] Unexpected server response: %s.\n", ans);
    return FAIL;
  }

  // Tell the server which address and port to point the tunnel at
  if (ssl_writeall(ssl, (uint8_t *)addr, 46) < 0) {return FAIL;}
  if (ssl_writeall(ssl, (uint8_t *)dport, 7) < 0) {return FAIL;}

  // Setup the listner
  if (setuplistner(atoi(lport), &sfd) != SUCCESS) {return FAIL;}

  // Register stdin with epoll to see if the user has typed something into the tunnel window.
  event.data.fd = 0;  // 0 is stdin.
  event.events = EPOLLIN | EPOLLET;
  if (epoll_ctl(efd, EPOLL_CTL_ADD, 0, &event) == -1) {return FAIL;}

  // Register the default descriptor to track - sfd in this case
  memset(&event, 0, sizeof(event));
  event.data.fd = sfd;
  event.events = EPOLLIN | EPOLLET;
  if (epoll_ctl(efd, EPOLL_CTL_ADD, sfd, &event) == -1) {return FAIL;}

  // Buffer for the events to be tracked
  if ((events = calloc(max, sizeof(event))) == NULL) {
    fprintf(stderr, "[-] Unable to initialize the event queue.\n");
    return FAIL;
  }

  printf("[*] To exit the tunnel interface type 'close' and press enter.\n");
  // Enter into the forward tunnel loop
  while(1) {
    // Wait for events 
    n = epoll_wait(efd, events, max, -1);

    // Loop over the alerts
    for (int i = 0; i < n; i++) {
      if (events[i].events & EPOLLERR || events[i].events & EPOLLHUP || (!events[i].events & EPOLLIN)) {
        close(events[i].data.fd);
        continue;
      } 
      // Handle user input -- if they want to exit shut down everything and return to the menu.
      else if (0 == events[i].data.fd) {
        memset(ans, 0, sizeof(ans));
        fgets((char *)ans, sizeof(ans), stdin);
        trim((char *)ans);
        if (strcmp((char *)ans, "close") == 0) {
          if (ssl_writeall(ssl, (uint8_t *)"514", 4) < 0) {goto loop_fail;}
          close(ffd);
          close(sfd);
          free(events);
          return SUCCESS;
        }
      }
      // Handle inbound connections 
      else if (sfd == events[i].data.fd) {
        // Accept the connection
        printf("[+] Detected new connection - accepting call.\n");
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

        // Print who we are speaking to.
        peerlen = sizeof(peer);
        getpeername(ffd, (struct sockaddr*)&peer, &peerlen);
        if (peer.ss_family == AF_INET) {
          struct sockaddr_in *p = (struct sockaddr_in *)&peer;
          tunport = ntohs(p->sin_port);
          inet_ntop(AF_INET, &p->sin_addr, tunaddr, sizeof(tunaddr));
        } else { // AF_INET6
          struct sockaddr_in6 *p = (struct sockaddr_in6 *)&peer;
          tunport = ntohs(p->sin6_port);
          inet_ntop(AF_INET6, &p->sin6_addr, tunaddr, sizeof(tunaddr));
        } 
        printf("[+] Successfully setup connection with tunnel client at %s:%d.\n", tunaddr, tunport);

        // Add the event to the event queue - connected socket
        memset(&event, 0, sizeof(event));
        event.data.fd = ffd;
        event.events = EPOLLIN | EPOLLET;
        if (epoll_ctl(efd, EPOLL_CTL_ADD, ffd, &event) == -1) {goto loop_fail;}

        // Add the event to the event queue - client socket
        memset(&event, 0, sizeof(event));
        event.data.fd = ssl_fd;
        event.events = EPOLLIN | EPOLLET;
        if (epoll_ctl(efd, EPOLL_CTL_ADD, ssl_fd, &event) == -1) {goto loop_fail;}

        // Message the client to alert them to the new connection
        printf("[+] Sending message to server to initiate the server setup.\n");
        if (ssl_writeall(ssl, (uint8_t *)"511", 4) < 0) {goto loop_fail;}
        printf("[+] Message sent successfully!\n");
      } 
      // This branch handles incoming data from the target to the tunnel
      else if (ffd == events[i].data.fd) {
        // Clear the buffers
        memset(buf, 0, sizeof(buf));
        memset(ans, 0, sizeof(ans));
        // Read in the messages from the connected socket
        res = read(ffd, buf, sizeof(buf));
        // Check for errors or disconnected clients
        if (res < 0) {
          if (errno != EAGAIN || errno != EWOULDBLOCK) {
            goto loop_fail;
          }
          continue;
        } else if (res == 0) {
          printf("[*] Target attatched to tunnel disconnected.\n");
          ssl_writeall(ssl, (uint8_t *)"513", 4);
          close(ffd);
          continue;
        }
        // Tell the server we are still connected
        if (ssl_writeall(ssl, (uint8_t *)"512", 4) < 0) {goto loop_fail;}
        // Tell the server the expected size of the incoming message
        printf("[+] Sending %d bytes to the target.\n", res);
        sprintf((char *)ans, "%d", res);
        if (ssl_writeall(ssl, (uint8_t *)ans, sizeof(ans)) < 0) {goto loop_fail;}
        // Deliver the message
        if (ssl_writeall(ssl, buf, res) < 0) {goto loop_fail;}
      } 
      // This branch handles incoming data from the client side tunnel target
      else if (ssl_fd == events[i].data.fd) {
        // Clear the buffers
        memset(buf, 0, sizeof(buf));
        memset(ans, 0, sizeof(ans));
        // Read into memory the size of message
        ssl_readall(ssl, ans, sizeof(ans));
        len = atoi((char *)ans);
        // Echo the messages from the target back to our connected socket
        printf("[+] Recieved %d bytes from target.\n", len);
        ssl_readall(ssl, buf, len);
        writeall(ffd, buf, len);
      } 
      // We should never hit this branch but if we do just see if we can carry on.
      else {  
        goto loop_fail;
      } // Done checking specific event
    } // Done checking updated events
  } // Loop for reverse tunnel

  loop_fail:
  printf("[-] The loop failed for some reason...\n");
  if (ffd > 0) {
    close(ffd);
  }
  if (sfd > 0) {
    close(sfd);
  }
  free(events);
  return FAIL;
}

/**
 * Setup either a forward or reverse tunnel.
 * The client will remain in this mode until the user indicates they would like to shutdown the tunnel
 * or it detects a read/write error on either of the sockets. In the event of a socket error while in the 
 * loop the server will revert to its beaconing behavior.
 */ 
int reverse_tunnel(SSL *ssl, int efd, char *lport, char *dport, char *addr) {
  int sfd;
  int res;
  int n, max = 128;
  int ssl_fd = SSL_get_fd(ssl);
  uint8_t ans[16] = {0};
  uint8_t buf[4096] = {0};
  uint8_t sport[7] = {0};
  uint8_t saddr[INET6_ADDRSTRLEN] = {0};
  struct epoll_event event;
  struct epoll_event *events;

  // Signal to the server that we are using a forward tunnel
  if (ssl_writeall(ssl, (uint8_t *)"52", 3) < 0) {return FAIL;}

  // Ensure that the server is gtg.
  if (ssl_readall(ssl, ans, 4) < 0) {return FAIL;}
  if (strcmp((char *)ans, "520") != 0) {
    fprintf(stderr, "[-] Unexpected server response: %s.\n", ans);
    return FAIL;
  }

  if (ssl_writeall(ssl, (uint8_t *)lport, 7) < 0) {return FAIL;}

  // Register stdin with epoll to see if the user has typed something into the tunnel window.
  event.data.fd = 0;  // 0 is stdin.
  event.events = EPOLLIN | EPOLLET;
  if (epoll_ctl(efd, EPOLL_CTL_ADD, 0, &event) == -1) {return FAIL;}

  // Register the default descriptor to track - sfd in this case
  memset(&event, 0, sizeof(event));
  event.data.fd = ssl_fd;
  event.events = EPOLLIN | EPOLLET;
  if (epoll_ctl(efd, EPOLL_CTL_ADD, ssl_fd, &event) == -1) {return FAIL;}

  // Buffer for the events to be tracked
  if ((events = calloc(max, sizeof(event))) == NULL) {
    fprintf(stderr, "[-] Unable to initialize the event queue.\n");
    return FAIL;
  }

  printf("[*] To exit the tunnel interface type 'close' and press enter.\n");
  while(1) {
    // Wait for events 
    n = epoll_wait(efd, events, max, -1);

    // Loop over the alerts
    for (int i = 0; i < n; i++) {
      if (events[i].events & EPOLLERR || events[i].events & EPOLLHUP || (!events[i].events & EPOLLIN)) {
        close(events[i].data.fd);
        continue;
      } 
      // Handle user input -- if they want to exit shut down everything and return to the menu.
      else if (0 == events[i].data.fd) {
        memset(ans, 0, sizeof(ans));
        fgets((char *)ans, sizeof(ans), stdin);
        trim((char *)ans);
        if (strcmp((char *)ans, "close") == 0) {
          if (ssl_writeall(ssl, (uint8_t *)"E514", 5) < 0) {goto loop_fail;}
          close(sfd);
          free(events);
          return SUCCESS;
        }
      }
      // Handle traffic coming from server and remote target
      else if (ssl_fd == events[i].data.fd) {
        // Check to see the state of the socket on the client side 1) new, 2) connected, 3) shutdown.
        memset(ans, 0, sizeof(ans));
        if (ssl_readall(ssl, ans, 4) < 0) {return FAIL;}
        // This branch handles new connections
        if (strcmp((char *)ans, "521") == 0) {
          if (ssl_readall(ssl, saddr, sizeof(saddr)) < 0) {return FAIL;}
          if (ssl_readall(ssl, sport, sizeof(sport)) < 0) {return FAIL;}
          printf("[+] Server detected connection from %s:%d.\n", saddr, atoi((char *)sport));

          // Connect to the target address and register/add the resulting fd to the event list          
          if (resolveandconnect(&sfd, (int8_t *)addr, atoi(dport)) != SUCCESS) {return FAIL;}
          memset(&event, 0, sizeof(event));
          event.data.fd = sfd;
          event.events = EPOLLIN | EPOLLET;
          if (epoll_ctl(efd, EPOLL_CTL_ADD, sfd, &event) == -1) {return FAIL;}
        } 
        // This branch handles established connections
        else if (strcmp((char *)ans, "522") == 0) {
          // Clear the buffers.
          memset(buf, 0, sizeof(buf));
          memset(ans, 0, sizeof(ans));
          // Check the size of the incoming message
          if (ssl_readall(ssl, buf, sizeof(ans)) < 0) {return FAIL;}
          res = atoi((char *)buf);
          printf("[+] SSL Connection Data: %d\n", res);
          // Read the size of the message into the buffer and echo to the target
          memset(buf, 0, sizeof(buf));
          if (ssl_readall(ssl, buf, res) < 0) {return FAIL;}
          if (writeall(sfd, buf, res) < 0) {continue;}
        } 
        // This branch handles shutting down connections
        else if (strcmp((char *)ans, "523") == 0) {
          // Remove the fd for the connected socket and close down the fd indicated. 
          close(sfd);
          continue;
        } 
        // This branch should not be reached. Fail, and resume beaconing.
        else { 
          return FAIL;
        }
      }
      // Handle incoming data from the tunnel target
      else if (sfd == events[i].data.fd) {
        // Clear the buffers
        memset(buf, 0, sizeof(buf));
        memset(ans, 0, sizeof(ans));
        // Read the size of the message
        res = read(sfd, buf, sizeof(buf));
        if (res < 0) {
          if (errno != EAGAIN || errno != EWOULDBLOCK) {
            goto loop_fail;
          }
          continue;
        }
        printf("[+] Local Client Data: %d.\n", res);
        sprintf((char *)ans, "%d", res);
        // Echo the target messages back to the client.
        ssl_writeall(ssl, ans, sizeof(ans));
        ssl_writeall(ssl, buf, (size_t)res);
      } 
      // We should never hit this branch but if we do just see if we can carry on.
      else {  
        goto loop_fail;
      } // Done checking specific event
    } // Done checking updated events
  } // Loop for reverse tunnel

  loop_fail:
  printf("[-] The loop failed for some reason...\n");
  if (sfd > 0) {
    close(sfd);
  }
  free(events);
  return FAIL;
}
