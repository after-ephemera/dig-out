#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stdio.h>

int create_udp_socket(char* server, short port) {
	struct sockaddr_in resolver_addr = {
		.sin_family = AF_INET, // Internet Address Family
		.sin_port = htons(53), // DNS port, converted to big endian if host is little endian
		.sin_addr = inet_addr(server) // Converting the dot notation (e.g., 8.8.8.8) to binary
	};
	// PF_INET for Internet Protocol family
	// SOCK_DGRAM for datagram socket type
	// IPPROTO_UDP for explicitly indicating UDP protocol
	int sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (sock == -1) {
		perror("socket");
		exit(EXIT_FAILURE);
	}

	// Note that connect() on a UDP socket isn't required since it's
	// a connectionless protocol. However, doing this will make future send()
	// write(), read(), and recv() calls use the address we "connected" to. 
	// That way you no longer use sendto() or recvfrom(). If this is
	// not useful for your purposes, remove the connect() call.
	if (connect(sock, (struct sockaddr*)&resolver_addr, sizeof(resolver_addr)) == -1) {
		perror("connect");
		exit(EXIT_FAILURE);
	}
	return sock;
}
