#include<stdio.h>
#include<string.h>
#include<stdlib.h>
#include<sys/types.h>
#include<sys/socket.h>
#include<netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <unistd.h>

#define TEMP_BUF_LEN	1024
#define BUFFER_MAX	1024

typedef unsigned int dns_rr_ttl;
typedef unsigned short dns_rr_type;
typedef unsigned short dns_rr_class;
typedef unsigned short dns_rdata_len;
typedef unsigned short dns_rr_count;
typedef unsigned short dns_query_id;
typedef unsigned short dns_flags;

typedef struct {
	char *name;
	dns_rr_type type;
	dns_rr_class class;
	dns_rr_ttl ttl;
	dns_rdata_len rdata_len;
	unsigned char *rdata;
} dns_rr;

void print_bytes(unsigned char *bytes, int byteslen) {
	int i, j, byteslen_adjusted;
	unsigned char c;

	if (byteslen % 8) {
		byteslen_adjusted = ((byteslen / 8) + 1) * 8;
	} else {
		byteslen_adjusted = byteslen;
	}
	for (i = 0; i < byteslen_adjusted + 1; i++) {
		if (!(i % 8)) {
			if (i > 0) {
				for (j = i - 8; j < i; j++) {
					if (j >= byteslen_adjusted) {
						printf("  ");
					} else if (j >= byteslen) {
						printf("  ");
					} else if (bytes[j] >= '!' && bytes[j] <= '~') {
						printf(" %c", bytes[j]);
					} else {
						printf(" .");
					}
				}
			}
			if (i < byteslen_adjusted) {
				printf("\n%02X: ", i);
			}
		} else if (!(i % 4)) {
			printf(" ");
		}
		if (i >= byteslen_adjusted) {
			continue;
		} else if (i >= byteslen) {
			printf("   ");
		} else {
			printf("%02X ", bytes[i]);
		}
	}
	printf("\n");
}

void canonicalize_name(char *name) {
	/*
	 * Canonicalize name in place.  Change all upper-case characters to
	 * lower case and remove the trailing dot if there is any.  If the name
	 * passed is a single dot, "." (representing the root zone), then it
	 * should stay the same.
	 *
	 * INPUT:  name: the domain name that should be canonicalized in place
	 */
	
	int namelen, i;

	// leave the root zone alone
	if (strcmp(name, ".") == 0) {
		return;
	}

	namelen = strlen(name);
	// remove the trailing dot, if any
	if (name[namelen - 1] == '.') {
		name[namelen - 1] = '\0';
	}

	// make all upper-case letters lower case
	for (i = 0; i < namelen; i++) {
		if (name[i] >= 'A' && name[i] <= 'Z') {
			name[i] += 32;
		}
	}
}

#define CHAR_BUFFER 256

int name_ascii_to_wire(char *name, unsigned char *wire) {
	/* 
	 * Convert a DNS name from string representation (dot-separated labels)
	 * to DNS wire format, using the provided byte array (wire).  Return
	 * the number of bytes used by the name in wire format.
	 *
	 * INPUT:  name: the string containing the domain name
	 * INPUT:  wire: a pointer to the array of bytes where the
	 *              wire-formatted name should be constructed
	 * OUTPUT: the length of the wire-formatted name.
	 */
	//  printf("Putting {%x, %x, %x, %x, %x} into {%x, %x, %x, %x, %x}",
	//  	*name, *(name+1), *(name+2), *(name+3), *(name+4),
	// 	*wire, *(wire+1), *(wire+2), *(wire+3), *(wire+4));

	 printf("Putting");
	 print_bytes(name, 5);
	 printf(" into ");
	 print_bytes(wire, 5);

	 unsigned char* currentCount = wire; // Represents pointer to the count preceding each segment of the name.
	 *currentCount = 0; // Start the count at 0.
	 wire++; // We will start assigning values at the 1st index of the array.

	 while(*name != 0x00){
		 if(*name == '.'){
			 currentCount = wire;
		 }else{
			 *wire = *name;
			 (*currentCount)++;
		 }
		 wire++;
		 name++;
		//  printf("New wire: %x New Count: %x\n", (unsigned)wire,(unsigned)currentCount);
	 }
	 return strlen(wire);
}

char *name_ascii_from_wire(unsigned char *wire, int *indexp) {
	/* 
	 * Extract the wire-formatted DNS name at the offset specified by
	 * *indexp in the array of bytes provided (wire) and return its string
	 * representation (dot-separated labels) in a char array allocated for
	 * that purpose.  Update the value pointed to by indexp to the next
	 * value beyond the name.
	 *
	 * INPUT:  wire: a pointer to an array of bytes
	 * INPUT:  indexp, a pointer to the index in the wire where the
	 *              wire-formatted name begins
	 * OUTPUT: a string containing the string representation of the name,
	 *              allocated on the heap.
	 */

}

dns_rr rr_from_wire(unsigned char *wire, int *indexp, int query_only) {
	/* 
	 * Extract the wire-formatted resource record at the offset specified by
	 * *indexp in the array of bytes provided (wire) and return a 
	 * dns_rr (struct) populated with its contents. Update the value
	 * pointed to by indexp to the next value beyond the resource record.
	 *
	 * INPUT:  wire: a pointer to an array of bytes
	 * INPUT:  indexp: a pointer to the index in the wire where the
	 *              wire-formatted resource record begins
	 * INPUT:  query_only: a boolean value (1 or 0) which indicates whether
	 *              we are extracting a full resource record or only a
	 *              query (i.e., in the question section of the DNS
	 *              message).  In the case of the latter, the ttl,
	 *              rdata_len, and rdata are skipped.
	 * OUTPUT: the resource record (struct)
	 */
}


int rr_to_wire(dns_rr rr, unsigned char *wire, int query_only) {
	/* 
	 * Convert a DNS resource record struct to DNS wire format, using the
	 * provided byte array (wire).  Return the number of bytes used by the
	 * name in wire format.
	 *
	 * INPUT:  rr: the dns_rr struct containing the rr record
	 * INPUT:  wire: a pointer to the array of bytes where the
	 *             wire-formatted resource record should be constructed
	 * INPUT:  query_only: a boolean value (1 or 0) which indicates whether
	 *              we are constructing a full resource record or only a
	 *              query (i.e., in the question section of the DNS
	 *              message).  In the case of the latter, the ttl,
	 *              rdata_len, and rdata are skipped.
	 * OUTPUT: the length of the wire-formatted resource record.
	 *
	 */
}

unsigned short create_dns_query(char *qname, dns_rr_type qtype, unsigned char *wire) {
	/* 
	 * Create a wire-formatted DNS (query) message using the provided byte
	 * array (wire).  Create the header and question sections, including
	 * the qname and qtype.
	 *
	 * INPUT:  qname: the string containing the name to be queried
	 * INPUT:  qtype: the integer representation of type of the query (type A == 1)
	 * INPUT:  wire: the pointer to the array of bytes where the DNS wire
	 *               message should be constructed
	 * OUTPUT: the length of the DNS wire message
	 */
}

char *get_answer_address(char *qname, dns_rr_type qtype, unsigned char *wire) {
	/* 
	 * Extract the IPv4 address from the answer section, following any
	 * aliases that might be found, and return the string representation of
	 * the IP address.  If no address is found, then return NULL.
	 *
	 * INPUT:  qname: the string containing the name that was queried
	 * INPUT:  qtype: the integer representation of type of the query (type A == 1)
	 * INPUT:  wire: the pointer to the array of bytes representing the DNS wire message
	 * OUTPUT: a string representing the IP address in the answer; or NULL if none is found
	 */
}

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

int recv_comm(int socket, unsigned char* buffer, int length) {

	unsigned char* ptr;
	int bytes_left;
	int bytes_read;
	ptr = buffer;
	bytes_left = length;
	printf("Receiving...\n");
	bytes_read = recv(socket, ptr, bytes_left, 0);
	printf("Bytes Read: %d", bytes_read);
	if (bytes_read < 0) {
		if (errno == EINTR) {
			// continue; // continue upon interrupt
		}
		else {
			perror("recv");
		}
	}
	else if (bytes_read == 0) {
		return -1;
	}
	ptr += bytes_read;
	bytes_left -= bytes_read;
	return 0;
}

int send_comm(int socket, unsigned char* buffer, int length) {
	unsigned char* ptr;
	int bytes_left;
	int bytes_sent;
	ptr = buffer;
	bytes_left = length;
	while (bytes_left) {
		bytes_sent = send(socket, ptr, bytes_left, 0);
		if (bytes_sent < 0) {
			if (errno == EINTR) {
				continue; // continue upon interrupt
			}
			else {
				perror("send");
			}
		}
		else if (bytes_sent == 0) {
			return -1;
		}
		ptr += bytes_sent;
		bytes_left -= bytes_sent;
	}
	return 0;
}

int send_recv_message(unsigned char *request, int requestlen, unsigned char *response, char *server, unsigned short port) {
	/* 
	 * Send a message (request) over UDP to a server (server) and port
	 * (port) and wait for a response, which is placed in another byte
	 * array (response).  Create a socket, "connect()" it to the
	 * appropriate destination, and then use send() and recv();
	 *
	 * INPUT:  request: a pointer to an array of bytes that should be sent
	 * INPUT:  requestlen: the length of request, in bytes.
	 * INPUT:  response: a pointer to an array of bytes in which the
	 *             response should be received
	 * OUTPUT: the size (bytes) of the response received
	 */
	 
	 //  printf("Attempting to connect to %s on port %d\n", server, port);
	 int sock = create_udp_socket(server, port);
	//  printf("Got socket! %d\n", sock);
	 int send_status = send_comm(sock, request, requestlen);
	 if(send_status != 0){
		//  printf("Error sending request to server.\n");
	 }
	//  printf("Sent Request!\n");
	const int RECEIVE_BUFFER_SIZE = 512;
	 recv_comm(sock, response, RECEIVE_BUFFER_SIZE);
	//  print_bytes(response, 49);
}

char *resolve(char *qname, char *server) {
}

int main(int argc, char *argv[]) {
	// ascii to wire test ************************************
	char wire[5];
	char* str = "i.a$";
	for(int i = 0; i < 5; i++){
		wire[i] = 0;
	}
	name_ascii_to_wire(str, wire);
	printf("Wire: {%x, %x, %x, %x, %x}\n", wire[0], wire[1], wire[2], wire[3], wire[4]);
	// print_bytes(wire, 5);
	// *******************************************************

	// send_rcv test *****************************************
	unsigned char msg[] = {
		0x27, 0xd6, 0x01, 0x00,
		0x00, 0x01, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x03, 0x77, 0x77, 0x77,
		0x07, 0x65, 0x78, 0x61,
		0x6d, 0x70, 0x6c, 0x65,
		0x03, 0x63, 0x6f, 0x6d,
		0x00, 0x00, 0x01, 0x00,
		0x01
		};
	unsigned char recv_buffer[512];
	send_recv_message(msg, 33, recv_buffer, argv[2], 53);
	// *******************************************************

	char *ip;
	if (argc < 3) {
		fprintf(stderr, "Usage: %s <domain name> <server>\n", argv[0]);
		exit(1);
	}
	ip = resolve(argv[1], argv[2]);
	printf("%s => %s\n", argv[1], ip == NULL ? "NONE" : ip);
}
