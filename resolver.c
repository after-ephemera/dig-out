#include<stdio.h>
#include<string.h>
#include<stdlib.h>
#include<sys/types.h>
#include<sys/socket.h>
#include<netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>

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

	//  printf("Putting");
	//  print_bytes(name, 5);
	//  printf(" into ");
	//  print_bytes(wire, 5);
	 unsigned char* wireStart = wire;
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
	 *wire = 0x00;
	 return strlen(wireStart);
}

int name_ascii_from_wire(unsigned char *wire, int *indexp, char* name) {
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
	 * OUTPUT: the length of the original wire-formatted name.
	 */
	 int length = 1; // Start at 1 for the first chunksize.
	 char* nameStart = name;
	 unsigned char retBuf[BUFFER_MAX];
	 int i = *indexp;
	 unsigned char chunkSize = wire[i];
	//  printf("First char: 0x%x\n", chunkSize);
	 i++;
	 while(chunkSize){
		for(int j = 0; j < chunkSize; j++){
			// printf("0x%x\n",wire[i+j]);
			length++;
			*name = wire[i+j];
			name++;
		}
		unsigned char oldCS = chunkSize;
		chunkSize = wire[i+chunkSize];
		i = i+oldCS + 1;
		// printf("new chunk size: %d\n", chunkSize);
		if(chunkSize){
			*name = '.';
			name++;
			length++;
		}
	 }
	 *name = 0x00;

	//  printf("Final name: %s\n", nameStart);
	 return length;
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
	wire[0] = rand();
	wire[1] = rand();
	wire[2] = 0x01;
	wire[3] = 0x00;
	wire[4] = 0x00;
	wire[5] = 0x01;
	wire[6] = 0x00;
	wire[7] = 0x00;
	wire[8] = 0x00;
	wire[9] = 0x00;
	wire[10] = 0x00;
	wire[11] = 0x00;
	int queryLen = name_ascii_to_wire(qname, &(wire[12]));
	// printf("Length of qname: %d\n", queryLen);
	int nextLoc = 12 + queryLen + 1;
	wire[nextLoc] = 0x00;
	wire[++nextLoc] = 0x01;
	wire[++nextLoc] = 0x00;
	wire[++nextLoc] = 0x01;
	return nextLoc+1; // Final element + 1 
}

void wire_to_string_ip(char* wire, int ipLength, char* ip){
	// printf("IP Length: %d", ipLength);
	int i = 0;
	char* ipCurr = ip;
	while(ipLength){
		printf("ip: %u\n", (wire[i] & 0xff));
		int chars = sprintf(ipCurr, (ipLength == 1) ? "%u":"%u.", (wire[i] & 0xff));
		// printf("Chars: %d", chars); 
		ipCurr += chars; 
		i++;
		ipLength--;
	}
	printf("FINAL: %s\n", ip);
}

char *get_answer_address(char *qname, dns_rr_type qtype, unsigned char *wire, char* answer) {
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
	 uint16_t id = (wire[0] << 8) | wire[1];
	 printf("ID: 0x%x\n", id);
	 uint16_t flags = (wire[2] << 8) | wire[3];
	 printf("Flags: 0x%x\n", flags); // Should be 0x8180 for standard DNS query.
	 uint16_t totalQs = (wire[4] << 8) | wire[5];
	 printf("Total Questions: %d\n", totalQs);
	 uint16_t totalAnswerRRs = (wire[6] << 8) | wire[7];
	 printf("Total Answer RRs: %d\n", totalAnswerRRs);
	 uint16_t totalAuthRRs = (wire[8] << 8) | wire[9];
	 printf("Total Authority RRs: %d\n", totalAuthRRs);
	 uint16_t totalAddlRRs = (wire[10] << 8) | wire[11];
	 printf("Total Additional RRs: %d\n", totalAddlRRs);
	 char* queryStart = &(wire[12]); // Save the location of the start of the queries.
	 // We are going to assume there is only a single query because we only ever send one.	
	 unsigned char nameBuf[512];
	 int i = 12;
	 name_ascii_from_wire(wire, &i, nameBuf);
	 printf("Got name: %s with length %d\n", nameBuf, (int)strlen(nameBuf));
	 
	//  uint16_t queryType = (uint16_t) *(queryStart + strlen(nameBuf) + 1);
	//  printf("Query Type: 0x%x\n", queryType);
	//  uint16_t queryClass = *(queryStart + strlen(nameBuf) + 2);

	int answerNumber = 1;
	// The first answer rr...
	char* answerRRPtr = queryStart + strlen(nameBuf) + 6;
	// Run through all answer rrs until we've found the right one.
	while(answerNumber <= totalAnswerRRs){
		// printf("Answer RR first Char 0x%2x\n", (*answerRRPtr) & 0xff);

		// If the first two bits of the answer RR are set, then the name has been compressed.
		unsigned char ownerName[BUFFER_MAX];
		int j = 0;
		if((*answerRRPtr & 0xC0) == 0xC0){
			printf("Compressed encoding\n");
			answerRRPtr += 2;
			j = *answerRRPtr;
			name_ascii_from_wire(queryStart, &j, ownerName);
			printf("Got uncompressed name: %s\n", ownerName);
			uint16_t answerType = (*(answerRRPtr + 2) << 8) | *(answerRRPtr + 3);
			answerRRPtr += 3;
			printf("Answer type: 0x%x\n", answerType);
			// If the names match and the answerType is 1...
			if(!(strcmp(ownerName, qname)) && answerType == 0x01){
				// ... then we have found our address!
				answerRRPtr += 5;
				int rDataLength = (*(answerRRPtr) << 8) | *(answerRRPtr + 1);
				printf("Length of Rdata: 0x%x\n", rDataLength);
				answerRRPtr += 2;
				char stringIP[BUFFER_MAX];
				wire_to_string_ip(answerRRPtr, rDataLength, stringIP);
				strncpy(answer, answerRRPtr, rDataLength);
				// print_bytes(answerRRPtr, rDataLength);
			}
		} else{
			name_ascii_from_wire(queryStart, &j, ownerName);
			printf("Got owner name: %s\n", ownerName);
		}
		answerNumber++;
		break;
	}
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
	// printf("Receiving...\n");
	bytes_read = recv(socket, ptr, bytes_left, 0);
	// printf("Bytes Read: %d", bytes_read);
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
	return bytes_read;
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
	 
	//   printf("Attempting to connect to %s on port %d\n", server, port);
	 int sock = create_udp_socket(server, port);
	//  printf("Got socket! %d\n", sock);
	 int send_status = send_comm(sock, request, requestlen);
	 if(send_status != 0){
		//  printf("Error sending request to server.\n");
	 }
	//  printf("Sent Request!\n");
	const int RECEIVE_BUFFER_SIZE = 512;
	return recv_comm(sock, response, RECEIVE_BUFFER_SIZE);
	//  print_bytes(response, 49);
}

char *resolve(char *qname, char *server) {

	unsigned char msg[BUFFER_MAX]; // A buffered char array to hold the query.
	for(int i = 0; i < BUFFER_MAX; i++){
		msg[i] = 0; // Fill with zeroes..
	}
	dns_rr_type type = 0x01;
	int queryLen = create_dns_query(qname, type, msg); // Create the query and get the length.

	printf("Final request length: %d\n", queryLen);
	
	// print_bytes(msg, queryLen); // Diagnostic for printing the request
	unsigned char recv_buffer[512];
	int bytes_read = send_recv_message(msg, queryLen, recv_buffer, server, 53);
	printf("Bytes read from response: %d\n", bytes_read);
	print_bytes(recv_buffer, bytes_read);
	
	// We will need to parse the response and analyze it to grab the final IP.
	char answer_buffer[BUFFER_MAX];
	get_answer_address(qname, type, recv_buffer, answer_buffer);
	printf("resolve\n");
	print_bytes(answer_buffer, 4);
	// printf("ANSWER: %s", answer_buffer);
	char* returnPtr = answer_buffer;
	// return answer_buffer;
	return returnPtr;
	return "Not working yet...";
}

int main(int argc, char *argv[]) {
    srand(time(NULL));
	// ascii name to wire test ************************************
	// char wire[5];
	// char* str = "i.a$";
	// for(int i = 0; i < 5; i++){
	// 	wire[i] = 0;
	// }
	// name_ascii_to_wire(str, wire);
	// printf("Wire: {%x, %x, %x, %x, %x}\n", wire[0], wire[1], wire[2], wire[3], wire[4]);
	// print_bytes(wire, 5);
	// *******************************************************
	
	// ascii name from wire test *********************************
	// char wire[10] = {0, 0, 0x03, 0x64, 0x65, 0x66, 0x01, 0x67, 0x00, 0x00}; // junk then def.g
	// int i = 2;
	// int* ind = &(i);
	// unsigned char nameBuf[512];
	// name_ascii_from_wire(wire, ind, nameBuf);
	// return 1;
	// ***********************************************************

	char *ip;
	if (argc < 3) {
		fprintf(stderr, "Usage: %s <domain name> <server>\n", argv[0]);
		exit(1);
	}
	ip = resolve(argv[1], argv[2]);
	printf("IP: ");
	print_bytes(ip, 4);
	printf("%s => %s\n", argv[1], ip == NULL ? "NONE" : ip);
}
