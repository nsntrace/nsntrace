#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>

int main(int argc, char **argv)
{
	struct sockaddr_in addr = { 0 };
	int port, num, s;

	if (argc != 3) {
		fprintf(stderr, "usage: udp_send port num_packets\n");
		exit(EXIT_FAILURE);
	}
	port = atoi(argv[1]);
	num = atoi(argv[2]);

	if ((s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
		fprintf(stderr, "failed to create socket\n");
		exit(EXIT_FAILURE);
	}

	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	inet_aton("127.0.0.1", &addr.sin_addr);

	while(num--) {
		char *message = "if not now, when?";
		int ret;

		ret = sendto(s, message, strlen(message), 0,
			     (struct sockaddr *) &addr, sizeof(addr));
		if (ret < 0) {
			fprintf(stderr, "failed to send message\n");
			exit(EXIT_FAILURE);
		}
	}

	return 0;
}
