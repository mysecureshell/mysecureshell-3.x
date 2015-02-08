#include "../config.h"
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "TcpCheck.h"

int main(int argc, char *argv[])
{
	fd_set master;
	fd_set read_fds;
	struct sockaddr_in serveraddr;
	struct sockaddr_in clientaddr;
	int fdmax;
	int listener;
	int newfd;
	int yes = 1;
	socklen_t addrlen;
	int i, j;

	FD_ZERO(&master);
	FD_ZERO(&read_fds);
	if ((listener = socket(AF_INET, SOCK_STREAM, 0)) == -1)
	{
		perror("Server-socket() error lol!");
		exit(1);
	}
	printf("Server-socket() is OK...\n");
	if (setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1)
	{
		perror("Server-setsockopt() error lol!");
		exit(1);
	}
	printf("Server-setsockopt() is OK...\n");

	serveraddr.sin_family = AF_INET;
	serveraddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	serveraddr.sin_port = htons(PORT);
	memset(&(serveraddr.sin_zero), '\0', 8);
	if (bind(listener, (struct sockaddr *) &serveraddr, sizeof(serveraddr)) == -1)
	{
		perror("Server-bind() error lol!");
		exit(1);
	}
	printf("Server-bind() is OK...\n");
	if (listen(listener, 10) == -1)
	{
		perror("Server-listen() error lol!");
		exit(1);
	}
	printf("Server-listen() is OK...\n");
	FD_SET(listener, &master);
	fdmax = listener;
	for (;;)
	{
		read_fds = master;
		if (select(fdmax + 1, &read_fds, NULL, NULL, NULL) == -1)
		{
			perror("Server-select() error lol!");
			exit(1);
		}
		printf("Server-select() is OK...\n");
		for (i = 0; i <= fdmax; i++)
		{
			if (FD_ISSET(i, &read_fds))
			{
				if (i == listener)
				{
					/* handle new connections */
					addrlen = sizeof(clientaddr);
					if ((newfd = accept(listener, (struct sockaddr *) &clientaddr, &addrlen)) == -1)
						perror("Server-accept() error lol!");
					else
					{
						uid_t	uidClient;

						printf("Server-accept() is OK...\n");
						FD_SET(newfd, &master);
						if (newfd > fdmax)
							fdmax = newfd;
						printf("%s: New connection from %s:%d on socket %d\n",
								argv[0], inet_ntoa(clientaddr.sin_addr),
								ntohs(clientaddr.sin_port), newfd);
						printf(" -> isMSS: %d\n", TcpCheckIfClientIsMSS(ntohs(clientaddr.sin_port), &uidClient));
						printf(" -> uid client: %d\n", uidClient);
					}
				}
				else
				{
					char buf[1024];
					int nbytes;

					if ((nbytes = recv(i, buf, sizeof(buf), 0)) <= 0)
					{
						if (nbytes == 0)
							printf("%s: socket %d hung up\n", argv[0], i);
						else
							perror("recv() error lol!");
						close(i);
						FD_CLR(i, &master);
					}
					else
					{
						for (j = 0; j <= fdmax; j++)
							if (FD_ISSET(j, &master))
								if (j != listener && j != i)
									if (send(j, buf, nbytes, 0) == -1)
										perror("send() error lol!");
					}
				}
			}
		}
	}
	return 0;
}
