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
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "CFixes.h"
#include "Log.h"
#include "Sftp.h"
#include "TcpCheck.h"

static void deadChild(int signal)
{
	pid_t ret;
	int status;

	do
	{
		ret = waitpid(-1, &status, WNOHANG);
		printf("Child has died: pid=%i status=%i\n", ret, status);
	}
	while (ret > 0);
}

static void launchSftpClient(int serverFd, int clientFd, uid_t clientUid)
{
	int ret;

	ret = fork();
	if (ret == -1)
		perror("fork error lol!");
	else if (ret == 0)
	{
		tGlobal	*params;

		printf("[pid:%i-child]Socket-server: %i\n", getpid(), serverFd);
		xClose(serverFd);
		params = calloc(1, sizeof(*params));
		params->home = strdup("/home/test");
		params->who = calloc(1, sizeof(*params->who));
		_sftpglobal = calloc(1, sizeof(*_sftpglobal));

		mylog_open(strdup("/tmp/sftp3.x.log"), 0);
		SftpMain(params, 3, clientFd);
		printf("[pid:%i-child]END CLIENT\n", getpid());
		exit(0);
	}
	else
	{
		printf("[pid:%i-parent]Socket-client: %i\n", getpid(), clientFd);
		xClose(clientFd);
	}
}

int main(int argc, char *argv[])
{
	fd_set master;
	fd_set readFds;
	struct sockaddr_in serveraddr;
	struct sockaddr_in clientaddr;
	int listener;
	int newFd;
	int yes = 1;
	socklen_t addrlen;

	signal(SIGCHLD, deadChild);
	FD_ZERO(&master);
	FD_ZERO(&readFds);
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
	for (;;)
	{
		readFds = master;
		if (select(listener + 1, &readFds, NULL, NULL, NULL) == -1)
		{
			if (errno == EINTR)
				continue;
			perror("Server-select() error lol!");
			exit(1);
		}
		printf("Server-select() is OK...\n");
		if (FD_ISSET(listener, &readFds))
		{
			addrlen = sizeof(clientaddr);
			if ((newFd = accept(listener, (struct sockaddr *) &clientaddr, &addrlen)) == -1)
				perror("Server-accept() error lol!");
			else
			{
				uid_t uidClient;
				int isMSS;

				printf("Server-accept() is OK...\n");
				printf("%s: New connection from %s:%d on socket %d\n",
						argv[0], inet_ntoa(clientaddr.sin_addr),
						ntohs(clientaddr.sin_port), newFd);
				isMSS = TcpCheckIfClientIsMSS(ntohs(clientaddr.sin_port), &uidClient);
				printf(" -> isMSS: %d\n", isMSS);
				printf(" -> uid client: %d\n", uidClient);
				launchSftpClient(listener, newFd, uidClient);
			}
		}
	}
	return 0;
}
