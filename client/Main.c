/*
MySecureShell permit to add restriction to modified sftp-server
when using MySecureShell as shell.
Copyright (C) 2007 Sebastien Tardif

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation (version 2)

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
*/

#include "../config.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

int main(int ac, char **av)
{
	struct sockaddr_in serverAddr;
	fd_set fds;
	int socketFd = -1;
	int	status = 0;

	serverAddr.sin_family = AF_INET;
	serverAddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	serverAddr.sin_port = htons(PORT);
	memset(&(serverAddr.sin_zero), '\0', 8);
	if ((socketFd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
	{
		perror("Unable to open socket");
		status = 1;
	}
	else if ((status = connect(socketFd, (struct sockaddr *)&serverAddr, sizeof(serverAddr))) < 0)
	{
		perror("Unable to connect socket");
		status = 1;
	}
	else
	{
		for (;;)
		{
			FD_ZERO(&fds);
			FD_SET(STDIN_FILENO, &fds);
			FD_SET(socketFd, &fds);
			status = select(socketFd + 1, &fds, NULL, NULL, NULL);
			if (status == -1)
				break;
			if (FD_ISSET(STDIN_FILENO, &fds))
			{
				char data[4096];
				ssize_t dataSize;

				dataSize = read(STDIN_FILENO, &data, sizeof(data));
				if (dataSize > 0)
					dataSize = write(socketFd, &data, dataSize);
				else if (dataSize == 0)
					break;
			}
			if (FD_ISSET(socketFd, &fds))
			{
				char data[4096];
				ssize_t dataSize;

				dataSize = read(socketFd, &data, sizeof(data));
				if (dataSize > 0)
					dataSize = write(STDOUT_FILENO, &data, dataSize);
				else if (dataSize == 0)
					break;
			}
		}
	}
	if (socketFd != -1)
		close(socketFd);
	return status;
}
