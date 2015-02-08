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
	int rc = -1;
	int sd = -1;
	int	status = 0;

	serverAddr.sin_family = AF_INET;
	serverAddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	serverAddr.sin_port = htons(PORT);
	memset(&(serverAddr.sin_zero), '\0', 8);
	if ((sd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
	{
		perror("Client-socket() error");
		status = 1;
		goto endMain;
	}
	if ((rc = connect(sd, (struct sockaddr *)&serverAddr, sizeof(serverAddr))) < 0)
	{
		perror("Client-connect() error");
		status = 1;
		goto endMain;
	}
	if (dup2(rc, STDIN_FILENO) == -1)
	{
		perror("Client-dup2-stdin error");
		status = 2;
		goto endMain;
	}
	if (dup2(rc, STDOUT_FILENO) == -1)
	{
		perror("Client-dup2-stdout error");
		status = 2;
		goto endMain;
	}
	if (dup2(rc, STDERR_FILENO) == -1)
	{
		perror("Client-dup2-stderr error");
		status = 2;
		goto endMain;
	}
	while (sleep(3600) == 0)
		;
	fprintf(stderr, "Client-sleep interrupted");
endMain:
	if (rc != -1)
		close(rc);
	if (sd != -1)
		close(sd);
	return status;
}
