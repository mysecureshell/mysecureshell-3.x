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
#include "../server/Hash.h"

static void showVersion(int showAll)
{
	(void) printf(
			"MySecureShell is version "PACKAGE_VERSION" build on " __DATE__ "%s",
#ifdef DODEBUG
			" with DEBUG"
#else
			""
#endif
	);
	if (showAll == 1)
	{
		(void) printf("\n\nOptions:\n  ACL support: "
#if(MSS_ACL)
					"yes"
#else
				"no"
#endif
				"\n  UTF-8 support: "
#if(HAVE_ICONV||HAVE_LIBICONV)
				"yes"
#else
				"no"
#endif
				"\n\nSftp Extensions:\n"
#ifdef MSSEXT_DISKUSAGE
				"  Disk Usage\n"
#endif
#ifdef MSSEXT_DISKUSAGE_SSH
				"  Disk Usage (OpenSSH)\n"
#endif
#ifdef MSSEXT_FILE_HASHING
				"  File Hashing\n"
#endif
		);
	}
}

static void ParseArgs(int ac, char **av)
{
	int verbose = 1;
	int i;

	if (ac == 1)
		return;
	for (i = 1; i < ac; i++)
		if (strcmp(av[i], "-c") == 0)
			i++;
		else if (strcmp(av[i], "--configtest") == 0)
		{
			ConfigLoad(verbose);
			if (HashGet("ApplyFileSpec") != NULL)
				FileSpecActiveProfils(HashGet("ApplyFileSpec"), verbose);
			(void) printf("Config is valid.\n");
			exit(0);
		}
		else if (strcmp(av[i], "--help") == 0)
		{
			help: (void) printf("Build:\n\t");
			showVersion(0);
			(void) printf("\nUsage:\n\t%s [verbose] [options]\n\nOptions:\n",
					av[0]);
			(void) printf(
					"\t--configtest : test the config file and show errors\n");
			(void) printf("\t--help       : show this screen\n");
			(void) printf("\t--version    : show version of MySecureShell\n");
			(void) printf("\nVerbose:\n");
			(void) printf("\t-v           : add a level at verbose mode\n");
			exit(0);
		}
		else if (strcmp(av[i], "--version") == 0)
		{
			showVersion(1);
			exit(0);
		}
		else if (strcmp(av[i], "-v") == 0)
			verbose++;
		else
		{
			(void) printf("--- UNKNOW OPTION: %s ---\n\n", av[i]);
			goto help;
		}
}

int main(int ac, char **av, char **env)
{
	int isCommand = 0;
	int isSftp = 0;
	int	status = 0;

	if (ac == 3 && av[1] != NULL && av[2] != NULL
			&& strcmp("-c", av[1]) == 0
				&& (strstr(av[2], "sftp-server") != NULL || strstr(av[2], "MySecureShell") != NULL))
		isSftp = 1;
	else if (ac >= 3 && av[1] != NULL && av[2] != NULL && strcmp("-c", av[1]) == 0)
		isCommand = 1;
	else
		ParseArgs(ac, av);

	if (isSftp == 1)
	{
		struct sockaddr_in serverAddr;
		fd_set fds;
		int socketFd = -1;

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
	}
	else
	{
		char *ptr;

		if (getuid() != geteuid())
		//if we are in utset byte mode then we restore user's rights to avoid security problems
		{
			if (seteuid(getuid()) == -1 || setegid(getgid()) == -1)
			{
				perror("revoke root rights");
				exit(1);
			}
		}
		ptr = HashGet("Shell");
		if (ptr != NULL)
		{
			if (strcmp(ptr, av[0]) != 0)
			{
				av[0] = ptr;
				if (isCommand == 1)
				{
					size_t	len = 0;
					char	**newEnv;
					char	*cmd, *envVar;
					int		i;

					for (i = 2; i < ac; i++)
						len += strlen(av[i]);
					cmd = malloc(len + ac + 1);
					envVar = malloc(len + ac + 1 + 21);
					cmd[0] = '\0';
					for (i = 2; i < ac; i++)
					{
						if (i > 2)
							strcat(cmd, " ");
						strcat(cmd, av[i]);
					}
					av[2] = cmd;
					av[3] = NULL;
					strcpy(envVar, "SSH_ORIGINAL_COMMAND=");
					strcat(envVar, cmd);
					len = 0;
					for (i = 0; env[i] != NULL; i++)
						len++;
					newEnv = calloc(len + 2, sizeof(*newEnv));
					for (i = 0; i < len; i++)
						newEnv[i] = env[i];
					newEnv[len] = envVar;
					(void) execve(av[0], av, newEnv);
				}
				else
					(void) execve(av[0], av, env);
				perror("execute shell");
			}
			else
				(void) fprintf(stderr, "You cannot specify MySecureShell has shell (in the MySecureShell configuration) !");
		}
		else
			(void) fprintf(stderr, "Shell access is disabled !");
		exit(1);
	}
	return status;
}
