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
#include <ctype.h>
#include <dirent.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "TcpCheck.h"

int TcpCheckIfClientIsMSS(int localPort)
{
	FILE *fh;

	if ((fh = fopen("/proc/net/tcp", "r")) == NULL)
		perror("Unable to open proc/tcp");
	else
	{
		char line[1024];
		int nbLines = 0;

		while (fgets(line, sizeof(line), fh) != NULL)
		{
			if (TcpCheckTcpLine(nbLines, line, localPort) == 1)
				return 1;
			nbLines++;
		}
		fclose(fh);
	}
	return 0;
}

int TcpCheckTcpLine(int nbLines, char *line, int localPort)
{
	unsigned long rxq, txq, time_len, retr, inode;
	int num, local_port, rem_port, d, state, uid, timer_run, timeout;
	char rem_addr[128], local_addr[128], more[512];

	if (nbLines == 0)
		return 0;
	num = sscanf(line,
						"%d: %64[0-9A-Fa-f]:%X %64[0-9A-Fa-f]:%X %X %lX:%lX %X:%lX %lX %d %d %ld %512s\n",
						&d, local_addr, &local_port, rem_addr, &rem_port, &state,
						&txq, &rxq, &timer_run, &time_len, &retr, &uid, &timeout,
						&inode, more);

	if (num < 11)
		fprintf(stderr, "warning, got bogus tcp line.\n");
	else if (local_port == localPort)
	{
		printf("-> %s\n", line);
		return TcpCheckProccesses(inode);
	}
	return 0;
}

int TcpCheckProccesses(unsigned long searchInode)
{
	char line[LINE_MAX];
	int procFdLen, lNameLen, len;
	char lName[30];
	long inode;
	struct dirent *direProc, *direFd;
	DIR *dirProc = NULL, *dirFd = NULL;
	int isValid = 0;

	if ((dirProc = opendir(PATH_PROC)) == NULL)
		return 0;
	while ((direProc = readdir(dirProc)) != NULL)
	{
		if (direProc->d_type != DT_DIR)
			continue;

		if (isdigit(*direProc->d_name) == 0)
			continue;

		procFdLen = snprintf(line, sizeof(line), PATH_PROC_X_FD, direProc->d_name);
		if (procFdLen <= 0 || procFdLen >= sizeof(line) - 5)
			continue;
		dirFd = opendir(line);
		if (dirFd == NULL)
			continue;
		while ((direFd = readdir(dirFd)))
		{
			if (direFd->d_type != DT_LNK)
				continue;

			len = snprintf(line, sizeof(line), PATH_PROC_X_FD "/%s", direProc->d_name, direFd->d_name);
			if (len <= 0 || len >= sizeof(line))
				continue;
			lNameLen = readlink(line, lName, sizeof(lName) - 1);
			if (lNameLen == -1)
				continue;
			lName[lNameLen] = '\0';
			if (sscanf(lName, "socket:[%ld]", &inode) == 0)
				if (sscanf(lName, "[0000]:%ld", &inode) == 0)
					continue;
			printf("[%s]lname [%s] => inode[%li] // %li\n", line, lName, inode, searchInode);
			if (inode == searchInode)
			{
				len = snprintf(line, sizeof(line), PATH_PROC_X_EXE, direProc->d_name);
				if (len <= 0 || len >= sizeof(line))
					continue;
				printf("Try to readfile: %s\n", line);
				lNameLen = readlink(line, lName, sizeof(lName) - 1);
				if (lNameLen == -1)
					continue;
				lName[lNameLen] = '\0';
				printf("APP: %s [%i]\n", lName, lNameLen);
				if (strcmp(lName, MSS_EXE) == 0)
					isValid = 1;
				goto TcpCheckProccesses_end;
			}
		}
		closedir(dirFd);
		dirFd = NULL;
	}
TcpCheckProccesses_end:
	if (dirProc != NULL)
		closedir(dirProc);
	if (dirFd != NULL)
		closedir(dirFd);
	return isValid;
}
