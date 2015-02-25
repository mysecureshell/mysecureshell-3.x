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
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include "CFixes.h"

void xClose(int fd)
{
	while (close(fd) == -1)
		if (errno != EINTR)
			break;
}

void xDup2(int oldFd, int newFd)
{
	while (dup2(oldFd, newFd) == -1)
		if (errno != EINTR)
			break;
}

void xFclose(FILE *fp)
{
	while (fclose(fp) == -1)
		if (errno != EINTR)
			break;
}

void xDeleteComments(char *buffer)
{
	char c;

	while (*buffer != '\0')
	{
		if (*buffer == '\'' || *buffer == '"')
		{
			c = *buffer;
			buffer++;
			while (*buffer != '\0' && *buffer != c)
				buffer++;
		}
		else if (*buffer == '\\')
			buffer++;
		else if (*buffer == '#')
		{
			*buffer = '\0';
			return;
		}
		buffer++;
	}
}

char *xTrimAndCleanComments(char *buffer)
{
	xDeleteComments(buffer);
	buffer = xTrimRight(xTrimLeft(buffer));
	if (buffer[0] != '\0')
		return (buffer);
	return (NULL);
}

char *xTrimRight(char *buffer)
{
	size_t i;

	i = strlen(buffer);
	if (i == 0)
		return (buffer);
	do
	{
		i--;
		if (buffer[i] > '\0' && buffer[i] <= ' ')
			buffer[i] = '\0';
		else
			break;
	}
	while (i > 0);
	return (buffer);
}

char *xTrimLeft(char *buffer)
{
	while (*buffer == ' ' || *buffer == '\t')
		buffer++;
	return (buffer);
}

char *xClean(char *buffer)
{
	size_t i, max;
	char c;

	buffer = xTrimLeft(xTrimRight(buffer));
	for (i = 0, max = strlen(buffer); i < max; i++)
	{
		if (buffer[i] == '"' || buffer[i] == '\'')
		{
			c = buffer[i];
			xStrCopy(buffer + i, buffer + i + 1, max - i);
			while (c != buffer[i] && i < max)
				i++;
			if (c == buffer[i])
				xStrCopy(buffer + i, buffer + i + 1, max - i);
		}
		else if (buffer[i] == '\\')
			xStrCopy(buffer + i, buffer + i + 1, max - i);
	}
	return (buffer);
}

void xStrCopy(char *dest, char *src, size_t length)
{
	while (length--)
		*dest++ = *src++;
}
