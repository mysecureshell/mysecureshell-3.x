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

#ifndef _CFIXES_H_
#define _CFIXES_H_

#include <stdio.h>

void xClose(int fd);
void xDup2(int oldFd, int newFd);
void xFclose(FILE *fp);

void xDeleteComments(char *buffer);
char *xTrimAndCleanComments(char *buffer);
char *xClean(char *buffer);
char *xTrimRight(char *buffer);
char *xTrimLeft(char *buffer);
void xStrCopy(char *dest, char *src, size_t length);

#ifdef HAVE_STRLCAT
#define STRCAT(_DST, _SRC, _LEN) strlcat(_DST, _SRC, _LEN)
#else
#define STRCAT(_DST, _SRC, _LEN) strcat(_DST, _SRC)
#endif

#ifdef HAVE_STRLCPY
#define STRCPY(_DST, _SRC, _LEN) strlcpy(_DST, _SRC, _LEN)
#else
#define STRCPY(_DST, _SRC, _LEN) strcpy(_DST, _SRC)
#endif

#endif //_CFIXES_H_
