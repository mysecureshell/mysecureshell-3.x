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

#ifndef _GETUSERSINFOS_H_
#define _GETUSERSINFOS_H_

typedef struct sInfo
{
	u_int32_t id;
	char *name;
} tInfo;

void free_usersinfos();
tInfo *mygetpwuid(u_int32_t uid);
tInfo *mygetpwnam(const char *login);
tInfo *mygetgrgid(u_int32_t gid);
tInfo *mygetgrnam(const char *group);

#endif //_GETUSERSINFOS_H_
