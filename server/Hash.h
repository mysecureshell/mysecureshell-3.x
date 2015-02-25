/*
MySecureShell permit to add restriction to modified sftp-server
when using MySecureShell as shell.
Copyright (C) 2007-2014 MySecureShell Team

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

#ifndef _HASH_H_
#define _HASH_H_

#define MSS_HASH_SIZE	256

typedef struct s_element
{
	char *key;
	char *str;
	int number;
	struct s_element *next;
} t_element;

typedef struct s_hash
{
	t_element *hash[MSS_HASH_SIZE];
} t_hash;

void HashInit();
void HashDelete();
int HashKeyExists(const char *key);
char *HashGet(const char *key);
int HashGetInt(const char *key);
void HashSet(const char *key, char *value);
void HashSetInt(const char *key, int value);

#endif //_HASH_H_
