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
#include <stdlib.h>
#include <unistd.h>

static gid_t *_inGroup = 0;

void AccessInit()
{
	gid_t *groups;
	int nbGroups;

	nbGroups = getgroups(0, NULL);
	if (nbGroups == -1)
		nbGroups = 0;
	else
	{
		_inGroup = malloc((nbGroups + 2) * sizeof(*_inGroup));
		if (nbGroups > 0)
			if (getgroups(nbGroups, _inGroup) == -1)
				nbGroups = 0;
	}
	_inGroup[nbGroups] = getgid();
	_inGroup[nbGroups + 1] = -1;
	free(groups);
}

void AccessFree()
{
	free(_inGroup);
	_inGroup = NULL;
}

int	AccessUserIsInThisGroup(gid_t grp)
{
	int i;

	if (_inGroup != NULL)
		for (i = 0; _inGroup[i] != -1; i++)
			if (_inGroup[i] == grp)
				return 1;
	return 0;
}
