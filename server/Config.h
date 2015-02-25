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

#ifndef _CONFIG_H_
#define _CONFIG_H_

int	init_user_info();
int	ConfigIsForUser(const char *user, int verbose);
int	ConfigIsForGroup(const char *group, int verbose);
int	ConfigIsForRangeIP(const char *range, int verbose);
int	ConfigIsForVirtualhost(const char *host, int port, int verbose);
void	free_user_info();

void ConfigLoad(int verbose);
int ConfigLoadFile(const char *file, int verbose, int maxRecursiveLeft);
int ConfigConvertModeToInt(const char *str);
int ConfigConvertBooleanToInt(const char *str);
int ConfigConvertSpeedToInt(char **tb);
int ConfigConvertTimeToInt(char **tb);
void ConfigProcessLine(char **tb, int maxRecursiveLeft, int verbose);
char *ConfigConvertStrWithResolvEnvToStr(const char *str);
char *ConfigConvertToPath(char *path);

#endif //_CONFIG_H_
