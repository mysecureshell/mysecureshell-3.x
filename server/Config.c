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

#include "../config.h"
#include <errno.h>
#include <sys/types.h>
#include <grp.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "Access.h"
#include "CFixes.h"
#include "Config.h"
#include "FileSpec.h"
#include "Ip.h"
#include "Tag.h"

static char *user_name = NULL;

#define CONF_IS_EMPTY				0
#define CONF_IS_STRING				1
#define CONF_IS_STRING_MAYBE_EMPTY	2
#define CONF_IS_PATH_RESOLVE_ENV	3
#define CONF_IS_INT					4
#define CONF_IS_BOOLEAN				5
#define CONF_IS_SPEED				6
#define CONF_IS_MODE				7
#define CONF_IS_TIME				8
#define CONF_IS_FILE_AND_DIR		9
#define CONF_DEPRECATED				10

#define CONF_SHOW			0
#define CONF_SHOW_ALWAYS	1
#define CONF_NOT_SHOW		2

typedef struct sConf
{
	char *name;
	int type;
	int show;
} tConf;

static const tConf confParams[] =
{
	{ "GlobalDownload", CONF_IS_SPEED, CONF_SHOW },
	{ "GlobalUpload", CONF_IS_SPEED, CONF_SHOW },
	{ "Download", CONF_IS_SPEED, CONF_SHOW },
	{ "Upload", CONF_IS_SPEED, CONF_SHOW },
	{ "StayAtHome", CONF_IS_BOOLEAN, CONF_SHOW },
	{ "VirtualChroot", CONF_IS_BOOLEAN, CONF_SHOW },
	{ "LimitConnection", CONF_IS_INT, CONF_SHOW },
	{ "LimitConnectionByUser", CONF_IS_INT, CONF_SHOW },
	{ "LimitConnectionByIP", CONF_IS_INT, CONF_SHOW },
	{ "Home", CONF_IS_PATH_RESOLVE_ENV, CONF_SHOW },
	{ "Shell", CONF_IS_STRING, CONF_SHOW },
	{ "ResolveIP", CONF_IS_BOOLEAN, CONF_SHOW },
	{ "IdleTimeOut", CONF_IS_TIME, CONF_SHOW },
	{ "IgnoreHidden", CONF_IS_BOOLEAN, CONF_SHOW },
	{ "DirFakeUser", CONF_IS_BOOLEAN, CONF_SHOW },
	{ "DirFakeGroup", CONF_IS_BOOLEAN, CONF_SHOW },
	{ "DirFakeMode", CONF_IS_MODE, CONF_SHOW },
	{ "HideNoAccess", CONF_IS_BOOLEAN, CONF_SHOW },
	{ "ByPassGlobalDownload", CONF_IS_BOOLEAN, CONF_SHOW },
	{ "ByPassGlobalUpload", CONF_IS_BOOLEAN, CONF_SHOW },
	{ "MaxOpenFilesForUser", CONF_IS_INT, CONF_SHOW },
	{ "MaxReadFilesForUser", CONF_IS_INT, CONF_SHOW },
	{ "MaxWriteFilesForUser", CONF_IS_INT, CONF_SHOW },
	{ "ShowLinksAsLinks", CONF_IS_BOOLEAN, CONF_SHOW },
	{ "SftpProtocol", CONF_IS_INT, CONF_SHOW_ALWAYS },
	{ "LogFile", CONF_IS_STRING, CONF_SHOW_ALWAYS },
	{ "LogSyslog", CONF_IS_BOOLEAN, CONF_SHOW },
	{ "ConnectionMaxLife", CONF_IS_TIME, CONF_SHOW },
	{ "DisableAccount", CONF_IS_BOOLEAN, CONF_SHOW },
#ifdef MSS_HAVE_ADMIN
	{ "IsAdmin", CONF_IS_BOOLEAN, CONF_SHOW },
	{ "IsSimpleAdmin", CONF_IS_BOOLEAN, CONF_SHOW },
#endif
	{ "DisableRemoveDir", CONF_IS_BOOLEAN, CONF_SHOW },
	{ "DisableRemoveFile", CONF_IS_BOOLEAN, CONF_SHOW },
	{ "DisableReadFile", CONF_IS_BOOLEAN, CONF_SHOW },
	{ "DisableReadDir", CONF_IS_BOOLEAN, CONF_SHOW },
	{ "DisableWriteFile", CONF_IS_BOOLEAN, CONF_SHOW },
	{ "DisableSetAttribute", CONF_IS_BOOLEAN, CONF_SHOW },
	{ "DisableMakeDir", CONF_IS_BOOLEAN, CONF_SHOW },
	{ "DisableRename", CONF_IS_BOOLEAN, CONF_SHOW },
	{ "DisableSymLink", CONF_IS_BOOLEAN, CONF_SHOW },
	{ "DisableOverwrite", CONF_IS_BOOLEAN, CONF_SHOW },
	{ "DisableStatsFs", CONF_IS_BOOLEAN, CONF_SHOW },
	{ "Charset", CONF_IS_STRING, CONF_SHOW },
	{ "CanChangeRights", CONF_IS_BOOLEAN, CONF_SHOW },
	{ "CanChangeTime", CONF_IS_BOOLEAN, CONF_SHOW },
	{ "ExpireDate", CONF_IS_STRING_MAYBE_EMPTY, CONF_SHOW },
	{ "ForceUser", CONF_IS_STRING, CONF_SHOW },
	{ "ForceGroup", CONF_IS_STRING, CONF_SHOW },
	{ "CreateHome", CONF_IS_BOOLEAN, CONF_SHOW },
	{ "DefaultRights", CONF_IS_FILE_AND_DIR, CONF_SHOW },
	{ "MinimumRights", CONF_IS_FILE_AND_DIR, CONF_SHOW },
	{ "MaximumRights", CONF_IS_FILE_AND_DIR, CONF_SHOW },
	{ "ForceRights", CONF_IS_FILE_AND_DIR, CONF_SHOW },
	{ "ApplyFileSpec", CONF_IS_STRING, CONF_SHOW_ALWAYS },

	{ "CanRemoveDir", CONF_DEPRECATED, CONF_SHOW },
	{ "CanRemoveFile", CONF_DEPRECATED, CONF_SHOW },
	{ "GMTTime", CONF_DEPRECATED, CONF_NOT_SHOW },
	{ "HideFiles", CONF_DEPRECATED, CONF_SHOW },
	{ "PathAllowFilter", CONF_DEPRECATED, CONF_SHOW },
	{ "PathDenyFilter", CONF_DEPRECATED, CONF_SHOW },
	{ "{last item}", CONF_IS_EMPTY, CONF_NOT_SHOW }
};

void ConfigLoad(int verbose)
{
	if (init_user_info() == 0)
	{
		(void) fprintf(stderr, "[ERROR]Error when fetching user information\n");
		exit(2);
	}
	HashSetInt("SERVER_PORT", IpGetServerPort());
	HashSet("SERVER_IP", IpGetServer());
	HashSetInt("CanChangeRights", 1);
	HashSetInt("CanChangeTime", 1);
	if (ConfigLoadFile(CONFIG_FILE, verbose, 10) == 0)
		if (ConfigLoadFile(CONFIG_FILE2, verbose, 10) == 0)
		{
			(void) fprintf(stderr,
					"[ERROR]No valid config file were found. Please correct this.\n");
			exit(2);
		}
	free_user_info();
	if (verbose > 0)
	{
		size_t maxLen;
		char bTmp[256];
		int i, r;

		(void) printf("--- %s ---\n", (char *) HashGet("User"));
		for (i = 0, maxLen = 0; confParams[i].type != CONF_IS_EMPTY; i++)
		{
			size_t len = strlen(confParams[i].name);

			if (len > maxLen)
				maxLen = len;
		}
		for (i = 0; confParams[i].type != CONF_IS_EMPTY; i++)
		{
			size_t j;
			char *ptr;
			int vInt;

			if (confParams[i].show != CONF_SHOW_ALWAYS && HashKeyExists(
					confParams[i].name) == 0)
				continue;
			(void) printf("%s", confParams[i].name);
			for (j = maxLen - strlen(confParams[i].name) + 1; j > 0; j--)
				(void) printf(" ");
			(void) printf("= ");
			switch (confParams[i].type)
			{
			case CONF_IS_STRING:
			case CONF_IS_PATH_RESOLVE_ENV:
				ptr = (char *) HashGet(confParams[i].name);
				if (ptr == NULL && confParams[i].show == CONF_SHOW_ALWAYS)
					(void) printf("{default}");
				else
					(void) printf("%s", ptr);
				break;
			case CONF_IS_STRING_MAYBE_EMPTY:
				ptr = (char *) HashGet(confParams[i].name);
				(void) printf("%s", ptr != NULL ? ptr : "{nothing}");
				break;
			case CONF_IS_INT:
				vInt = HashGetInt(confParams[i].name);
				if (vInt == 0 && confParams[i].show == CONF_SHOW_ALWAYS)
					(void) printf("{default}");
				else
					(void) printf("%i", vInt);
				break;
			case CONF_IS_BOOLEAN:
				(void) printf("%s",
						HashGetInt(confParams[i].name) == 0 ? "false" : "true");
				break;
			case CONF_IS_SPEED:
				(void) printf("%i bytes/s", HashGetInt(confParams[i].name));
				break;
			case CONF_IS_MODE:
				vInt = HashGetInt(confParams[i].name);
				if (vInt == 0)
					(void) printf("{default}");
				else
					(void) printf("%i", vInt);
				break;
			case CONF_IS_TIME:
				(void) printf("%is", HashGetInt(confParams[i].name));
				break;
			case CONF_IS_FILE_AND_DIR:
				(void) snprintf(bTmp, sizeof(bTmp), "%sFile", confParams[i].name);
				r = HashGetInt(bTmp);
				(void) printf("%i%i%i%i", r / (8 * 8 * 8), (r / (8 * 8)) % 8,
						(r / 8) % 8, r % 8);
				(void) snprintf(bTmp, sizeof(bTmp), "%sDirectory", confParams[i].name);
				r = HashGetInt(bTmp);
				if (r > 0)
				{
					(void) printf(" %i%i%i%i", r / (8 * 8 * 8), (r / (8 * 8)) % 8, (r / 8) % 8, r % 8);
				}
				break;
			case CONF_DEPRECATED:
				(void) printf("%s is deprecated and unused", confParams[i].name);
				break;
			}
			(void) printf("\n");
		}
	}
}

int ConfigLoadFile(const char *file, int verbose, int max_recursive_left)
{
	size_t len;
	FILE *fh;
	char buffer[1024];
	char **tb, *str;
	int line, processTag;
	int openedTag = 0;

	if (max_recursive_left == 0)
	{
		(void) fprintf(stderr, "[ERROR]Too much inclusions !!!\n");
		return (0);
	}
	processTag = 1;
	if ((fh = fopen(file, "r")))
	{
		if (verbose > 1)
			(void) printf("- Parse config file: %s -\n", file);
		line = 0;
		while (fgets(buffer, (int) sizeof(buffer), fh))
		{
			line++;
			if ((str = xTrimAndCleanComments(buffer)))
			{
				len = strlen(str) - 1;
				if (*str == '<')
				{
					if (str[len] == '>')
					{
						openedTag += TagParse(str);
						if (openedTag < 0)
						{
							(void) fprintf(
									stderr,
									"[ERROR]Too much tag closed at line %i in file '%s'!\n",
									line, file);
							exit(2);
						}
					}
					else
					{
						(void) fprintf(
								stderr,
								"[ERROR]Error parsing line %i is not valid in file '%s'!\n",
								line, file);
						exit(2);
					}
					processTag = TagIsActive(verbose);
				}
				else if (processTag == 0)
					continue;
				else if ((tb = ParseCutString(str)))
				{
					if (tb[0] != NULL)
					{
						if (TagIsOpen(VTAG_FILESPEC) == 1)
							FileSpecParse(tb);
						else
							ConfigProcessLine(tb, max_recursive_left, verbose);
					}
					free(tb);
				}
			}
		}
		if (openedTag != 0)
		{
			(void) fprintf(stderr,
					"[ERROR]Missing %i close(s) tag(s) in file '%s'!!!\n",
					openedTag, file);
			exit(2);
		}
		xFclose(fh);
	}
	else
	{
		(void) fprintf(stderr,
				"[ERROR]Couldn't load config file '%s'. Error : %s\n", file,
				strerror(errno));
		return (0);
	}
	return (1);
}

void ConfigProcessLine(char **tb, int max_recursive_left, int verbose)
{
	char bTmp[256];
	int notRecognized;
	int i;

	notRecognized = 1;
	for (i = 0; confParams[i].type != CONF_IS_EMPTY; i++)
		if (strcmp(tb[0], confParams[i].name) == 0 && (tb[1] != NULL
				|| confParams[i].type == CONF_IS_STRING_MAYBE_EMPTY))
		{
			notRecognized = 0;
			switch (confParams[i].type)
			{
			case CONF_IS_STRING:
				HashSet(tb[0], (void *) strdup(tb[1]));
				break;
			case CONF_IS_STRING_MAYBE_EMPTY:
				HashSet(tb[0], (void *) (tb[1] ? strdup(tb[1]) : 0));
				break;
			case CONF_IS_PATH_RESOLVE_ENV:
			{
				char *path = ConfigConvertStrWithResolvEnvToStr(tb[1]);

				if (path != NULL)
					HashSet(tb[0], (void *) ConfigConvertToPath(path));
			}
				break;
			case CONF_IS_INT:
				HashSetInt(tb[0], atoi(tb[1]));
				break;
			case CONF_IS_BOOLEAN:
				HashSetInt(tb[0], ConfigConvertBooleanToInt(tb[1]));
				break;
			case CONF_IS_SPEED:
				HashSetInt(tb[0], ConfigConvertSpeedToInt(tb + 1));
				break;
			case CONF_IS_MODE:
				HashSetInt(tb[0], ConfigConvertModeToInt(tb[1]));
				break;
			case CONF_IS_TIME:
				HashSetInt(tb[0], ConfigConvertTimeToInt(tb + 1));
				break;
			case CONF_IS_FILE_AND_DIR:
				HashSetInt(tb[0], 42);
				(void) snprintf(bTmp, sizeof(bTmp), "%sFile", tb[0]);
				HashSetInt(bTmp, ConfigConvertModeToInt(tb[1]));
				if (tb[2] != NULL)
				{
					(void) snprintf(bTmp, sizeof(bTmp), "%sDirectory", tb[0]);
					HashSetInt(bTmp, ConfigConvertModeToInt(tb[2]));
				}
				break;
			}
			break;
		}
	if (notRecognized == 1)
	{
		if (strcmp(tb[0], "Include") == 0 && tb[1] != NULL)
		{
			notRecognized = 0;
			(void) ConfigLoadFile(tb[1], verbose, max_recursive_left - 1);
		}
		if (notRecognized == 1)
			(void) fprintf(stderr, "Property '%s' is not recognized !\n", tb[0]);
	}
}

char *ConfigConvertToPath(char *path)
{
	size_t len = strlen(path);

	if (len > 0)
	{
		if (path[len - 1] == '/' || path[len - 1] == '\\')
			path[len - 1] = '\0';
	}
	return (path);
}

char *ConfigConvertStrWithResolvEnvToStr(const char *str)
{
	size_t beg, end, i, max;
	char *env_var, *env_str, *new, *res;

	if ((res = strdup(str)) == NULL)
		return NULL;
	max = strlen(res);
	for (i = 0; i < max; i++)
		if (res[i] == '$')
		{
			int firstIsBlock = 0;

			beg = i + 1;
			if (res[beg] == '{')
			{
				firstIsBlock = 1;
				i++;
			}
			while (i < max)
			{
				i++;
				if (!((res[i] >= 'a' && res[i] <= 'z') || (res[i] >= 'A'
						&& res[i] <= 'Z') || (res[i] >= '0' && res[i] <= '9')
						|| (res[i] == '_')))
					break;
			}
			end = i;
			env_str = malloc(end - beg + 1);
			if (env_str != NULL)
			{
				strncpy(env_str, res + beg + firstIsBlock, end - beg - firstIsBlock);
				env_str[end - beg - firstIsBlock] = '\0';
				if (firstIsBlock == 1 && (end + 1) <= max)
					end++;
				if ((env_var = getenv(env_str)))
				{
					size_t len;

					len = strlen(res) - (end - beg) + strlen(env_var) + 1;
					new = malloc(len);
					if (new != NULL)
					{
						strncpy(new, res, beg - 1);
						new[beg - 1] = '\0';
						STRCAT(new, env_var, len);
						STRCAT(new, res + end, len);
						free(res);
						res = new;
						i = 0;
						max = len - 1;
					}
				}
				free(env_str);
			}
		}
	return (res);
}

int ConfigConvertBooleanToInt(const char *str)
{
	if (str)
		if (strcasecmp(str, "true") == 0 || strcmp(str, "1") == 0)
			return (1);
	return (0);
}

int ConfigConvertSpeedToInt(char **tb)
{
	const char *str;
	int nb = 0;
	int div = 0;
	int i, j;
	int *ptr = &nb;
	int len = 1;

	for (j = 0; tb[j]; j++)
	{
		str = tb[j];
		for (i = 0; str[i] != '\0'; i++)
		{
			if (str[i] >= '0' && str[i] <= '9')
			{
				*ptr = *ptr * 10 + ((int) str[i] - (int) '0');
				len *= 10;
			}
			else
				switch (str[i])
				{
				case 'k':
				case 'K':
					return (nb * 1024 + div * (1024 / len));

				case 'm':
				case 'M':
					return (nb * 1024 * 1024 + div * ((1024 * 1024) / len));

				case '.':
					ptr = &div;
					len = 1;
					break;
				}
		}
	}
	return (nb);
}

int ConfigConvertTimeToInt(char **tb)
{
	int nb = 0;
	int i, j;

	for (j = 0; tb[j]; j++)
	{
		const char *str = tb[j];

		for (i = 0; str[i] != '\0'; i++)
		{
			if (str[i] >= '0' && str[i] <= '9')
				nb = nb * 10 + ((int) str[i] - (int) '0');
			else
				switch (str[i])
				{
				case 'd':
				case 'D':
					nb *= 24;
				case 'h':
				case 'H':
					nb *= 60;
				case 'm':
				case 'M':
					nb *= 60;
					break;
				}
		}
	}
	return (nb);
}

int ConfigConvertModeToInt(const char *str)
{
	int i;
	int r;

	r = 0;
	for (i = 0; str[i] != '\0'; i++)
		r = (r * 8) + ((int) str[i] - (int) '0');
	return (r);
}

int init_user_info()
{
	struct passwd *info;

	AccessInit();
	if ((info = getpwuid(getuid())))
	{
		if ((user_name = strdup(info->pw_name)) == NULL)
			return (0);
		HashSet("User", (void *) strdup(info->pw_name));
		HashSet("Home", (void *) strdup(info->pw_dir));
		return (1);
	}
	return (0);
}

void free_user_info()
{
	if (user_name != NULL)
		free(user_name);
	user_name = NULL;
}

int ConfigIsForUser(const char *user, int verbose)
{
	if (user == NULL)
		return (0);
	if (strcmp(user, TAG_ALL) == 0)
	{
		if (verbose >= 2)
			(void) printf("--- Apply restrictions for all users ---\n");
		return (1);
	}
	if (user_name != NULL && strcmp(user, user_name) == 0)
	{
		if (verbose >= 2)
			(void) printf("--- Apply restrictions for user '%s' ---\n", user);
		return (1);
	}
	return (0);
}

int ConfigIsForGroup(const char *group, int verbose)
{
	struct group *grp;

	if (strcmp(group, TAG_ALL) == 0)
	{
		if (verbose >= 2)
			(void) printf("--- Apply restrictions for all groups ---\n");
		return (1);
	}
	if ((grp = getgrnam(group)) != NULL)
		if (AccessUserIsInThisGroup(grp->gr_gid) == 1)
		{
			if (verbose >= 2)
				(void) printf("--- Apply restrictions for group '%s' ---\n",
						group);
			return (1);
		}
	return (0);
}

int ConfigIsForVirtualhost(const char *host, int port, int verbose)
{
	char *current_host;
	int current_port;

	current_host = (char *) HashGet("SERVER_IP");
	current_port = HashGetInt("SERVER_PORT");
	if (current_host != NULL && host != NULL && (strcmp(host, current_host)
			== 0 || strcmp(host, TAG_ALL) == 0))
		if (current_port == 0 || port == current_port)
		{
			if (verbose >= 2)
				(void) printf(
						"--- Apply restriction for virtualhost '%s:%i' ---\n",
						current_host, current_port);
			return (1);
		}
	return (0);
}

int ConfigIsForRangeIP(const char *range, int verbose)
{
	char *bip, *ip;
	int pos, size, retValue = 0;

	if (range == NULL)
		return (0);
	size = (int) ((unsigned char) range[8]);
	ip = IpGetClient(0); //don't resolv dns
	if (ip == NULL)
		return (0);
	bip = TagParseRangeIP(ip);
	if (bip == NULL)
		return (0);
	pos = 0;
	while (size >= 8)
	{
		if (range[pos] <= bip[pos] && bip[pos] <= range[pos + 4])
		{
			pos++;
			size -= 8;
		}
		else
			goto error_is_for_rangeip;
	}
	if (size > 0)
	{
		bip[pos] = (unsigned char) bip[pos] >> (8 - size);
		bip[pos] = (unsigned char) bip[pos] << (8 - size);
		if (range[pos] > bip[pos] || bip[pos] > range[pos + 4])
			goto error_is_for_rangeip;
	}
	if (verbose >= 2)
		(void) printf(
				"--- Apply restrictions for ip range '%i.%i.%i.%i-%i.%i.%i.%i/%i' ---\n",
				(unsigned char) range[0], (unsigned char) range[1],
				(unsigned char) range[2], (unsigned char) range[3],
				(unsigned char) range[4], (unsigned char) range[5],
				(unsigned char) range[6], (unsigned char) range[7],
				(unsigned char) range[8]);
	retValue = 1;

error_is_for_rangeip:
	free(bip);
	free(ip);
	return (retValue);
}
