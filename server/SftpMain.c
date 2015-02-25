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
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include "CFixes.h"
#include "Config.h"
#include "Encoding.h"
#include "FileSpec.h"
#include "Hash.h"
#include "Ip.h"
#include "Log.h"
#include "Sftp.h"

int SftpMain(int clientFd)
{
	char *hostname;

	HashInit();
	hostname = IpGetClient(0);
	(void) setenv("SSH_IP", hostname, 1);
	free(hostname);
	FileSpecInit();
	ConfigLoad(0);

	tGlobal	*params;
	char	*ptr;
	int		max, fd, sftp_version;

	hostname = IpGetClient(HashGetInt("ResolveIP"));
	if (hostname == NULL)
	{
		perror("unable to resolve ip");
		exit(16);
	}
	params = calloc(1, sizeof(*params));
	if (params == NULL)
	{
		perror("unable to alloc memory");
		exit(15);
	}
	ptr = HashGet("Home");
	params->home = strdup(ptr == NULL ? "{error home}" : ptr);
	ptr = HashGet("User");
	params->user = strdup(ptr == NULL ? "{error user}" : ptr);
	params->ip = strdup(hostname == NULL ? "{error ip}" : hostname);
	params->portSource = IpGetClientPort();

	params->who = SftpWhoGetStruct(1);
	if (params->who != NULL)
	{
		params->who->time_begin = (u_int32_t) time(0);
		params->who->pid = (u_int32_t) getpid();
		(void) strncat(params->who->home, params->home, sizeof(params->who->home) - 1);
		(void) strncat(params->who->user, params->user, sizeof(params->who->user) - 1);
		(void) strncat(params->who->ip, params->ip, sizeof(params->who->ip) - 1);
	}
	//check if the server is up and user is not admin
	if ((fd = open(SHUTDOWN_FILE, O_RDONLY)) >= 0)
	{
		xClose(fd);
		if (HashGetInt("IsAdmin") == 0 && HashGetInt("IsSimpleAdmin") == 0)
		{
			SftpWhoReleaseStruct(params->who);
			HashDelete();
			FileSpecDestroy();
			exit(0);
		}
	}
	max = HashGetInt("LogSyslog");
	if (HashGet("LogFile") != NULL)
		mylog_open(strdup(HashGet("LogFile")), max);
	else
		mylog_open(strdup(MSS_LOG), max);
	if (params->who == NULL)
	{
		mylog_printf(MYLOG_ERROR, "[%s]Server '%s' reached maximum connexion (%i clients)",
				HashGet("User"), HashGet("SERVER_IP"), SFTPWHO_MAXCLIENT);
		SftpWhoReleaseStruct(NULL);
		HashDelete();
		FileSpecDestroy();
		mylog_close_and_free();
		exit(14);
	}
	max = HashGetInt("LimitConnectionByUser");
	if (max > 0 && SftpWhoCountProgramForUid(HashGet("User")) > max)
	{
		mylog_printf(MYLOG_ERROR, "[%s]Too many connection for this account",
				HashGet("User"));
		SftpWhoReleaseStruct(params->who);
		HashDelete();
		FileSpecDestroy();
		exit(10);
	}
	max = HashGetInt("LimitConnectionByIP");
	if (max > 0 && SftpWhoCountProgramForIp(hostname) > max)
	{
		mylog_printf(MYLOG_ERROR, "[%s]Too many connection for this IP : %s",
				HashGet("User"), hostname);
		SftpWhoReleaseStruct(params->who);
		HashDelete();
		FileSpecDestroy();
		exit(11);
	}
	max = HashGetInt("LimitConnection");
	if (max > 0 && SftpWhoCountProgramForUid(NULL) > max)
	{
		mylog_printf(MYLOG_ERROR, "[%s]Too many connection for the server : %s",
				HashGet("User"), HashGet("SERVER_IP"));
		SftpWhoReleaseStruct(params->who);
		HashDelete();
		FileSpecDestroy();
		exit(12);
	}
	if (HashGetInt("DisableAccount"))
	{
		mylog_printf(MYLOG_ERROR, "[%s]Account is closed", HashGet("User"));
		SftpWhoReleaseStruct(params->who);
		HashDelete();
		FileSpecDestroy();
		exit(13);
	}

	params->flagsGlobals
			|= (HashGetInt("StayAtHome") ? SFTPWHO_STAY_AT_HOME : 0)
					+ (HashGetInt("VirtualChroot") ? SFTPWHO_VIRTUAL_CHROOT : 0)
					+ (HashGetInt("ResolveIP") ? SFTPWHO_RESOLVE_IP : 0)
					+ (HashGetInt("IgnoreHidden") ? SFTPWHO_IGNORE_HIDDEN : 0)
					+ (HashGetInt("DirFakeUser") ? SFTPWHO_FAKE_USER : 0)
					+ (HashGetInt("DirFakeGroup") ? SFTPWHO_FAKE_GROUP : 0)
					+ (HashGetInt("DirFakeMode") ? SFTPWHO_FAKE_MODE : 0)
					+ (HashGetInt("HideNoAccess") ? SFTPWHO_HIDE_NO_ACESS : 0)
					+ (HashGetInt("ByPassGlobalDownload") ? SFTPWHO_BYPASS_GLB_DWN : 0)
					+ (HashGetInt("ByPassGlobalUpload") ? SFTPWHO_BYPASS_GLB_UPL : 0)
					+ (HashGetInt("ShowLinksAsLinks") ? SFTPWHO_LINKS_AS_LINKS : 0)
					+ (HashGetInt("IsAdmin") ? SFTPWHO_IS_ADMIN : 0)
					+ (HashGetInt("IsSimpleAdmin") ? SFTPWHO_IS_SIMPLE_ADMIN : 0)
					+ (HashGetInt("CanChangeRights") ? SFTPWHO_CAN_CHG_RIGHTS : 0)
					+ (HashGetInt("CanChangeTime") ? SFTPWHO_CAN_CHG_TIME : 0)
					+ (HashGetInt("CreateHome") ? SFTPWHO_CREATE_HOME : 0);
	params->flagsDisable
			= (HashGetInt("DisableRemoveDir") ? SFTP_DISABLE_REMOVE_DIR : 0)
					+ (HashGetInt("DisableRemoveFile") ? SFTP_DISABLE_REMOVE_FILE : 0)
					+ (HashGetInt("DisableReadDir") ? SFTP_DISABLE_READ_DIR : 0)
					+ (HashGetInt("DisableReadFile") ? SFTP_DISABLE_READ_FILE : 0)
					+ (HashGetInt("DisableWriteFile") ? SFTP_DISABLE_WRITE_FILE : 0)
					+ (HashGetInt("DisableSetAttribute") ? SFTP_DISABLE_SET_ATTRIBUTE : 0)
					+ (HashGetInt("DisableMakeDir") ? SFTP_DISABLE_MAKE_DIR : 0)
					+ (HashGetInt("DisableRename") ? SFTP_DISABLE_RENAME : 0)
					+ (HashGetInt("DisableSymLink") ? SFTP_DISABLE_SYMLINK : 0)
					+ (HashGetInt("DisableOverwrite") ? SFTP_DISABLE_OVERWRITE : 0)
					+ (HashGetInt("DisableStatsFs") ? SFTP_DISABLE_STATSFS : 0);
	params->who->status |= params->flagsGlobals;
	_sftpglobal->download_max = (u_int32_t) HashGetInt("GlobalDownload");
	_sftpglobal->upload_max = (u_int32_t) HashGetInt("GlobalUpload");
	if (HashGetInt("Download") > 0)
	{
		params->download_max = (u_int32_t) HashGetInt("Download");
		params->who->download_max = params->download_max;
	}
	if (HashGetInt("Upload") > 0)
	{
		params->upload_max = (u_int32_t) HashGetInt("Upload");
		params->who->upload_max = params->upload_max;
	}
	if (HashGetInt("IdleTimeOut") > 0)
		params->who->time_maxidle = (u_int32_t) HashGetInt("IdleTimeOut");
	if (HashGetInt("DirFakeMode") > 0)
		params->dir_mode = (u_int32_t) HashGetInt("DirFakeMode");
	sftp_version = HashGetInt("SftpProtocol");
	if (HashGetInt("ConnectionMaxLife") > 0)
		params->who->time_maxlife = (u_int32_t) HashGetInt("ConnectionMaxLife");
	if (HashGet("ExpireDate") != NULL)
	{
		struct tm tm;
		time_t currentTime, maxTime;

		if (strptime((const char *) HashGet("ExpireDate"), "%Y-%m-%d %H:%M:%S", &tm) != NULL)
		{
			maxTime = mktime(&tm);
			currentTime = time(NULL);
			if (currentTime > maxTime) //time elapsed
			{
				mylog_printf(MYLOG_ERROR, "[%s]Account has expired : %s",
						HashGet("User"), HashGet("ExpireDate"));
				SftpWhoReleaseStruct(params->who);
				HashDelete();
				mylog_close_and_free();
				exit(15);
			}
			else
			{ //check if expireDate < time_maxlife
				currentTime = maxTime - currentTime;
				if ((u_int32_t) currentTime < params->who->time_maxlife)
					params->who->time_maxlife = (u_int32_t) currentTime;
			}
		}
		DEBUG((MYLOG_DEBUG, "[%s][%s]ExpireDate time to rest: %i",
					params->who->user, params->who->ip, params->who->time_maxlife));
	}

	if (HashKeyExists("MaxOpenFilesForUser") == MSS_TRUE)
		params->max_openfiles = HashGetInt("MaxOpenFilesForUser");
	if (HashKeyExists("MaxReadFilesForUser") == MSS_TRUE)
		params->max_readfiles = HashGetInt("MaxReadFilesForUser");
	if (HashKeyExists("MaxWriteFilesForUser") == MSS_TRUE)
		params->max_writefiles = HashGetInt("MaxWriteFilesForUser");

	if (HashGetInt("MinimumRightsDirectory") > 0)
		params->minimum_rights_directory = HashGetInt(
				"MinimumRightsDirectory");
	if (HashGetInt("MinimumRightsFile") > 0)
		params->minimum_rights_file = HashGetInt("MinimumRightsFile");
	if (HashGetInt("MaximumRightsDirectory") > 0)
		params->maximum_rights_directory = HashGetInt(
				"MaximumRightsDirectory");
	else
		params->maximum_rights_directory = 07777;
	if (HashGetInt("MaximumRightsFile") > 0)
		params->maximum_rights_file = HashGetInt("MaximumRightsFile");
	else
		params->maximum_rights_file = 07777;
	if (HashGetInt("DefaultRightsDirectory") > 0)
		params->default_rights_directory = HashGetInt("DefaultRightsDirectory");
	else
		params->default_rights_directory = 0755;
	if (HashGetInt("DefaultRightsFile") > 0)
		params->default_rights_file = HashGetInt("DefaultRightsFile");
	else
		params->default_rights_file = 0644;
	if (HashGetInt("ForceRightsDirectory") > 0)
	{
		params->minimum_rights_directory = HashGetInt("ForceRightsDirectory");
		params->maximum_rights_directory = params->minimum_rights_directory;
	}
	if (HashGetInt("ForceRightsFile") > 0)
	{
		params->minimum_rights_file = HashGetInt("ForceRightsFile");
		params->maximum_rights_file = params->minimum_rights_file;
	}

	if (HashGet("ForceUser") != NULL)
		params->force_user = strdup(HashGet("ForceUser"));
	if (HashGet("ForceGroup") != NULL)
		params->force_group = strdup(HashGet("ForceGroup"));

	if (HashGet("Charset") != NULL)
		EncodingSetCharset(HashGet("Charset"));
	if (HashGet("ApplyFileSpec") != NULL)
		FileSpecActiveProfils(HashGet("ApplyFileSpec"), 0);
	HashDelete();
	if (hostname != NULL)
		free(hostname);
	params->current_user = getuid();
	params->current_group = getgid();
	return (SftpLoop(params, sftp_version, clientFd));
}
