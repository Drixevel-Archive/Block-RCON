#pragma semicolon 1
#pragma newdecls required

#include <sourcemod>
#include <smrcon>

ConVar hConVars[3];
ConVar hPassword;

public Plugin myinfo = 
{
	name = "Block RCON", 
	author = "Keith Warren (Drixevel)", 
	description = "Disables all access to RCON-based commands.", 
	version = "1.0.0", 
	url = "http://www.drixevel.com/"
};

public void OnPluginStart()
{
	LoadTranslations("common.phrases");
	
	hConVars[0] = CreateConVar("sm_blockrcon_status", "1", "Status of the plugin.", FCVAR_NOTIFY, true, 0.0, true, 1.0);
	hConVars[1] = CreateConVar("sm_blockrcon_logattempts", "1", "Log any attempts used to access the RCON command.", FCVAR_NOTIFY, true, 0.0, true, 1.0);
	hConVars[2] = CreateConVar("sm_blockrcon_logformat", ".%m_%y", "Log formatting to use for the postfix information. (Can be empty)", FCVAR_NOTIFY, true);

	AutoExecConfig();
	
	hPassword = FindConVar("rcon_password");
	HookConVarChange(hPassword, HookConVar_Password);
}

public void OnConfigsExecuted()
{
	//Set the password to empty since that disables it.
	SetConVarString(hPassword, "");
}

public Action SMRCon_OnAuth(int rconId, const char[] address, const char[] password, bool &allow)
{
	if (GetConVarBool(hConVars[0]))
	{
		allow = false;
		RCONLog("RCON command attempt: %s - %s", strlen(address) > 0 ? address : "N/A", strlen(password) > 0 ? password : "N/A");
		return Plugin_Changed;
	}
	
	return Plugin_Continue;
}

public void HookConVar_Password(ConVar convar, const char[] oldValue, const char[] newValue)
{
	if (GetConVarBool(hConVars[0]) && strlen(newValue) > 0)
	{
		RCONLog("RCON password change attempt: %s - %s", strlen(oldValue) > 0 ? oldValue : "N/A", strlen(newValue) > 0 ? newValue : "N/A");
		SetConVarString(convar, oldValue);
	}
}

void RCONLog(const char[] sFormat, any ...)
{
	if (GetConVarBool(hConVars[1]))
	{
		char sBuffer[1024];
		VFormat(sBuffer, sizeof(sBuffer), sFormat, 2);
		
		char sTimeFormat[32];
		GetConVarString(hConVars[2], sTimeFormat, sizeof(sTimeFormat));
		
		char sTime[32];
		FormatTime(sTime, sizeof(sTime), sTimeFormat);
		
		char sLogPath[PLATFORM_MAX_PATH];
		BuildPath(Path_SM, sLogPath, sizeof(sLogPath), "logs/rcon.attempts%s.log", sTime);
		LogToFile(sLogPath, sBuffer);
	}
}