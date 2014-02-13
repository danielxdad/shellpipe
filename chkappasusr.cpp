#include "stdafx.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

//#define USER_TO_CHECK "Administrador"

LPSTR GetShell(void);
DWORD CheckSessionUser(LPSTR lpUserName);
DWORD CheckIsProcessRuningAsUser(LPSTR lpszPathProc, LPSTR lpszUserName);

LPSTR GetShell(void){
	HKEY hKey;
	DWORD dwValueType = REG_SZ, dwcbOutBuffer = MAX_PATH+2;
	LPSTR lpOutBuffer = new CHAR[dwcbOutBuffer];
	LPSTR retVal = NULL;
	CHAR msg[256]={0};
	DecodeString ds;
	
	if(RegOpenKey(HKEY_LOCAL_MACHINE, 
		ds.getDecodeString((LPSTR)encStr_SOFTWARE_Microsoft_WindowsNT_CurrentVersion_Winlogon), 
		&hKey) != ERROR_SUCCESS){
		retVal = NULL;
		goto Cleanup;
	}

	if(RegQueryValueEx(hKey, ds.getDecodeString((LPSTR)encStr_Shell), 
		NULL, &dwValueType,(LPBYTE)lpOutBuffer, &dwcbOutBuffer) != ERROR_SUCCESS){
		retVal = NULL;
		goto Cleanup;
	}

	RegCloseKey(hKey);

	retVal = lpOutBuffer;
Cleanup:
	return retVal;
}

DWORD CheckInteractiveSessionUser(LPSTR lpUserName){
	PLUID sessions = NULL;
	ULONG count;
	DWORD retVal = FALSE;
	PSECURITY_LOGON_SESSION_DATA pLogonSessionData;
	CHAR s1[MAX_PATH] = {0};
	int i;

	if (LsaEnumerateLogonSessions(&count, &sessions) != 0){				
		retVal = -1;
		goto Cleanup;
	} 	

	for (i =0;i<(int)count; i++) {
		if(LsaGetLogonSessionData(&sessions[i], &pLogonSessionData) != 0)
			continue;
		
		memset(s1, 0, MAX_PATH);
		wcstombs(s1, pLogonSessionData->UserName.Buffer, wcslen(pLogonSessionData->UserName.Buffer));
		//printf("%s - %s\n", s1, lpUserName);
		if(stricmp(s1, lpUserName) == 0){
			if (pLogonSessionData->LogonType == Interactive 
				|| pLogonSessionData->LogonType == RemoteInteractive
				|| pLogonSessionData->LogonType == CachedInteractive
				|| pLogonSessionData->LogonType == CachedRemoteInteractive){
					
					//printf("\t%d\n", pLogonSessionData->LogonType);
					retVal = TRUE;
					LsaFreeReturnBuffer(pLogonSessionData);
					break;
			}
		}

		LsaFreeReturnBuffer(pLogonSessionData);
	}
	

Cleanup:
	if (sessions)
		LsaFreeReturnBuffer(sessions);

	return retVal;

}

DWORD PathIsSamePath(LPCSTR lpPath1, LPCSTR lpPath2){
	LPSTR lpszShortPath1 = new CHAR[MAX_PATH+2];
	LPSTR lpszShortPath2 = new CHAR[MAX_PATH+2];
	DWORD dwRetVal=FALSE;

	if(!lpszShortPath1 || !lpszShortPath2){
		dwRetVal=FALSE;
		goto Cleanup;
	}

	if(!GetShortPathName(lpPath1, lpszShortPath1, MAX_PATH)){
		dwRetVal=FALSE;
		goto Cleanup;
	}

	if(!GetShortPathName(lpPath2, lpszShortPath2, MAX_PATH)){
		dwRetVal=FALSE;
		goto Cleanup;
	}

	if(stricmp(lpszShortPath1, lpszShortPath2) == 0)
		dwRetVal = TRUE;
	else
		dwRetVal = FALSE;
	
Cleanup:
	if(lpszShortPath1)
		delete[] lpszShortPath1;

	if(lpszShortPath2)
		delete[] lpszShortPath2;

	return dwRetVal;
}

DWORD CheckIsSameProcess(HANDLE hProc, LPCSTR lpszPathProc, HMODULE hModule){
	LPSTR lpszModuleFileName1 = new CHAR[MAX_PATH+2];
	LPSTR lpszModuleFileName2 = new CHAR[MAX_PATH+2];
	LPSTR lpszEnvVarPath = new CHAR[32770];
	LPSTR token = NULL, lpStrTmp = NULL;
	DWORD dwRetVal = 0;

	if ( !hProc ){
		dwRetVal = -1;
		goto Cleanup;
	}

	if(!lpszModuleFileName1 || !lpszModuleFileName2 || !lpszEnvVarPath){
		dwRetVal = -1;
		goto Cleanup;
	}
		
	if(!GetModuleFileNameEx(hProc, hModule, lpszModuleFileName1, MAX_PATH+2)){
		dwRetVal = -1;
		goto Cleanup;
	}

	//VER funcion: PathFindOnPath
	if(PathIsRelative(lpszPathProc)){
		memset(lpszEnvVarPath, 0, 32770);
		if(!GetEnvironmentVariable("PATH", lpszEnvVarPath, 32770)){
			dwRetVal = -1;
			goto Cleanup;
		}

		lpStrTmp = strdup(lpszEnvVarPath);
		token = strtok( lpStrTmp, ";" );
		while( token != NULL ){
			if(PathFileExists(PathCombine(lpszModuleFileName2, token, lpszPathProc))){
				//if(stricmp(lpszModuleFileName1, lpszModuleFileName2) == 0){
				if(PathIsSamePath(lpszModuleFileName1, lpszModuleFileName2) == TRUE){
					dwRetVal = 1;
					goto Cleanup;
				}
			}
			
			token = strtok( NULL, ";" );
		}
	}
	else{
		if(PathFileExists(lpszPathProc)){
			if(PathIsSamePath(lpszModuleFileName1, lpszPathProc) == TRUE){
				dwRetVal = 1;
				goto Cleanup;
			}
		}
	}

Cleanup:
	if ( lpszModuleFileName1 )
		delete[] lpszModuleFileName1;

	if ( lpszModuleFileName2 )
		delete[] lpszModuleFileName2;

	if ( lpszEnvVarPath )
		delete[] lpszEnvVarPath;

	if ( lpStrTmp )
		free(lpStrTmp);
	
	return dwRetVal;
}

LPSTR GetProcessOwner(HANDLE hProcess){
	HANDLE hToken=NULL;
	LPSTR Owner = NULL, refDomainName=NULL;
	PTOKEN_USER tokenUser = NULL;
	DWORD retLen = 0, cbName=0, cbrefDomainName=0;
	SID_NAME_USE SidNameUse;
	TOKEN_INFORMATION_CLASS tokenInfClass = TokenUser; 

	if(!OpenProcessToken(hProcess, TOKEN_READ, &hToken)){
		Owner = NULL;
		goto Cleanup;
	}

	if(!GetTokenInformation(hToken, tokenInfClass, (LPVOID)tokenUser, 0, &retLen)){

		if(GetLastError() != ERROR_INSUFFICIENT_BUFFER){
			Owner = NULL;
			goto Cleanup;
		}

		tokenUser = (PTOKEN_USER) new BYTE[retLen];
		memset((LPVOID)tokenUser, 0, retLen);

		if(!GetTokenInformation(hToken, tokenInfClass, (LPVOID)tokenUser, retLen, &retLen)){
			Owner = NULL;
			goto Cleanup;
		}
	}

	cbName = MAX_PATH;
	Owner = new CHAR[MAX_PATH];
	memset(Owner, '0', MAX_PATH);

	cbrefDomainName = MAX_PATH;
	refDomainName = new CHAR[MAX_PATH];
	memset(refDomainName, '0', MAX_PATH);

	if(!LookupAccountSid(NULL, tokenUser->User.Sid, Owner, &cbName, 
		refDomainName, &cbrefDomainName, &SidNameUse)){
		delete[] Owner;
		Owner = NULL;
		goto Cleanup;
	}

Cleanup:
	if(hToken)
		CloseHandle(hToken);

	if(tokenUser)
		delete[] tokenUser;

	if(refDomainName)
		delete[] refDomainName;
	
	return Owner;
}

DWORD CheckIsProcessRuningAsUser(LPSTR lpszPathProc, LPSTR lpszUserName){
	HANDLE hProcessSnap;
	HANDLE hProcess;
	PROCESSENTRY32 pe32;
	DWORD dwRetVal=0;
	LPSTR lpszOwner;
	CHAR msg[256]={0};

	hProcessSnap = CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS, 0 );
	if( hProcessSnap == INVALID_HANDLE_VALUE )
		return -1;

	pe32.dwSize = sizeof( PROCESSENTRY32 );

	if( !Process32First( hProcessSnap, &pe32 ) ){
		dwRetVal = -1;
		goto Cleanup;
	}

	do{
		//printf("Exe file: %s - %u\n", pe32.szExeFile, pe32.th32ProcessID);
		hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pe32.th32ProcessID );
		if( hProcess == NULL ){
		  //sprintf(msg, "Error OpenProcess %s: %u\n", pe32.szExeFile, GetLastError());
		  //MessageBox(0, msg, "", 0);
		  continue;
		}
		else{
			if(CheckIsSameProcess(hProcess, lpszPathProc, NULL) == TRUE){
				if(CheckInteractiveSessionUser(lpszUserName) == 1){
					lpszOwner = GetProcessOwner(hProcess);
					if(lpszOwner){
						if(stricmp(lpszOwner, lpszUserName) == 0){
							//printf("The proc is: %s\n", pe32.szExeFile);
							dwRetVal = 1;
							CloseHandle( hProcess );
							delete[] lpszOwner;
							break;
						}
						delete[] lpszOwner;
					}
				}
			}

		  CloseHandle( hProcess );
		}
	} while( Process32Next( hProcessSnap, &pe32 ) );

	

Cleanup:
	CloseHandle( hProcessSnap );
	return dwRetVal;
}