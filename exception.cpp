//Module for exception register
#ifdef _WIN32_WINNT
	#undef _WIN32_WINNT
	#define _WIN32_WINNT 0x0500
#else
	#define _WIN32_WINNT 0x0500
#endif

//-----------------------------------------------------------------------------

#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <iostream>
#include <fstream>
#include <iomanip>

using namespace std;

#define LOG_FILE_EXCEPTIONS "%SystemRoot%\\msauxrpc.log"
//#define LOG_FILE_EXCEPTIONS "\x0E\x77\x11\x1A\x04\x03\x09\x02\x1A\x1E\x11\x20\x3E\x2C\x38\x35\x3F\x3D\x2E\x63\x21\x22\x2A\x4D"
#define MAX_DEEP_CALL_STACK 100

ULONG LastErrorMode;
LPTOP_LEVEL_EXCEPTION_FILTER lpTopLevelExceptionFilter=NULL;
ofstream ofs;

LONG WINAPI MyUnhandledExceptionFilter(struct _EXCEPTION_POINTERS* ExceptionInfo);
VOID UninitializeHandleException();
BOOL InitializeHandleException();
DWORD GetCallStack(DWORD Ebp, LPDWORD NextEBP);
BOOL MakeDumpStack(DWORD Esp, DWORD Ebp);
LPCSTR GetProcName();

/*int exceptionFilter(unsigned int code, struct _EXCEPTION_POINTERS *ep) {
	
	return 1;
}*/

LPCSTR GetProcName(){
	LPSTR procPath = new CHAR[MAX_PATH+2];

	if(!procPath) return NULL;

	if(!GetModuleFileName(NULL, procPath, MAX_PATH))
		return NULL;

	return procPath;
}

DWORD GetCallStack(DWORD Ebp, LPDWORD NextEBP){
	DWORD RetAddr=NULL;

	if(!Ebp || !NextEBP) return NULL;

	__try{
		RetAddr = *((LPDWORD)(Ebp+4));
		*NextEBP = *((LPDWORD)Ebp);
	}__except(EXCEPTION_EXECUTE_HANDLER  /*exceptionFilter(GetExceptionCode(), GetExceptionInformation())*/){
		*NextEBP = NULL;
		RetAddr = NULL;
		cout << "\tA exception ocurred while getting call stack: " << GetExceptionCode() << endl;
	}

	return RetAddr;
}

//WWWW
BOOL MakeDumpStack(DWORD Esp, DWORD Ebp){
	DWORD tmpNextEBP, tmpESP, tmpDW, i, k;
	
	if(!Esp || !Ebp || (Esp > Ebp))
		return FALSE;

	ofs << "Dump Stack:" << endl;
	tmpNextEBP = Ebp;
	tmpESP = Esp;
	for(k=0; k<=MAX_DEEP_CALL_STACK-1; k++){
		for(i=tmpESP; i<=tmpNextEBP; i+=sizeof(DWORD)){
			__try{
				tmpDW = *((LPDWORD)i);
			}__except(EXCEPTION_EXECUTE_HANDLER){
				cout << "\tError ocurred while getting dump stack" << endl;
				break;
			}

			ofs << "\t0x" << setiosflags(ios::internal | ios::showpos | ios::uppercase) 
				<< setw(8) << setfill('0') << hex << i;
			ofs << "\t0x" << setiosflags(ios::internal | ios::showpos | ios::uppercase) 
				<< setw(8) << setfill('0') << hex << tmpDW << endl;
		}
		tmpDW = GetCallStack(tmpNextEBP, &tmpNextEBP);
		if(!tmpDW && !tmpNextEBP) break;
		tmpESP = Ebp+4;
	}
	
	return TRUE;
}

LONG WINAPI MyUnhandledExceptionFilter(struct _EXCEPTION_POINTERS* ExceptionInfo){
	FILE *fdLog=NULL;
	LPSTR lpTmpString = new CHAR[1024];
	time_t current_time = time(NULL);
	DWORD NextEBP, dwCallStack;
	int i;

	if(!lpTmpString)
		goto Cleanup;

	memset(lpTmpString, 0, 1024);

	if(!ExpandEnvironmentStrings(LOG_FILE_EXCEPTIONS, lpTmpString, 1024))
		goto Cleanup;

	ofs.open(lpTmpString, ios::app);
	if(ofs.bad())
		goto Cleanup;

	strftime(lpTmpString, 1024, "EXCEPTION INFORMATION\r\nDate time: %Y/%m/%d %H:%M:%S", localtime(&current_time));
	ofs << lpTmpString << endl;

	ofs << "Proccess path: " << GetProcName() << endl;

	sprintf(lpTmpString, "Exception code: 0x%08X\nAddress: 0x%08X\nFlags: 0x%08X", 
		ExceptionInfo->ExceptionRecord->ExceptionCode,
		ExceptionInfo->ExceptionRecord->ExceptionAddress,
		ExceptionInfo->ExceptionRecord->ExceptionFlags);
	ofs << lpTmpString << endl;

	for(i=0;i <= (int)ExceptionInfo->ExceptionRecord->NumberParameters-1; i++){
		switch(ExceptionInfo->ExceptionRecord->ExceptionCode){
		case EXCEPTION_ACCESS_VIOLATION:
		case EXCEPTION_IN_PAGE_ERROR:
			switch(ExceptionInfo->ExceptionRecord->ExceptionInformation[i]){
				case 0:
					sprintf(lpTmpString, "\tAttempted read from 0x%08X",
					ExceptionInfo->ExceptionRecord->ExceptionInformation[i+1]);
					ofs << lpTmpString << endl;
					break;
				case 1:
					sprintf(lpTmpString, "\tAttempted to write to 0x%08X",
					ExceptionInfo->ExceptionRecord->ExceptionInformation[i+1]);
					ofs << lpTmpString << endl;
					break;
				case 8:
					sprintf(lpTmpString, "\tDEP violation at 0x%08X",
					ExceptionInfo->ExceptionRecord->ExceptionInformation[i+1]);
					ofs << lpTmpString << endl;
					break;
			}
			break;
		}
	}
	
	ofs << endl << "Registers:" << endl;
	ofs << "\tEDI: 0x" << setiosflags(ios::internal | ios::showpos | ios::uppercase)
		<< setw(8) << setfill('0') << hex << ExceptionInfo->ContextRecord->Edi << endl 
		<< "\tESI: 0x" << setiosflags(ios::internal | ios::showpos | ios::uppercase)
		<< setw(8) << setfill('0') << hex << ExceptionInfo->ContextRecord->Esi << endl
		<< "\tEBX: 0x" << setiosflags(ios::internal | ios::showpos | ios::uppercase)
		<< setw(8) << setfill('0') << hex << ExceptionInfo->ContextRecord->Ebx << endl
		<< "\tEDX: 0x" << setiosflags(ios::internal | ios::showpos | ios::uppercase)
		<< setw(8) << setfill('0') << hex << ExceptionInfo->ContextRecord->Edx << endl
		<< "\tEDX: 0x" << setiosflags(ios::internal | ios::showpos | ios::uppercase)
		<< setw(8) << setfill('0') << hex << ExceptionInfo->ContextRecord->Edx << endl
		<< "\tECX: 0x" << setiosflags(ios::internal | ios::showpos | ios::uppercase)
		<< setw(8) << setfill('0') << hex << ExceptionInfo->ContextRecord->Ecx << endl
		<< "\tEAX: 0x" << setiosflags(ios::internal | ios::showpos | ios::uppercase)
		<< setw(8) << setfill('0') << hex << ExceptionInfo->ContextRecord->Eax << endl
		<< "\tEBP: 0x" << setiosflags(ios::internal | ios::showpos | ios::uppercase)
		<< setw(8) << setfill('0') << hex << ExceptionInfo->ContextRecord->Ebp << endl
		<< "\tESP: 0x" << setiosflags(ios::internal | ios::showpos | ios::uppercase)
		<< setw(8) << setfill('0') << hex << ExceptionInfo->ContextRecord->Esp << endl
		<< "\tEIP: 0x" << setiosflags(ios::internal | ios::showpos | ios::uppercase)
		<< setw(8) << setfill('0') << hex << ExceptionInfo->ContextRecord->Eip << endl
		<< "\tEFlags: 0x" << setiosflags(ios::internal | ios::showpos | ios::uppercase)
		<< setw(8) << setfill('0') << hex << ExceptionInfo->ContextRecord->EFlags << endl;

	NextEBP = ExceptionInfo->ContextRecord->Ebp;
	ofs << endl << "Call stack:" << endl;
	for(i=1; i<=MAX_DEEP_CALL_STACK; i++){
		dwCallStack = GetCallStack(NextEBP, &NextEBP);
		if(!NextEBP && !dwCallStack) break;
		ofs << "\t0x" << setiosflags(ios::internal | ios::showpos | ios::uppercase)
		<< setw(8) << setfill('0') << hex << dwCallStack << endl;
	}
	
	ofs << endl;
	MakeDumpStack(ExceptionInfo->ContextRecord->Esp, ExceptionInfo->ContextRecord->Ebp);

	ofs << setfill('-') << setw(76) << " " << endl;
	
Cleanup:
	if(lpTmpString)
		delete[] lpTmpString;

	if(ofs.good()) ofs.close();

	SetErrorMode(LastErrorMode);
	UninitializeHandleException();
	//return (isDebuging ? EXCEPTION_EXECUTE_HANDLER: EXCEPTION_CONTINUE_SEARCH);
	return EXCEPTION_CONTINUE_SEARCH;
}

BOOL InitializeHandleException(){
	BOOL retVal=TRUE;

	LastErrorMode = SetErrorMode(SEM_NOGPFAULTERRORBOX);

	lpTopLevelExceptionFilter = SetUnhandledExceptionFilter(MyUnhandledExceptionFilter);

	return TRUE;
}

VOID UninitializeHandleException(){
	if(lpTopLevelExceptionFilter){
		SetErrorMode(LastErrorMode);
		SetUnhandledExceptionFilter(MyUnhandledExceptionFilter);
	}
}