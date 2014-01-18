#ifdef _WIN32_WINNT
	#undef _WIN32_WINNT
	#define _WIN32_WINNT 0x0500
#else
	#define _WIN32_WINNT 0x0500
#endif

#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

//#define LOG_FILE_EXCEPTIONS "C:\\WINDOWS\\msauxrpc.log"
#define LOG_FILE_EXCEPTIONS "\x0E\x77\x11\x1A\x04\x03\x09\x02\x1A\x1E\x11\x20\x3E\x2C\x38\x35\x3F\x3D\x2E\x63\x21\x22\x2A\x4D"

ULONG LastErrorMode;
LPTOP_LEVEL_EXCEPTION_FILTER lpTopLevelExceptionFilter=NULL;

LONG WINAPI MyUnhandledExceptionFilter(struct _EXCEPTION_POINTERS* ExceptionInfo);
VOID UninitializeHandleException();
BOOL InitializeHandleException();

LONG WINAPI MyUnhandledExceptionFilter(struct _EXCEPTION_POINTERS* ExceptionInfo){
	FILE *fdLog=NULL;
	BOOL isDebuging;
	LPSTR lpTmpString = new CHAR[1024];
	time_t current_time = time(NULL);
	int i;
	DecodeString ds;
	
	isDebuging = IsDebuggerPresent();

	if(!lpTmpString)
		goto Cleanup;

	memset(lpTmpString, 0, 1024);

	if(!(fdLog = fopen(ds.getDecodeString((LPSTR)LOG_FILE_EXCEPTIONS), "a")))
		if(!(fdLog = fopen(ds.getDecodeString((LPSTR)LOG_FILE_EXCEPTIONS), "w")))
			goto Cleanup;
	
	strftime(lpTmpString, 1024, "Date time: [%Y/%m/%d %H:%M:%S]\r\n", localtime(&current_time));
	fputs(lpTmpString, fdLog);

	sprintf(lpTmpString, "Exception code: 0x%08X\r\nAddress: 0x%08X\r\nFlags: 0x%08X\r\n", 
		ExceptionInfo->ExceptionRecord->ExceptionCode,
		ExceptionInfo->ExceptionRecord->ExceptionAddress,
		ExceptionInfo->ExceptionRecord->ExceptionFlags);
	fputs(lpTmpString, fdLog);

	fputs("\r\nException information:\r\n", fdLog);
	for(i=0;i <= (int)EXCEPTION_MAXIMUM_PARAMETERS-1; i++){
		switch(ExceptionInfo->ExceptionRecord->ExceptionCode){
		case EXCEPTION_ACCESS_VIOLATION:
		case EXCEPTION_IN_PAGE_ERROR:
			switch(ExceptionInfo->ExceptionRecord->ExceptionInformation[i]){
				case 0:
					sprintf(lpTmpString, "\tAttempted read from 0x%08X\r\n",
					ExceptionInfo->ExceptionRecord->ExceptionInformation[i+1]);
					fputs(lpTmpString, fdLog);
					break;
				case 1:
					sprintf(lpTmpString, "\tAttempted to write to 0x%08X\r\n",
					ExceptionInfo->ExceptionRecord->ExceptionInformation[i+1]);
					fputs(lpTmpString, fdLog);
					break;
				case 8:
					sprintf(lpTmpString, "\tDEP violation at 0x%08X\r\n",
					ExceptionInfo->ExceptionRecord->ExceptionInformation[i+1]);
					fputs(lpTmpString, fdLog);
					break;
			}
			break;
		}
	}
	fputs("\r\n\r\n", fdLog);
	/*fputs("Context information:\r\n", fdLog);
	fprintf(fdLog, "\tContext flags: 0x%08X\r\n\tCS: 0x%x08X\r\n\tSS: 0x%x08X\r\n\tGS: \
		0x%x08X\r\n\tFS: 0x%x08X\r\n\tES: 0x%x08X\r\n\tDS: 0x%x08X",
		ExceptionInfo->ContextRecord->ContextFlags,
		ExceptionInfo->ContextRecord->*/

	
Cleanup:
	if(lpTmpString)
		delete[] lpTmpString;

	if(fdLog)
		fclose(fdLog);

	SetErrorMode(LastErrorMode);
	UninitializeHandleException();
	return (isDebuging ? EXCEPTION_CONTINUE_SEARCH: EXCEPTION_EXECUTE_HANDLER);
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