#include <windows.h>

DWORD IsActivePC(in_addr Addr){
	HANDLE hIcmpFile=NULL;
	char SendData[] = "AAAA";
	LPVOID ReplyBuffer = NULL;
    DWORD ReplySize = NULL, dwRetVal=TRUE;
	int i=0;

	if((hIcmpFile = IcmpCreateFile()) == INVALID_HANDLE_VALUE){
		#ifdef DEBUG_SHOW_ERROR
		MessageBox(0, "Error IcmpCreateFile", NULL, NULL);
		#endif
		dwRetVal=-1;
		goto Cleanup;
	}

	ReplySize = sizeof(ICMP_ECHO_REPLY) + sizeof(SendData);
    ReplyBuffer = (VOID*) malloc(ReplySize);
    if (ReplyBuffer == NULL) {
		#ifdef DEBUG_SHOW_ERROR
        MessageBox(0, "Unable to allocate memory", NULL, NULL);
		#endif
        dwRetVal=-1;
		goto Cleanup;
    }

	for(i=0;i<=1;i++){
		dwRetVal = IcmpSendEcho(hIcmpFile, Addr, SendData, sizeof(SendData), 
			NULL, ReplyBuffer, ReplySize, 100);
		if (dwRetVal != 0) {
			PICMP_ECHO_REPLY pEchoReply = (PICMP_ECHO_REPLY)ReplyBuffer;
			//ReplyAddr.S_un.S_addr = pEchoReply->Address;
			if(pEchoReply->Address.S_un.S_addr == Addr.S_un.S_addr){
				dwRetVal=TRUE;
				goto Cleanup;
			}
		}
	}
	dwRetVal=FALSE;

Cleanup:
	if(hIcmpFile && hIcmpFile!=INVALID_HANDLE_VALUE)
		IcmpCloseHandle(hIcmpFile);

	if(ReplyBuffer)
		free(ReplyBuffer);

	return dwRetVal;
}
