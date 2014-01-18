#include <time.h>
#include <shlwapi.h>
#include <string>
#include "package.h"

using namespace std;

#pragma comment(lib, "shlwapi.lib")

CHAR package_ErrMsg[256] = {0};

DWORD getEncryptKeyAndFTime(LPDWORD pfTime, BOOL ReturnFTime){
	DWORD key = NULL, fTime = NULL;
	SYSTEMTIME sysTime={0};

	if(pfTime)
		fTime = *pfTime;

	if(!fTime){
		GetSystemTime(&sysTime);
		key = (sysTime.wHour << 22) | (sysTime.wMinute << 16) | 
				(sysTime.wSecond << 10) | sysTime.wMilliseconds;

		if(ReturnFTime)
			*pfTime = key;
	}
	else{
		/*key = ((fTime & 0x7C00000) >> 22) | 
			  ((fTime & 0x3F0000) >> 16) | 
			  ((fTime & 0xFC00) >> 10) |
			  ((fTime & &H3FF))*/

		key = fTime;
	}

	key ^= 0x429F73B;

	return key;
}


LPBYTE encryptData(LPBYTE lpData, DWORD dwDataLen, DWORD Key){
	DWORD i;
	BYTE byte;

	for(i=0; i<= dwDataLen-1; ++i){
		byte = lpData[i] ^ ((Key & 0xFF000000) >> 24);
		byte ^= ((Key & 0x00FF0000) >> 16);
		byte ^= ((Key & 0x0000FF00) >> 8);
		byte ^= (Key & 0x000000FF);

		lpData[i] = byte; 
	}

	return lpData;
}


LPBYTE decryptData(LPBYTE lpData, DWORD dwDataLen, DWORD Key){
	DWORD i;
	BYTE byte;

	for(i=0; i<= dwDataLen-1; ++i){
		byte = lpData[i] ^ (Key & 0x000000FF);
		byte ^= ((Key & 0x0000FF00) >> 8);
		byte ^= ((Key & 0x00FF0000) >> 16);
		byte ^= ((Key & 0xFF000000) >> 24);

		lpData[i] = byte; 
	}
	return lpData;
}


BOOL getHashData(LPBYTE lpData, DWORD cbData, LPBYTE lpOutHash, DWORD cbOutHash){
	if(HashData(lpData, cbData, lpOutHash, cbOutHash) != S_OK){
		//sprintf(package_ErrMsg, "Error getting hash of data");
		return FALSE;
	}

	return TRUE;
}

VOID FreePackage(LPSP_PACKET lpPacket){
	if(lpPacket->lpData && lpPacket->dwDataLen)
		delete[] lpPacket->lpData;

	delete[] lpPacket;
}


LPSP_PACKET InitializePackage(DWORD dwFlags, LPBYTE lpParam1, DWORD cbParam1,
								LPBYTE lpParam2, DWORD cbParam2, LPBYTE lpData, DWORD cbData)
{
	LPSP_PACKET lpSPPacket = new SP_PACKET;
	DWORD currTime=NULL;
	DWORD encryptKey = getEncryptKeyAndFTime(&currTime, TRUE);
	DecodeString ds;

	if (!lpSPPacket){
		sprintf(package_ErrMsg, ds.getDecodeString((LPSTR)encStr_Error_initizalize_package_no_memory));
		return NULL;
	}
	memset(lpSPPacket, 0, sizeof(SP_PACKET));

	lpSPPacket->wMagic = MAGIC_PACKET;
	lpSPPacket->dwFlags = dwFlags;
	lpSPPacket->currentTime = currTime;

	//Parametro 1
	if(lpParam1 && cbParam1){
		if(cbParam1 > MAX_PATH){
			sprintf(package_ErrMsg, ds.getDecodeString((LPSTR)encStr_The_len_of_param1_is_very_long));
			return NULL;
		}
		memcpy(lpSPPacket->lpParam1, lpParam1, cbParam1);
		//encryptData(lpSPPacket->lpParam1, cbParam1, encryptKey);
	}

	//Parametro 2
	if(lpParam2 && cbParam2){
		if(cbParam2 > MAX_PATH){
			sprintf(package_ErrMsg, ds.getDecodeString((LPSTR)encStr_The_len_of_param2_is_very_long));
			return NULL;
		}
		memcpy(lpSPPacket->lpParam2, lpParam2, cbParam2);
		//encryptData(lpSPPacket->lpParam2, cbParam2, encryptKey);
	}
	
	if(lpData){
		lpSPPacket->dwDataLen = cbData;
		lpSPPacket->lpData = new BYTE[cbData];
		memcpy(lpSPPacket->lpData, lpData, cbData);

		//Obtencion del hash de los datos
		if(!getHashData(lpSPPacket->lpData, cbData, lpSPPacket->Hash, HASH_LEN)){
			delete lpSPPacket;
			return NULL;
		}
	}

	//Encriptacion de los datos y parametros
	if(dwFlags & FLAG_DATA_ENCRYPTED){
		if(lpData && cbData){
			encryptData(lpSPPacket->lpData, cbData, encryptKey);
		}

		encryptData(lpSPPacket->lpParam1, MAX_PATH, encryptKey);
		encryptData(lpSPPacket->lpParam2, MAX_PATH, encryptKey);
	}

	return lpSPPacket;
}


BOOL WritePacketToPipe(HANDLE hPipe, LPSP_PACKET lpPacket){
	DWORD nbWriten;
	DecodeString ds;

	if(!lpPacket){
		sprintf(package_ErrMsg, ds.getDecodeString((LPSTR)encStr_Error_unitialized_packet));
		return FALSE;
	}

	if(lpPacket->wMagic != MAGIC_PACKET){
		sprintf(package_ErrMsg, ds.getDecodeString((LPSTR)encStr_Error_unknow_magic_packet));
		return FALSE;
	}

	if(!WriteFile(hPipe, lpPacket, sizeof(SP_PACKET) - sizeof(lpPacket->lpData), 
		&nbWriten, NULL)){

		sprintf(package_ErrMsg, ds.getDecodeString((LPSTR)encStr_Error_write_header_packet_to_pipe),
			GetLastError());
		return FALSE;
	}
	
	if(lpPacket->lpData && lpPacket->dwDataLen){
		if(!WriteFile(hPipe, lpPacket->lpData, lpPacket->dwDataLen, 
			&nbWriten, NULL)){

			sprintf(package_ErrMsg, ds.getDecodeString((LPSTR)encStr_Error_write_data_packet_to_pipe), GetLastError());
			return FALSE;
		}
		//FlushFileBuffers(hPipe);
	}

	return nbWriten;
}


DWORD WriteToPipe(HANDLE hPipe, DWORD cbSize, LPSTR Buffer, DWORD dwFlags){
	DWORD dwRetVal=TRUE;
	LPSP_PACKET lpPacket;

	/*if (!Buffer || !cbSize) 
		return NULL;*/

	if(DataPacketIsEncrypted)
		dwFlags |= FLAG_DATA_ENCRYPTED;

	if(!(lpPacket = InitializePackage(dwFlags, NULL, NULL, NULL, NULL, (LPBYTE)Buffer, cbSize)))
		return FALSE;

	if(!(dwRetVal = WritePacketToPipe(hPipe, lpPacket))){
		dwRetVal = FALSE;
		goto Cleanup;
	}
	
Cleanup:
	FreePackage(lpPacket);
	return dwRetVal;
}

/*
	Se encarga de leer un paquete desde un pipe especificado, comprueba la integridad
	de la cabecera y de los datos; descripta los datos y elimina el flag de encriptacion
	si esta especificada esta opcion
*/
LPSP_PACKET ReadPacketFromPipe(HANDLE hPipe){
	LPSP_PACKET lpTmpPacket = new SP_PACKET;
	BYTE TmpHash[HASH_LEN]={0};
	DWORD nbRead, encKey;
	CHAR msg[256] = {0};
	DecodeString ds;

	memset(lpTmpPacket, 0, sizeof(SP_PACKET));
	if(!ReadFile(hPipe, (LPVOID)lpTmpPacket, sizeof(SP_PACKET) - sizeof(LPBYTE), 
		&nbRead, NULL)){

		delete lpTmpPacket;
		sprintf(package_ErrMsg, ds.getDecodeString((LPSTR)encStr_Error_cant_read_packet));
		
		return NULL;
	}
	
	if(nbRead != sizeof(SP_PACKET) - sizeof(LPBYTE)){
		delete lpTmpPacket;
		
		sprintf(package_ErrMsg, ds.getDecodeString((LPSTR)encStr_The_read_header_is_invalid));
		WriteToPipe(hPipe, strlen(package_ErrMsg), package_ErrMsg, FLAG_ERROR);
		return NULL;
	}

	if(lpTmpPacket->wMagic != MAGIC_PACKET){
		delete lpTmpPacket;
		sprintf(package_ErrMsg, ds.getDecodeString((LPSTR)encStr_The_magic_header_is_unknow));
		WriteToPipe(hPipe, strlen(package_ErrMsg), package_ErrMsg, FLAG_ERROR);
		return NULL;
	}

	if(lpTmpPacket->dwDataLen){
		lpTmpPacket->lpData = new BYTE[lpTmpPacket->dwDataLen];

		if(!ReadFile(hPipe, (LPVOID)lpTmpPacket->lpData, lpTmpPacket->dwDataLen, 
			&nbRead, NULL)){
			delete lpTmpPacket;
			sprintf(package_ErrMsg, ds.getDecodeString((LPSTR)encStr_Error_cant_read_packet));
			WriteToPipe(hPipe, strlen(package_ErrMsg), package_ErrMsg, FLAG_ERROR);
			return NULL;
		}

		if(nbRead != lpTmpPacket->dwDataLen){
			delete lpTmpPacket;
			sprintf(package_ErrMsg, ds.getDecodeString((LPSTR)encStr_Error_the_data_buffer_is_inconsistent));
			WriteToPipe(hPipe, strlen(package_ErrMsg), package_ErrMsg, FLAG_ERROR);
			return NULL;
		}
		
		if(lpTmpPacket->dwFlags & FLAG_DATA_ENCRYPTED){
			DataPacketIsEncrypted = TRUE;
			
			encKey = getEncryptKeyAndFTime(&(lpTmpPacket->currentTime), FALSE);
			
			/*sprintf(msg, "fTime: 0x%08X\r\nKey: 0x%08X\r\nFlags: 0x%08X", 
				lpTmpPacket->currentTime, encKey, lpTmpPacket->dwFlags);
			MessageBox(0, msg, NULL, NULL);*/

			decryptData(lpTmpPacket->lpData, lpTmpPacket->dwDataLen, encKey);
		}
		else{
			DataPacketIsEncrypted = FALSE;
		}
		
		if(!getHashData(lpTmpPacket->lpData, lpTmpPacket->dwDataLen, TmpHash, HASH_LEN)){
			delete lpTmpPacket;
			sprintf(package_ErrMsg, ds.getDecodeString((LPSTR)encStr_Error_cant_get_hash_data));
			WriteToPipe(hPipe, strlen(package_ErrMsg), package_ErrMsg, FLAG_ERROR);			
			return NULL;
		}

		if(memcmp(TmpHash, lpTmpPacket->Hash, HASH_LEN) != 0){
			delete lpTmpPacket;
			sprintf(package_ErrMsg, ds.getDecodeString((LPSTR)encStr_Error_the_data_integrity_is_inconsistent));
			WriteToPipe(hPipe, strlen(package_ErrMsg), package_ErrMsg, FLAG_ERROR);
			return NULL;
		}		
	}

	//Desemcrptacion de los parametros, aqui por opcion de GET_FILE, ya 
	//que no se envian datos.
	if(lpTmpPacket->dwFlags & FLAG_DATA_ENCRYPTED){
		encKey = getEncryptKeyAndFTime(&(lpTmpPacket->currentTime), FALSE);
		
		decryptData(lpTmpPacket->lpParam1, MAX_PATH, encKey);
		decryptData(lpTmpPacket->lpParam2, MAX_PATH, encKey);

		lpTmpPacket->dwFlags ^= FLAG_DATA_ENCRYPTED;
	}

	return lpTmpPacket;
}


LPSP_PACKET SendCommandToShellPipe(LPCSTR lpszMachine, LPCSTR lpszCommand, DWORD dwFlags){
	LPSP_PACKET lpPacket=NULL;
	string stringTmp;
	HANDLE hPipe;
	CHAR msg[256]={0};
	DecodeString ds;

	stringTmp = ds.getDecodeString((LPSTR)NAME_PIPE);
	if(lpszMachine)
		stringTmp.replace(stringTmp.find(".", 0), 1, lpszMachine);

	if((hPipe=CreateFile(stringTmp.c_str() , FILE_READ_DATA | FILE_WRITE_DATA, 
		NULL, NULL, OPEN_EXISTING, NULL, NULL)) == INVALID_HANDLE_VALUE){
		lpPacket=NULL;
		#ifdef DEBUG_SHOW_ERROR
		sprintf(msg, "Error CreateFile: %u", GetLastError());
		MessageBox(0, msg, NULL, NULL);
		#endif
		goto Cleanup;
	}

	if(WriteToPipe(hPipe, strlen(lpszCommand)+1, (LPSTR)lpszCommand, dwFlags) == -1){
		lpPacket=NULL;
		#ifdef DEBUG_SHOW_ERROR
		MessageBox(0, "Error WriteToPipe", NULL, NULL);
		#endif
		goto Cleanup;
	}

	if(!(lpPacket = ReadPacketFromPipe(hPipe))){
		lpPacket=NULL;
		#ifdef DEBUG_SHOW_ERROR
		MessageBox(0, "Error ReadPacketFromPipe", NULL, NULL);
		#endif
		goto Cleanup;
	}

Cleanup:
	return lpPacket;
}