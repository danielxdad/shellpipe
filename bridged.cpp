#pragma warning(disable: 4786)

#include "stdafx.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <conio.h>
#include <vector>
#include <iostream>
#include <windows.h>
#include <time.h>
#include <queue>
#include <string>

#pragma comment(lib,"ws2_32")

using namespace std;

struct in_addr srv_addr, local_addr;
int srv_port, lst_port;

queue<string> logger;

HANDLE hThreadUnloadMutex = NULL;
HANDLE hSemaphoreLogger = NULL;

BOOL isActiveBridged = FALSE;

//=================Funciones=================
bool create_bridged_unload_mutex(){
	if(!(hThreadUnloadMutex = CreateMutex(NULL, TRUE, THREAD_UNLOAD_MUTEX))){
		if(GetLastError() == ERROR_ALREADY_EXISTS)
			return TRUE;
		return FALSE;
	}
	return TRUE;
}

int cnt_to_serv(in_addr ipaddr, int port){
	SOCKET sck;
	sockaddr_in sck_addr = {0};
	
	if((sck=socket(AF_INET,SOCK_STREAM,IPPROTO_TCP)) == -1)
		return -1;

	sck_addr.sin_family = AF_INET;
	sck_addr.sin_addr.S_un.S_addr = ipaddr.S_un.S_addr;
	sck_addr.sin_port = htons(port);

	if(connect(sck,(const sockaddr*)&sck_addr,sizeof(sockaddr)) == -1)
		return -1;

	return sck;
}

bool checkThreadUnloadMutex(){
	HANDLE hTmp;

	if((hTmp = OpenMutex(SYNCHRONIZE, FALSE, THREAD_UNLOAD_MUTEX))){
		CloseHandle(hTmp);
		return TRUE;
	}
	return FALSE;
}

int bridge_proc(int sck_client){
	int sck_server=0, r, i, thread_exit_code;
	fd_set fd_sck;
	timeval tim;
	char *buffer;
	DWORD nrecv;
	SOCKET in,out;
	CHAR msg[256] = {0};
	DecodeString ds;

	if((sck_server = cnt_to_serv(srv_addr, srv_port)) == -1){
		thread_exit_code = -1;
		sprintf(msg, ds.getDecodeString((LPSTR)encStr_Error_connect_to_server), GetCurrentThreadId(), WSAGetLastError());
		push_log_record(msg);
		goto Cleanup;
	}

	tim.tv_sec = 0;
	tim.tv_usec = 750;

	while(TRUE){
		FD_ZERO(&fd_sck);		
		FD_SET(sck_client,&fd_sck);
		FD_SET(sck_server,&fd_sck);

		if((r = select(fd_sck.fd_count, &fd_sck, 0, 0, &tim)) ==  -1){
			thread_exit_code = -1;
			sprintf(msg, ds.getDecodeString((LPSTR)encStr_Error_waiting_for_incoming_data), 
				GetCurrentThreadId(), WSAGetLastError());
			push_log_record(msg);
			goto Cleanup;
		}

		if(checkThreadUnloadMutex()){
			thread_exit_code = 0;
			sprintf(msg, ds.getDecodeString((LPSTR)encStr_Thread_unload_mutex_actived), 
				GetCurrentThreadId());
			push_log_record(msg);
			goto Cleanup;
		}
		
		if(r > 0){
			for(i=0; i<=fd_sck.fd_count-1; i++){
				if(fd_sck.fd_array[i] == sck_client){
					in = sck_client;
					out = sck_server;
				}
				else{
					in = sck_server;
					out = sck_client;
				}

				if(ioctlsocket(in,FIONREAD,&nrecv) == -1){
					thread_exit_code = -1;
					sprintf(msg, ds.getDecodeString((LPSTR)encStr_Error_get_socket_amount_data), 
						GetCurrentThreadId(), WSAGetLastError());
					push_log_record(msg);
					goto Cleanup;
				}

				//Si nrecv = 0 -> se cerro la conexion en el otro extremo
				if(!nrecv){
					thread_exit_code = 0;
					sprintf(msg, ds.getDecodeString((LPSTR)encStr_Connection_closed_in_a_side), GetCurrentThreadId());
					push_log_record(msg);
					goto Cleanup;
				}

				if(!(buffer = new char[nrecv])){
					sprintf(msg, ds.getDecodeString((LPSTR)encStr_Error_no_enough_memory), GetCurrentThreadId());
					push_log_record(msg);
					goto Cleanup;
				}

				if((nrecv = recv(in,buffer,nrecv,0)) == -1){
					delete[] buffer;
					thread_exit_code = -1;
					sprintf(msg, ds.getDecodeString((LPSTR)encStr_Error_receving_data), GetCurrentThreadId(), WSAGetLastError());
					push_log_record(msg);
					goto Cleanup;
				}

				if(send(out,buffer,nrecv,0) == -1){
					delete[] buffer;
					thread_exit_code = -1;
					sprintf(msg, ds.getDecodeString((LPSTR)encStr_Error_sending_data), GetCurrentThreadId(), WSAGetLastError());
					push_log_record(msg);
					goto Cleanup;
				}
				delete[] buffer;
			}
		}
	}

Cleanup:
	if (sck_client)
		closesocket(sck_client);
	if (sck_server)
		closesocket(sck_server);

	//sprintf(msg, "[%d] - Thread exit code: %d", GetCurrentThreadId(), thread_exit_code);
	push_log_record(msg);

	ExitThread(thread_exit_code);
	return 0;
}

int create_thread(LPVOID lpFunc, DWORD Param){
	DWORD thid;
	CHAR msg[256] = {0};
	DecodeString ds;

	if(!CreateThread(0,0,(LPTHREAD_START_ROUTINE)bridge_proc,(LPVOID)Param,0,&thid)){
		sprintf(msg, ds.getDecodeString((LPSTR)encStr_Error_creating_new_thread), GetLastError());
		push_log_record(msg);
		return FALSE;
	}

	return TRUE;
}

bool get_main_args(char *localip, int localport, char* remoteip, int remoteport){
	hostent *hent;
	in_addr ipaddr;
	CHAR msg[256] = {0};
	DecodeString ds;

	//IP to bind local interface
	if((ipaddr.S_un.S_addr = inet_addr(localip)) == INADDR_NONE){
		sprintf(msg, ds.getDecodeString((LPSTR)encStr_Error_invalid_local_address), localip);
		push_log_record(msg);
		return FALSE;
	}
	//memcpy((void*)&local_addr, (void*)&ipaddr, sizeof(sockaddr));
	local_addr.S_un.S_addr = ipaddr.S_un.S_addr;

	//Listen local port
	if(!localport || localport >= 65536){
		sprintf(msg, ds.getDecodeString((LPSTR)encStr_Error_invalid_local_port), localport);
		push_log_record(msg);
		return FALSE;
	}
	lst_port = localport;
	
	//IP or FDQN to remote server
	if((ipaddr.S_un.S_addr = inet_addr(remoteip)) == INADDR_NONE){
		if((hent = gethostbyname(remoteip))){
			memcpy((void*)&ipaddr,hent->h_addr_list[0],4);
		}
		else{
			sprintf(msg, ds.getDecodeString((LPSTR)encStr_The_IP_or_FQDN_is_invalid), 
				remoteip, WSAGetLastError());
			push_log_record(msg);
			return FALSE;
		}
	} 
	//memcpy((void*)&srv_addr, (void*)&ipaddr, sizeof(sockaddr));
	srv_addr.S_un.S_addr = ipaddr.S_un.S_addr;

	//Remote server port
	if(!remoteport || remoteport >= 65536){
		sprintf(msg, ds.getDecodeString((LPSTR)encStr_Error_invalid_remote_port), remoteport);
		push_log_record(msg);
		return FALSE;	
	}
	srv_port = remoteport;

	return TRUE;
}

bool check_is_accept_remote_host(LPBRIDGE_PARAMS bridgeParam, in_addr client_addr){
	int i;
	in_addr tmpAddr;
	hostent *hent;
	CHAR msg[256] = {0};
	DecodeString ds;
	
	if( !bridgeParam->narrayAcceptRemoteIPFDQN || !bridgeParam->arrayAcceptRemoteIPFDQN ) 
		return TRUE;
	
	for(i=0; i<= bridgeParam->narrayAcceptRemoteIPFDQN-1; ++i){
		if ((tmpAddr.S_un.S_addr = inet_addr(bridgeParam->arrayAcceptRemoteIPFDQN[i])) 
		== INADDR_NONE){
			if ((hent = gethostbyname(bridgeParam->arrayAcceptRemoteIPFDQN[i]))){
				memcpy((void*)&tmpAddr, hent->h_addr_list[0], sizeof(in_addr));
			}
			else{
				sprintf(msg, ds.getDecodeString((LPSTR)encStr_Invalid_IP_or_FQDN_in_accept_list_remote_connection),
					bridgeParam->arrayAcceptRemoteIPFDQN[i]);
				push_log_record(msg);
				continue;
			}
		}

		if (tmpAddr.S_un.S_addr == client_addr.S_un.S_addr)
			return TRUE;
	}
	
	return FALSE;
}

void push_log_record(LPSTR szEntry){
	string tmp;
	time_t current_time = time(NULL);
	char str_time[512] = {0};

	if(!szEntry ) return;
	if(!strlen(szEntry)) return;
	
	switch(WaitForSingleObject(hSemaphoreLogger, 1000)){
		case WAIT_OBJECT_0: 
			strftime(str_time, 512, "[%Y/%m/%d %H:%M:%S] - ", localtime(&current_time));
			strcat(str_time, szEntry);
			tmp = str_time;

			if(logger.size() >= 128) logger.pop();

			logger.push(tmp);
			ReleaseSemaphore(hSemaphoreLogger, 1, 0);
			break;
		case WAIT_TIMEOUT: 
			break;
	}
	return;
}

LPSTR pop_log_record(){
	LPSTR lpszTmp=NULL;
	string tmpString;
	DecodeString ds;

	switch(WaitForSingleObject(hSemaphoreLogger, 1000)){
		case WAIT_OBJECT_0: 
			if(!logger.size())
				return NULL;

			tmpString = logger.front(); 
			
			if(tmpString.length()){
				lpszTmp = new CHAR[tmpString.length() + 2];
				strcpy(lpszTmp, tmpString.c_str());
			}

			logger.pop();
			ReleaseSemaphore(hSemaphoreLogger, 1, NULL);
			break;
		case WAIT_TIMEOUT:
			lpszTmp = new CHAR[256];
			sprintf(lpszTmp, ds.getDecodeString((LPSTR)encStr_Error_wait_timeout));
			break;
		/*case WAIT_FAILED:
			lpszTmp = new CHAR[256];
			sprintf(lpszTmp, "Error, wait failed: %u", GetLastError());
			break;*/
	}
	
	return lpszTmp;
}

void unload_bridged(DWORD exitcode){
	CHAR msg[256]={0};

	isActiveBridged=FALSE;
	sprintf(msg, "Unloading");
	push_log_record(msg);
	CloseHandle(hThreadUnloadMutex);
	CloseHandle(hSemaphoreLogger);
	ExitThread(exitcode);
}

int thread_init_bridged(LPBRIDGE_PARAMS lpBridgeParam){
	WSAData wsa;
	SOCKET sck_listen, ns_client;
	int sck_count=0, addlen_remote_addr=sizeof(sockaddr);
	sockaddr_in sck_addr, remote_addr;
	fd_set fds_sck;
	timeval timev;
	CHAR msg[256]={0};
	DecodeString ds;

	if(!(hSemaphoreLogger = CreateSemaphore(NULL, 1, 1, NULL)))
		unload_bridged(-1);

	//push_log_record("Bridge init");

	if(WSAStartup(MAKEWORD(2,2),&wsa)!=0){
		sprintf(msg, ds.getDecodeString((LPSTR)encStr_Error_initialize_socket_service), WSAGetLastError());
		push_log_record(msg);
		unload_bridged(-1);
	}

	if(!get_main_args(lpBridgeParam->localip, lpBridgeParam->localport, 
		lpBridgeParam->remoteip, lpBridgeParam->remoteport)){
		//push_log_record("Error get_main_args");
		unload_bridged(-1);
	}	

	if((sck_listen = socket(AF_INET, SOCK_STREAM, IPPROTO_IP)) == -1){
		sprintf(msg, ds.getDecodeString((LPSTR)encStr_Error_creating_new_socket), WSAGetLastError());
		push_log_record(msg);
		unload_bridged(-1);
	}

	sck_addr.sin_addr.S_un.S_addr=local_addr.S_un.S_addr;
	sck_addr.sin_family=AF_INET;
	sck_addr.sin_port=htons(lst_port);
	memset((void*)&(sck_addr.sin_zero),'\0',sizeof(sck_addr.sin_zero));

	if(bind(sck_listen,(const sockaddr*)&sck_addr,sizeof(sck_addr))==-1){
		sprintf(msg, ds.getDecodeString((LPSTR)encStr_Error_binding_socket), WSAGetLastError());
		push_log_record(msg);
		unload_bridged(-1);
	}	

	if(listen(sck_listen, MAX_ACCEPT_CONNECTIONS)==-1){
		sprintf(msg, ds.getDecodeString((LPSTR)encStr_Error_set_listening_socket), WSAGetLastError());
		push_log_record(msg);
		unload_bridged(-1);
	}

	FD_ZERO(&fds_sck);
	FD_SET(sck_listen,&fds_sck);
	timev.tv_sec=0;
	timev.tv_usec=500;

	while(TRUE){
		if(select(fds_sck.fd_count,&fds_sck,0,0,&timev) == -1){
			sprintf(msg,ds.getDecodeString((LPSTR)encStr_Error_waiting_for_new_connection), WSAGetLastError());
			push_log_record(msg);
			create_bridged_unload_mutex(); 
			unload_bridged(-1);
		}
		
		if(FD_ISSET(sck_listen, &fds_sck)){
			if((ns_client = accept(sck_listen, (sockaddr*)&remote_addr, &addlen_remote_addr)) == -1){
				sprintf(msg,ds.getDecodeString((LPSTR)encStr_Error_accepting_new_connection), WSAGetLastError());
				push_log_record(msg);
				create_bridged_unload_mutex(); 
				unload_bridged(-1);
			}
			else{
				if(!check_is_accept_remote_host(lpBridgeParam, remote_addr.sin_addr)){
					closesocket(ns_client);
					sprintf(msg, ds.getDecodeString((LPSTR)encStr_Remote_client_no_accepted), inet_ntoa(remote_addr.sin_addr));
					push_log_record(msg);
				}
				else{
					if(!create_thread((LPVOID)bridge_proc,ns_client))
						closesocket(ns_client);
				}
			}
		}
		else{
			FD_SET(sck_listen,&fds_sck);
		}

		if(checkThreadUnloadMutex()){
			closesocket(sck_listen);
			unload_bridged(0);
		}
	}

	closesocket(sck_listen);
	create_bridged_unload_mutex();
	unload_bridged(0);
}
