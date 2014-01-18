#define ENC_DEC_KEY_STRING 0xF3A1839C

DWORD GetServiceState(LPSTR lpName);
BOOL MakeConnectionToNetworkResource(LPSTR lpRemoteName, LPSTR lpUser, LPSTR lpPassword);
BOOL TerminateConnectionToNetworkResource(LPSTR lpName);
BOOL GetFunctionsEntryPoint(void);
BOOL WaitAndCheckUnloadMutex(DWORD dwInterval, DWORD dwSleepTime);

