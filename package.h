#define MAGIC_PACKET			0x5A7F6E91

#define HASH_LEN				16

//Se espera por la salida del programa
#define FLAG_WAIT_PROC_OUTPUT	1

//Los datos son una macro interna
#define FLAG_DATA_IS_MACRO		2

//Los datos estan encriptados
#define FLAG_DATA_ENCRYPTED		4

//El programa sera interactivo con el nombre de secion especificado en lpParam1
#define FLAG_INTERACTIVE		8

//El programa se ejecutara con las credenciales especificadas 
//en lpParam1 = Username; lpParam2 = Password
#define FLAG_RUN_AS_USER		16

//Especifica que los datos se guardaran en un fichero con path y nombre especificado
//en lpParam1, devuelve error si existe el fichero
#define FLAG_PUT_FILE			32

//Especifica que se devolveran los datos especificados por lpParam1
#define FLAG_GET_FILE			64

//Los datos especificados son una linea de parametros
#define FLAG_COMMAND			128

#define FLAG_MORE_DATA			256

//Especifica que hubo un error al intentar interpretar o ejecutar el pedido,
//la descripcion del error estara en lpData
#define FLAG_ERROR				0x80000000

typedef struct __SP_PACKET{
	//Siempre: 0x5A7F
	DWORD wMagic;
	
	//Longitud de los datos adjuntos al paquete
	DWORD dwDataLen;
	
	//Flags del paquete
	DWORD dwFlags;
	
	//Tiempo actual a la hora de conformar el paquete
	DWORD currentTime;
	
	//Hash de los datos antes de ser encriptados
	BYTE Hash[HASH_LEN];
	
	//Parametro dependiente del Flag
	BYTE lpParam1[MAX_PATH];

	//Parametro dependiente del Flag
	BYTE lpParam2[MAX_PATH];
	
	//Datos
	LPBYTE lpData;
}SP_PACKET, *LPSP_PACKET;


//Funciones
DWORD getEncryptKeyAndFTime(LPDWORD pfTime, BOOL ReturnFTime);
LPBYTE encryptData(LPBYTE lpData, DWORD dwDataLen, DWORD Key);
LPBYTE decryptData(LPBYTE lpData, DWORD dwDataLen, DWORD Key);
BOOL getHashData(LPBYTE lpData, DWORD cbData, LPBYTE lpOutHash, DWORD cbOutHash);
LPSP_PACKET InitizalizePackage(DWORD dwFlags, LPBYTE lpParam1, DWORD cbParam1,LPBYTE lpParam2, DWORD cbParam2, LPBYTE lpData, DWORD cbData);
BOOL WritePacketToPipe(HANDLE hPipe, LPSP_PACKET lpPacket);
LPSP_PACKET ReadPacketFromPipe(HANDLE hPipe);
