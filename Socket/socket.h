#ifndef _SOCKET_H_
#define _SOCKET_H_

#ifndef WIN32_LEAN_AND_MEAN
#	define WIN32_LEAN_AND_MEAN
#endif

#include <WinSock2.h>
#include <WS2tcpip.h>
#include <mstcpip.h>
#include <Shlwapi.h>

#include <openssl/ssl.h>

#pragma comment(lib, "WS2_32.lib")
#pragma comment(lib, "Crypt32.lib")  // Cert*()
#pragma comment(lib, "Normaliz.lib") // IdnToAscii()
#pragma comment(lib, "Shlwapi.lib")  // StrRStrIA()

#pragma comment(lib, "libcrypto.lib")
#pragma comment(lib, "libssl.lib")

#ifdef _DEBUG
#	define WITH_DEBUG_OUTPUT
#endif

#define MBTOB(mb)	  ((mb) * 1024 * 1024)

#define SECTOMS(s)	  ((s) * 1000)
#define MINTOMS(m)	  ((m) * SECTOMS(60))

#define KA_TIMEOUT	  MINTOMS(5)
#define KA_INTERVAL   SECTOMS(1)

#define SSOCKET_ERROR SOCKET_ERROR
#define OPENSSL_OK	  1

typedef const VOID* PCVOID;
typedef const BYTE* PCBYTE;
typedef const CHAR* PCCHAR;

typedef SSL_CTX*	PSSL_CTX;
typedef SSL*		PSSL;

typedef PVOID		(*PMALLOC)	(size_t, PCSTR, INT);
typedef PVOID		(*PREALLOC) (PVOID, size_t, PCSTR, INT);
typedef VOID		(*PFREE)	(PVOID, PCSTR, INT);

typedef PMALLOC*	PPMALLOC;
typedef PREALLOC*	PPREALLOC;
typedef PFREE*		PPFREE;

typedef enum {
	IPV_4 = AF_INET,
	IPV_6 = AF_INET6,
} IP_VERSION, *PIP_VERSION;

typedef enum {
	SA_READ,
	SA_WRITE,
} SOCKET_ACTION;

typedef enum {
	TLSV_1_2 = TLS1_2_VERSION,
	TLSV_1_3 = TLS1_3_VERSION,
} TLS_VERSION;

typedef struct
{
	SOCKET Socket;
	PSSL   pSSL;
	PSTR   pHost;
} SSOCKET, *PSSOCKET;

typedef struct tcp_keepalive KEEPALIVE;

typedef struct
{
	PCSTR		pCertPath;
	PCSTR		pPrivKeyPath;
	BOOL		VerifyCert;
	PCSTR		pCAPath;
	BOOL		UseCompression;
	BOOL		UseRenegotiation;
	BOOL		UseSessionCache;
	TLS_VERSION TLSMinVer;
	TLS_VERSION TLSMaxVer;
} CONTEXT_OPTIONS, *PCONTEXT_OPTIONS;

typedef const CONTEXT_OPTIONS* PCCONTEXT_OPTIONS;

typedef struct
{
	PCSTR		pCertPath;
	PCSTR		pPrivKeyPath;
	BOOL		VerifyCert;
	BOOL		UseCompression;
	BOOL		UseRenegotiation;
	TLS_VERSION TLSMinVer;
	TLS_VERSION TLSMaxVer;
} SSL_OPTIONS, *PSSL_OPTIONS;

typedef const SSL_OPTIONS* PCSSL_OPTIONS;

VOID SocketGetMemFunctions(PPMALLOC ppMalloc, PPREALLOC ppReAlloc, PPFREE ppFree);
BOOL SocketSetMemFunctions(PMALLOC pMalloc, PREALLOC pReAlloc, PFREE pFree);

BOOL SocketInit(VOID);
VOID SocketCleanup(VOID);

PSSOCKET SocketCreate(VOID);
VOID SocketDestroy(PSSOCKET pSocket);

BOOL SocketConnect(PSSOCKET pSocket, PCWSTR pDomain, PCWSTR pPort, IP_VERSION Version);
VOID SocketDisconnect(PSSOCKET pSocket);
BOOL SocketIsConnected(PSSOCKET pSocket);

BOOL SocketGetIPVersion(PSSOCKET pSocket, PIP_VERSION pVersion);

INT SocketRead(PSSOCKET pSocket, PBYTE pbData, INT Size, BOOL WaitAll);
BOOL SocketReadEx(PSSOCKET pSocket, PBYTE pbData, INT Size, PINT pRead, BOOL WaitAll);

INT SocketWrite(PSSOCKET pSocket, PCBYTE pbData, INT Size);
BOOL SocketWriteEx(PSSOCKET pSocket, PCBYTE pbData, INT Size, PINT pWritten);

BOOL SocketReadyToRead(PSSOCKET pSocket, PBOOL pReady);
BOOL SocketReadyToWrite(PSSOCKET pSocket, PBOOL pReady);
BOOL SocketReadyTo(PSSOCKET pSocket, SOCKET_ACTION Action, PBOOL pReady);

BOOL SocketBytesAvailable(PSSOCKET pSocket, PDWORD pdwBytes);

PSSL_CTX SocketCreateContext(PCCONTEXT_OPTIONS pOpts);
VOID SocketDestroyContext(PSSL_CTX pCtx);

BOOL SocketSecure(PSSOCKET pSocket, PSSL_CTX pCtx, PCSSL_OPTIONS pOpts);
BOOL SocketIsSecure(PSSOCKET pSocket);

static BOOL SocketSetupSocket(SOCKET Socket);
static BOOL SocketSetupContext(PSSL_CTX pCtx, PCCONTEXT_OPTIONS pOpts);
static BOOL SocketSetupSSL(PSSL pSSL, PCSSL_OPTIONS pOpts);

static BOOL SocketCreateSocket(PSSOCKET pSocket, IP_VERSION Version);
static PWSTR SocketConvertToPunycode(PCWSTR pDomain);
static BOOL SocketReadyForAction(PSSOCKET pSocket, SOCKET_ACTION Action, PBOOL pReady);

static PWSTR SocketAToW(PCSTR pStr);
static PSTR SocketWToA(PCWSTR pStr);

#endif // _SOCKET_H_
