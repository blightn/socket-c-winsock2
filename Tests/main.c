#ifdef NDEBUG
#	error Tests can be run only in debug mode
#endif

//#include <Windows.h> // Already included in "socket.h".
#include <wchar.h>
#include <assert.h>

#include <openssl/rand.h>

#include "..\Socket\socket.h"

#define TEST_IPV_4   1
//#define TEST_IPV_6   1

#define RWBUF_SIZE   64
#define RWBUF_SIZE2  MBTOB(8)

#define ITERATIONS   64
#define ITERATIONS2  8

#define THREAD_COUNT 4
#define WAIT_TIME    SECTOMS(15)

#ifdef TEST_IPV_4
#	define HOST      L"127.0.0.1"
#	define IPV       IPV_4
#elif TEST_IPV_6
#	define HOST      L"::1"
#	define IPV       IPV_6
#else
#	error Specify the IP version macro for tests (TEST_IPV_4 or TEST_IPV_6)
#endif

#define HTTP_PORT    L"80"
#define HTTPS_PORT   L"443"
#define REQUEST      "GET / HTTP/1.1\r\nHost: %S:%S\r\n\r\n"

static DWORD  g_dwCounter;
static HANDLE g_hServerEvent = NULL;
static HANDLE g_hClientEvent = NULL;
static PBYTE  g_pbTestData   = NULL;

static const BYTE g_bTestData[] = { 0x81, 0xb4, 0xfc, 0x15, 0x21, 0xaf, 0x4a, 0x72, 0x73, 0x21, 0x3a, 0xb1, 0x4e, 0x3a, 0x0f, 0x5a, 0x1a, 0x0d, 0x4f, 0x41, 0x4c, 0x0e, 0x95, 0xf1, 0xa0, 0x36, 0xac, 0x32, 0x40, 0xb7, 0x34, 0xdb };

static struct {
	PCWSTR pInput;
	PCWSTR pWant;
} g_TestPunycodeData[] =
{
	{ L"example.com", L"example.com"           },
	{ L"пример.рф",   L"xn--e1afmkfd.xn--p1ai" },
	{ L"网.中国",      L"xn--ur0a.xn--fiqs8s"   },
};

extern PWSTR(*pSocketConvertToPunycode)(PCWSTR);

static VOID Init(VOID);
static VOID Cleanup(VOID);

static VOID TestMemoryFunctions(VOID);
static VOID TestPlainMode(VOID);
static VOID TestSecureMode(VOID);
static VOID TestThreadSafety(BOOL Secure);
static VOID TestPunycodeConversion(VOID);

static PVOID TestMalloc(size_t Size, PCSTR pFile, INT Line);
static PVOID TestReAlloc(PVOID pMem, size_t Size, PCSTR pFile, INT Line);
static VOID TestFree(PVOID pMem, PCSTR pFile, INT Line);

static VOID StartTestServer(PTHREAD_START_ROUTINE pFunc, BOOL Secure);

static INT PlainRead(SOCKET Socket, PBYTE pbData, INT Size);
static INT PlainWrite(SOCKET Socket, PCBYTE pbData, INT Size);

static INT SecureRead(PSSL pSSL, PBYTE pbData, INT Size);

static DWORD WINAPI PlainClient(LPVOID pvParam);
static DWORD WINAPI SecureClient(LPVOID pvParam);

static DWORD WINAPI PlainServer(LPVOID pvParam);
static DWORD WINAPI SecureServer(LPVOID pvParam);

static DWORD WINAPI PlainMultithreadedServer(LPVOID pvParam);
static DWORD WINAPI PlainMultithreadedServerWorker(LPVOID pvParam);

static DWORD WINAPI SecureMultithreadedServer(LPVOID pvParam);
static DWORD WINAPI SecureMultithreadedServerWorker(LPVOID pvParam);

static VOID Init(VOID)
{
	INT Res;

	Res = SocketInit();
	assert(Res == TRUE);

	g_hServerEvent = CreateEventW(NULL, FALSE, FALSE, NULL);
	g_hClientEvent = CreateEventW(NULL, FALSE, FALSE, NULL);
}

static VOID Cleanup(VOID)
{
	CloseHandle(g_hClientEvent);
	g_hClientEvent = NULL;

	CloseHandle(g_hServerEvent);
	g_hServerEvent = NULL;

	SocketCleanup();
}

static VOID TestMemoryFunctions(VOID)
{
	PMALLOC  pMalloc  = NULL;
	PREALLOC pReAlloc = NULL;
	PFREE    pFree    = NULL;
	INT      Res;
	PBYTE    pbBuf    = NULL;

	SocketGetMemFunctions(&pMalloc, &pReAlloc, &pFree);
	assert(pMalloc  == CRYPTO_malloc);
	assert(pReAlloc == CRYPTO_realloc);
	assert(pFree    == CRYPTO_free);

	Res = SocketSetMemFunctions(TestMalloc, TestReAlloc, TestFree);
	assert(Res == TRUE);

	SocketGetMemFunctions(&pMalloc, &pReAlloc, &pFree);
	assert(pMalloc  == TestMalloc);
	assert(pReAlloc == TestReAlloc);
	assert(pFree    == TestFree);

	g_dwCounter = 0;

	pbBuf = (PBYTE)OPENSSL_malloc(sizeof(g_bTestData));
	assert(pbBuf != NULL);

	CopyMemory((PVOID)pbBuf, (PCVOID)g_bTestData, sizeof(g_bTestData));

	pbBuf = (PBYTE)OPENSSL_realloc((PVOID)pbBuf, sizeof(g_bTestData) * 2);
	assert(pbBuf != NULL);

	Res = !memcmp((PCVOID)pbBuf, (PCVOID)g_bTestData, sizeof(g_bTestData));

	OPENSSL_free((PVOID)pbBuf);
	pbBuf = NULL;

	assert(g_dwCounter == 3);

	Res = SocketSetMemFunctions(CRYPTO_malloc, CRYPTO_realloc, CRYPTO_free);
	assert(Res == TRUE);

	SocketGetMemFunctions(&pMalloc, &pReAlloc, &pFree);
	assert(pMalloc  == CRYPTO_malloc);
	assert(pReAlloc == CRYPTO_realloc);
	assert(pFree    == CRYPTO_free);
}

static VOID TestPlainMode(VOID)
{
	PSSOCKET   pSocket = NULL;
	IP_VERSION Version;
	INT        Res;
	BOOL       Ready;
	DWORD      dwBytes;
	BYTE       bBuf[RWBUF_SIZE];
	PBYTE      pbBuf   = NULL;

	StartTestServer((PTHREAD_START_ROUTINE)PlainServer, FALSE);

	pSocket = SocketCreate();
	assert(pSocket != NULL);

	Version = -1;
	Res = SocketGetIPVersion(pSocket, &Version);
	assert(Version == -1);
	assert(Res == FALSE);

	Res = SocketIsConnected(pSocket);
	assert(Res == FALSE);

	Ready = -1;
	Res = SocketReadyToRead(pSocket, &Ready);
	assert(Ready == -1);
	assert(Res == FALSE);

	Ready = -1;
	Res = SocketReadyToWrite(pSocket, &Ready);
	assert(Ready == -1);
	assert(Res == FALSE);

	Res = SocketBytesAvailable(pSocket, &dwBytes);
	assert(Res == FALSE);

	Res = SocketRead(pSocket, bBuf, sizeof(bBuf), FALSE);
	assert(Res == SSOCKET_ERROR);
	Res = SocketWrite(pSocket, g_bTestData, sizeof(g_bTestData));
	assert(Res == SSOCKET_ERROR);

	Res = SocketIsSecure(pSocket);
	assert(Res == FALSE);

	Res = SocketConnect(pSocket, HOST, HTTP_PORT, IPV);
	assert(Res == TRUE);

	Version = -1;
	Res = SocketGetIPVersion(pSocket, &Version);
	assert(Version == IPV);
	assert(Res == TRUE);

	Res = SocketIsConnected(pSocket);
	assert(Res == TRUE);

	Res = SocketIsSecure(pSocket);
	assert(Res == FALSE);

	Ready = TRUE;
	Res = SocketReadyToRead(pSocket, &Ready);
	assert(Ready == FALSE);
	assert(Res == TRUE);

	Ready = FALSE;
	Res = SocketReadyToWrite(pSocket, &Ready);
	assert(Ready == TRUE);
	assert(Res == TRUE);

	dwBytes = 1;
	Res = SocketBytesAvailable(pSocket, &dwBytes);
	assert(dwBytes == 0);
	assert(Res == TRUE);

	Res = SetEvent(g_hClientEvent);
	assert(Res == TRUE);

	Res = WaitForSingleObject(g_hServerEvent, WAIT_TIME);
	assert(Res == WAIT_OBJECT_0);

	Res = SocketConnect(pSocket, HOST, HTTP_PORT, IPV);
	assert(Res == TRUE);

	Res = SocketIsConnected(pSocket);
	assert(Res == TRUE);

	Res = SocketIsSecure(pSocket);
	assert(Res == FALSE);

	Ready = TRUE;
	Res = SocketReadyToRead(pSocket, &Ready);
	assert(Ready == FALSE);
	assert(Res == TRUE);

	Ready = FALSE;
	Res = SocketReadyToWrite(pSocket, &Ready);
	assert(Ready == TRUE);
	assert(Res == TRUE);

	dwBytes = 1;
	Res = SocketBytesAvailable(pSocket, &dwBytes);
	assert(dwBytes == 0);
	assert(Res == TRUE);

	Res = SocketWrite(pSocket, g_bTestData, sizeof(g_bTestData));
	assert(Res == sizeof(g_bTestData));

	Ready = TRUE;
	Res = SocketReadyToRead(pSocket, &Ready);
	assert(Ready == FALSE);
	assert(Res == TRUE);

	Ready = FALSE;
	Res = SocketReadyToWrite(pSocket, &Ready);
	assert(Ready == TRUE);
	assert(Res == TRUE);

	dwBytes = 1;
	Res = SocketBytesAvailable(pSocket, &dwBytes);
	assert(dwBytes == 0);
	assert(Res == TRUE);

	Res = SetEvent(g_hClientEvent);
	assert(Res == TRUE);

	Res = WaitForSingleObject(g_hServerEvent, WAIT_TIME);
	assert(Res == WAIT_OBJECT_0);

	Ready = FALSE;
	Res = SocketReadyToRead(pSocket, &Ready);
	assert(Ready == TRUE);
	assert(Res == TRUE);

	Ready = FALSE;
	Res = SocketReadyToWrite(pSocket, &Ready);
	assert(Ready == TRUE);
	assert(Res == TRUE);

	dwBytes = 0;
	Res = SocketBytesAvailable(pSocket, &dwBytes);
	assert(dwBytes == sizeof(g_bTestData));
	assert(Res == TRUE);

	Res = SocketRead(pSocket, bBuf, sizeof(bBuf), FALSE);
	assert(Res == sizeof(g_bTestData));
	assert(memcmp((PCVOID)bBuf, (PCVOID)g_bTestData, Res) == 0);

	Ready = TRUE;
	Res = SocketReadyToRead(pSocket, &Ready);
	assert(Ready == FALSE);
	assert(Res == TRUE);

	Ready = FALSE;
	Res = SocketReadyToWrite(pSocket, &Ready);
	assert(Ready == TRUE);
	assert(Res == TRUE);

	dwBytes = 1;
	Res = SocketBytesAvailable(pSocket, &dwBytes);
	assert(dwBytes == 0);
	assert(Res == TRUE);

	g_pbTestData = (PBYTE)OPENSSL_malloc(RWBUF_SIZE2);
	assert(g_pbTestData != NULL);

	Res = RAND_bytes(g_pbTestData, RWBUF_SIZE2);
	assert(Res == TRUE);

	Res = SocketWrite(pSocket, g_pbTestData, RWBUF_SIZE2);
	assert(Res == RWBUF_SIZE2);

	pbBuf = (PBYTE)OPENSSL_malloc(RWBUF_SIZE2);
	assert(pbBuf != NULL);

	Res = SocketRead(pSocket, pbBuf, RWBUF_SIZE2, TRUE);
	assert(Res == RWBUF_SIZE2);
	assert(memcmp((PCVOID)pbBuf, (PCVOID)g_pbTestData, Res) == 0);

	OPENSSL_free((PVOID)pbBuf);
	pbBuf = NULL;

	OPENSSL_free((PVOID)g_pbTestData);
	g_pbTestData = NULL;

	Res = SocketIsConnected(pSocket);
	assert(Res == TRUE);

	SocketDisconnect(pSocket);

	Version = -1;
	Res = SocketGetIPVersion(pSocket, &Version);
	assert(Version == -1);
	assert(Res == FALSE);

	Res = SocketIsConnected(pSocket);
	assert(Res == FALSE);

	Res = SocketIsSecure(pSocket);
	assert(Res == FALSE);

	Ready = -1;
	Res = SocketReadyToRead(pSocket, &Ready);
	assert(Ready == -1);
	assert(Res == FALSE);

	Ready = -1;
	Res = SocketReadyToWrite(pSocket, &Ready);
	assert(Ready == -1);
	assert(Res == FALSE);

	dwBytes = -1;
	Res = SocketBytesAvailable(pSocket, &dwBytes);
	assert(dwBytes == -1);
	assert(Res == FALSE);

	Res = SocketRead(pSocket, bBuf, sizeof(bBuf), FALSE);
	assert(Res == SSOCKET_ERROR);
	Res = SocketWrite(pSocket, g_bTestData, sizeof(g_bTestData));
	assert(Res == SSOCKET_ERROR);

	SocketDestroy(pSocket);
	pSocket = NULL;

	Version = -1;
	Res = SocketGetIPVersion(pSocket, &Version);
	assert(Version == -1);
	assert(Res == FALSE);

	Res = SocketIsConnected(pSocket);
	assert(Res == FALSE);

	Res = SocketIsSecure(pSocket);
	assert(Res == FALSE);

	Ready = -1;
	Res = SocketReadyToRead(pSocket, &Ready);
	assert(Ready == -1);
	assert(Res == FALSE);

	Ready = -1;
	Res = SocketReadyToWrite(pSocket, &Ready);
	assert(Ready == -1);
	assert(Res == FALSE);

	dwBytes = -1;
	Res = SocketBytesAvailable(pSocket, &dwBytes);
	assert(dwBytes == -1);
	assert(Res == FALSE);

	Res = SocketRead(pSocket, bBuf, sizeof(bBuf), FALSE);
	assert(Res == SSOCKET_ERROR);
	Res = SocketWrite(pSocket, g_bTestData, sizeof(g_bTestData));
	assert(Res == SSOCKET_ERROR);

	Res = SetEvent(g_hClientEvent);
	assert(Res == TRUE);

	Res = WaitForSingleObject(g_hServerEvent, WAIT_TIME);
	assert(Res == WAIT_OBJECT_0);
}

static VOID TestSecureMode(VOID)
{
	PSSOCKET        pSocket = NULL;
	INT             Res;
	BOOL            Ready;
	DWORD           dwBytes;
	CONTEXT_OPTIONS CtxOpts;
	SSL_OPTIONS     SSLOpts;
	PSSL_CTX        pCtx    = NULL;
	BYTE            bBuf[RWBUF_SIZE];
	PBYTE           pbBuf   = NULL;

	StartTestServer((PTHREAD_START_ROUTINE)SecureServer, TRUE);

	pSocket = SocketCreate();
	assert(pSocket != NULL);

	Res = SocketIsConnected(pSocket);
	assert(Res == FALSE);

	Ready = -1;
	Res = SocketReadyToRead(pSocket, &Ready);
	assert(Ready == -1);
	assert(Res == FALSE);

	Ready = -1;
	Res = SocketReadyToWrite(pSocket, &Ready);
	assert(Ready == -1);
	assert(Res == FALSE);

	dwBytes = -1;
	Res = SocketBytesAvailable(pSocket, &dwBytes);
	assert(dwBytes == -1);
	assert(Res == FALSE);

	Res = SocketRead(pSocket, bBuf, sizeof(bBuf), FALSE);
	assert(Res == SSOCKET_ERROR);
	Res = SocketWrite(pSocket, g_bTestData, sizeof(g_bTestData));
	assert(Res == SSOCKET_ERROR);

	Res = SocketIsSecure(pSocket);
	assert(Res == FALSE);

	Res = SocketConnect(pSocket, HOST, HTTPS_PORT, IPV);
	assert(Res == TRUE);

	Res = SocketIsConnected(pSocket);
	assert(Res == TRUE);

	Res = SocketIsSecure(pSocket);
	assert(Res == FALSE);

	Ready = TRUE;
	Res = SocketReadyToRead(pSocket, &Ready);
	assert(Ready == FALSE);
	assert(Res == TRUE);

	Ready = FALSE;
	Res = SocketReadyToWrite(pSocket, &Ready);
	assert(Ready == TRUE);
	assert(Res == TRUE);

	dwBytes = 1;
	Res = SocketBytesAvailable(pSocket, &dwBytes);
	assert(dwBytes == 0);
	assert(Res == TRUE);

	CtxOpts.pCertPath        = "..\\Misc\\client\\cert.pem";
	CtxOpts.pPrivKeyPath     = "..\\Misc\\client\\key.pem";
	CtxOpts.VerifyCert       = TRUE;
	CtxOpts.pCAPath          = "..\\Misc\\server\\cert.pem";
	CtxOpts.UseCompression   = FALSE;
	CtxOpts.UseRenegotiation = FALSE;
	CtxOpts.UseSessionCache  = FALSE;
	CtxOpts.TLSMinVer        = TLSV_1_3;
	CtxOpts.TLSMaxVer        = TLSV_1_3;

	pCtx = SocketCreateContext(&CtxOpts);
	assert(pCtx != NULL);

	SSLOpts.pCertPath        = "..\\Misc\\client\\cert.crt";
	SSLOpts.pPrivKeyPath     = "..\\Misc\\client\\key.der";
	SSLOpts.VerifyCert       = TRUE;
	SSLOpts.UseCompression   = FALSE;
	SSLOpts.UseRenegotiation = FALSE;
	SSLOpts.TLSMinVer        = TLSV_1_3;
	SSLOpts.TLSMaxVer        = TLSV_1_3;

	Res = SocketSecure(pSocket, pCtx, &SSLOpts);
	assert(Res == TRUE);

	Res = SocketIsConnected(pSocket);
	assert(Res == TRUE);

	Res = SocketIsSecure(pSocket);
	assert(Res == TRUE);

	Ready = -1;
	Res = SocketReadyToRead(pSocket, &Ready);
	assert(Ready == -1);
	assert(Res == FALSE);

	Ready = -1;
	Res = SocketReadyToWrite(pSocket, &Ready);
	assert(Ready == -1);
	assert(Res == FALSE);

	dwBytes = -1;
	Res = SocketBytesAvailable(pSocket, &dwBytes);
	assert(dwBytes == -1);
	assert(Res == FALSE);

	Res = SocketSecure(pSocket, pCtx, NULL);
	assert(Res == FALSE);

	Res = SocketIsConnected(pSocket);
	assert(Res == TRUE);

	Res = SocketIsSecure(pSocket);
	assert(Res == TRUE);

	Res = SocketWrite(pSocket, g_bTestData, sizeof(g_bTestData));
	assert(Res == sizeof(g_bTestData));

	Ready = -1;
	Res = SocketReadyToRead(pSocket, &Ready);
	assert(Ready == -1);
	assert(Res == FALSE);

	Ready = -1;
	Res = SocketReadyToWrite(pSocket, &Ready);
	assert(Ready == -1);
	assert(Res == FALSE);

	dwBytes = -1;
	Res = SocketBytesAvailable(pSocket, &dwBytes);
	assert(dwBytes == -1);
	assert(Res == FALSE);

	Res = SetEvent(g_hClientEvent);
	assert(Res == TRUE);

	Res = WaitForSingleObject(g_hServerEvent, WAIT_TIME);
	assert(Res == WAIT_OBJECT_0);

	Ready = -1;
	Res = SocketReadyToRead(pSocket, &Ready);
	assert(Ready == -1);
	assert(Res == FALSE);

	Ready = -1;
	Res = SocketReadyToWrite(pSocket, &Ready);
	assert(Ready == -1);
	assert(Res == FALSE);

	dwBytes = -1;
	Res = SocketBytesAvailable(pSocket, &dwBytes);
	assert(dwBytes == -1);
	assert(Res == FALSE);

	Res = SocketRead(pSocket, bBuf, sizeof(bBuf), FALSE);
	assert(Res == sizeof(g_bTestData));
	assert(memcmp((PCVOID)bBuf, (PCVOID)g_bTestData, Res) == 0);

	Ready = -1;
	Res = SocketReadyToRead(pSocket, &Ready);
	assert(Ready == -1);
	assert(Res == FALSE);

	Ready = -1;
	Res = SocketReadyToWrite(pSocket, &Ready);
	assert(Ready == -1);
	assert(Res == FALSE);

	dwBytes = -1;
	Res = SocketBytesAvailable(pSocket, &dwBytes);
	assert(dwBytes == -1);
	assert(Res == FALSE);

	g_pbTestData = (PBYTE)OPENSSL_malloc(RWBUF_SIZE2);
	assert(g_pbTestData != NULL);

	Res = RAND_bytes(g_pbTestData, RWBUF_SIZE2);
	assert(Res == TRUE);

	Res = SocketWrite(pSocket, g_pbTestData, RWBUF_SIZE2);
	assert(Res == RWBUF_SIZE2);

	pbBuf = (PBYTE)OPENSSL_malloc(RWBUF_SIZE2);
	assert(pbBuf != NULL);

	Res = SocketRead(pSocket, pbBuf, RWBUF_SIZE2, TRUE);
	assert(Res == RWBUF_SIZE2);
	assert(memcmp((PCVOID)pbBuf, (PCVOID)g_pbTestData, Res) == 0);

	OPENSSL_free((PVOID)pbBuf);
	pbBuf = NULL;

	OPENSSL_free((PVOID)g_pbTestData);
	g_pbTestData = NULL;

	Res = SocketIsConnected(pSocket);
	assert(Res == TRUE);

	SocketDisconnect(pSocket);

	Res = SocketIsConnected(pSocket);
	assert(Res == FALSE);

	Res = SocketIsSecure(pSocket);
	assert(Res == FALSE);

	Ready = -1;
	Res = SocketReadyToRead(pSocket, &Ready);
	assert(Ready == -1);
	assert(Res == FALSE);

	Ready = -1;
	Res = SocketReadyToWrite(pSocket, &Ready);
	assert(Ready == -1);
	assert(Res == FALSE);

	dwBytes = -1;
	Res = SocketBytesAvailable(pSocket, &dwBytes);
	assert(dwBytes == -1);
	assert(Res == FALSE);

	Res = SocketRead(pSocket, bBuf, sizeof(bBuf), FALSE);
	assert(Res == SSOCKET_ERROR);
	Res = SocketWrite(pSocket, g_bTestData, sizeof(g_bTestData));
	assert(Res == SSOCKET_ERROR);

	SocketDestroy(pSocket);
	pSocket = NULL;

	Res = SocketIsConnected(pSocket);
	assert(Res == FALSE);

	Res = SocketIsSecure(pSocket);
	assert(Res == FALSE);

	Ready = -1;
	Res = SocketReadyToRead(pSocket, &Ready);
	assert(Ready == -1);
	assert(Res == FALSE);

	Ready = -1;
	Res = SocketReadyToWrite(pSocket, &Ready);
	assert(Ready == -1);
	assert(Res == FALSE);

	dwBytes = -1;
	Res = SocketBytesAvailable(pSocket, &dwBytes);
	assert(dwBytes == -1);
	assert(Res == FALSE);

	Res = SocketRead(pSocket, bBuf, sizeof(bBuf), FALSE);
	assert(Res == SSOCKET_ERROR);
	Res = SocketWrite(pSocket, g_bTestData, sizeof(g_bTestData));
	assert(Res == SSOCKET_ERROR);

	SocketDestroyContext(pCtx);
	pCtx = NULL;

	Res = SetEvent(g_hClientEvent);
	assert(Res == TRUE);

	Res = WaitForSingleObject(g_hServerEvent, WAIT_TIME);
	assert(Res == WAIT_OBJECT_0);
}

static VOID TestThreadSafety(BOOL Secure)
{
	CONTEXT_OPTIONS CtxOpts;
	PSSL_CTX        pCtx = NULL;
	HANDLE          hThreads[THREAD_COUNT];
	DWORD           i,
	                Res;

	g_pbTestData = (PBYTE)OPENSSL_malloc(RWBUF_SIZE2);
	assert(g_pbTestData != NULL);

	Res = RAND_bytes(g_pbTestData, RWBUF_SIZE2);
	assert(Res == TRUE);

	StartTestServer((PTHREAD_START_ROUTINE)(Secure ? SecureMultithreadedServer : PlainMultithreadedServer), Secure);

	if (Secure)
	{
		CtxOpts.pCertPath        = "..\\Misc\\client\\cert.crt";
		CtxOpts.pPrivKeyPath     = "..\\Misc\\client\\key.der";
		CtxOpts.VerifyCert       = TRUE;
		CtxOpts.pCAPath          = "..\\Misc\\server\\cert.pem";
		CtxOpts.UseCompression   = FALSE;
		CtxOpts.UseRenegotiation = FALSE;
		CtxOpts.UseSessionCache  = FALSE;
		CtxOpts.TLSMinVer        = TLSV_1_3;
		CtxOpts.TLSMaxVer        = TLSV_1_3;

		pCtx = SocketCreateContext(&CtxOpts);
		assert(pCtx != NULL);
	}

	ZeroMemory((PVOID)&hThreads, sizeof(hThreads));

	for (i = 0; i < ARRAYSIZE(hThreads); ++i)
	{
		hThreads[i] = CreateThread(NULL, 0, (PTHREAD_START_ROUTINE)(Secure ? SecureClient : PlainClient), (PVOID)pCtx, 0, NULL);
		assert(hThreads[i] != NULL);
	}

	Res = WaitForMultipleObjects(ARRAYSIZE(hThreads), hThreads, TRUE, WAIT_TIME);
	assert(Res == WAIT_OBJECT_0);

	for (i = 0; i < ARRAYSIZE(hThreads); ++i)
	{
		CloseHandle(hThreads[i]);
		hThreads[i] = NULL;
	}

	if (pCtx)
	{
		SocketDestroyContext(pCtx);
		pCtx = NULL;
	}

	OPENSSL_free((PVOID)g_pbTestData);
	g_pbTestData = NULL;
}

static VOID TestPunycodeConversion(VOID)
{
	DWORD i;
	PWSTR pConv = NULL;

	assert(ARRAYSIZE(g_TestPunycodeData) > 0);

	for (i = 0; i < ARRAYSIZE(g_TestPunycodeData); ++i)
	{
		pConv = pSocketConvertToPunycode(g_TestPunycodeData[i].pInput);
		assert(pConv != NULL);
		assert(memcmp((PCVOID)pConv, (PCVOID)g_TestPunycodeData[i].pWant, (((size_t)lstrlenW(g_TestPunycodeData[i].pWant) + 1) * sizeof(WCHAR))) == 0);

		OPENSSL_free((PVOID)pConv);
		pConv = NULL;
	}
}

static PVOID TestMalloc(size_t Size, PCSTR pFile, INT Line)
{
	++g_dwCounter;

	return HeapAlloc(GetProcessHeap(), 0, Size);
}

static PVOID TestReAlloc(PVOID pMem, size_t Size, PCSTR pFile, INT Line)
{
	++g_dwCounter;

	return HeapReAlloc(GetProcessHeap(), 0, pMem, Size);
}

static VOID TestFree(PVOID pMem, PCSTR pFile, INT Line)
{
	++g_dwCounter;

	HeapFree(GetProcessHeap(), 0, pMem);
}

static VOID StartTestServer(PTHREAD_START_ROUTINE pFunc, BOOL Secure)
{
	ADDRINFOW  Hints;
	PADDRINFOW pAddrInfo = NULL;
	INT        Res,
	           Enabled;
	SOCKET     Socket    = INVALID_SOCKET;
	HANDLE     hThread   = NULL;

	ZeroMemory(&Hints, sizeof(Hints));
	Hints.ai_family   = IPV;
	Hints.ai_socktype = SOCK_STREAM;
	Hints.ai_protocol = IPPROTO_TCP;
	Hints.ai_flags    = AI_PASSIVE;

	Res = GetAddrInfoW(NULL, Secure ? HTTPS_PORT : HTTP_PORT, &Hints, &pAddrInfo);
	assert(Res == 0);
	assert(pAddrInfo != NULL);
	
	Socket = WSASocketW(pAddrInfo->ai_family, pAddrInfo->ai_socktype, pAddrInfo->ai_protocol, NULL, (GROUP)0, 0);
	assert(Socket != INVALID_SOCKET);

	Enabled = TRUE;
	Res = setsockopt(Socket, SOL_SOCKET, SO_REUSEADDR, (PCCHAR)&Enabled, sizeof(Enabled)); // Либо ждать завершения потока сервера.
	assert(Res == 0);

	Res = bind(Socket, pAddrInfo->ai_addr, (INT)pAddrInfo->ai_addrlen);
	assert(Res != SOCKET_ERROR);

	Res = listen(Socket, SOMAXCONN);
	assert(Res != SOCKET_ERROR);

	hThread = CreateThread(NULL, 0, pFunc, (PVOID)Socket, 0, NULL);
	assert(hThread != NULL);

	CloseHandle(hThread);
	hThread = NULL;

	FreeAddrInfoW(pAddrInfo);
	pAddrInfo = NULL;
}

static INT PlainRead(SOCKET Socket, PBYTE pbData, INT Size)
{
	INT Read = 0,
	    Res  = 0;

	while (Size)
	{
		if ((Res = recv(Socket, (PCHAR)&pbData[Read], Size, 0)) <= 0)
			break;

		Read += Res;
		Size -= Res;
	}

	assert(Size == 0);
	assert(Res > 0);

	return Read;
}

static INT PlainWrite(SOCKET Socket, PCBYTE pbData, INT Size)
{
	INT Sent = 0,
	    Res  = 0;

	while (Size)
	{
		if ((Res = send(Socket, (PCCHAR)&pbData[Sent], Size, 0)) <= 0)
			break;

		Sent += Res;
		Size -= Res;
	}

	assert(Size == 0);
	assert(Res > 0);

	return Sent;
}

static INT SecureRead(PSSL pSSL, PBYTE pbData, INT Size)
{
	INT Read = 0,
	    Res  = 0;

	while (Size)
	{
		if ((Res = SSL_read(pSSL, (PVOID)&pbData[Read], Size)) <= 0)
			break;

		Size -= Res;
		Read += Res;
	}

	assert(Size == 0);
	assert(Res > 0);

	return Read;
}

static DWORD WINAPI PlainClient(LPVOID pvParam)
{
	PSSOCKET pSocket = NULL;
	INT      Res;
	DWORD    i;
	BYTE     bBuf[RWBUF_SIZE];
	PBYTE    pbBuf   = NULL;

	// Random delay.

	pSocket = SocketCreate();
	assert(pSocket != NULL);

	Res = SocketConnect(pSocket, HOST, HTTP_PORT, IPV);
	assert(Res == TRUE);

	for (i = 0; i < ITERATIONS; ++i)
	{
		Res = SocketWrite(pSocket, g_bTestData, sizeof(g_bTestData));
		assert(Res == sizeof(g_bTestData));

		Res = SocketRead(pSocket, bBuf, sizeof(bBuf), FALSE);
		assert(Res == sizeof(g_bTestData));
		assert(memcmp((PCVOID)bBuf, (PCVOID)g_bTestData, Res) == 0);
	}

	pbBuf = (PBYTE)OPENSSL_malloc(RWBUF_SIZE2);
	assert(pbBuf != NULL);

	for (i = 0; i < ITERATIONS2; ++i)
	{
		Res = SocketWrite(pSocket, g_pbTestData, RWBUF_SIZE2);
		assert(Res == RWBUF_SIZE2);

		Res = SocketRead(pSocket, pbBuf, RWBUF_SIZE2, TRUE);
		assert(Res == RWBUF_SIZE2);
		assert(memcmp((PCVOID)pbBuf, (PCVOID)g_pbTestData, Res) == 0);
	}

	OPENSSL_free((PVOID)pbBuf);
	pbBuf = NULL;

	SocketDestroy(pSocket);
	pSocket = NULL;

	return 0;
}

static DWORD WINAPI SecureClient(LPVOID pvParam)
{
	PSSL_CTX    pCtx    = (PSSL_CTX)pvParam;
	PSSOCKET    pSocket = NULL;
	INT         Res;
	SSL_OPTIONS SSLOpts;
	DWORD       i;
	BYTE        bBuf[RWBUF_SIZE];
	PBYTE       pbBuf   = NULL;

	// Random delay.

	assert(pCtx != NULL);

	pSocket = SocketCreate();
	assert(pSocket != NULL);

	Res = SocketConnect(pSocket, HOST, HTTPS_PORT, IPV);
	assert(Res == TRUE);

	SSLOpts.pCertPath        = "..\\Misc\\client\\cert.pem";
	SSLOpts.pPrivKeyPath     = "..\\Misc\\client\\key.pem";
	SSLOpts.VerifyCert       = TRUE;
	SSLOpts.UseCompression   = FALSE;
	SSLOpts.UseRenegotiation = FALSE;
	SSLOpts.TLSMinVer        = TLSV_1_3;
	SSLOpts.TLSMaxVer        = TLSV_1_3;

	Res = SocketSecure(pSocket, pCtx, &SSLOpts);
	assert(Res == TRUE);

	for (i = 0; i < ITERATIONS; ++i)
	{
		Res = SocketWrite(pSocket, g_bTestData, sizeof(g_bTestData));
		assert(Res == sizeof(g_bTestData));

		Res = SocketRead(pSocket, bBuf, sizeof(bBuf), FALSE);
		assert(Res == sizeof(g_bTestData));
		assert(memcmp((PCVOID)bBuf, (PCVOID)g_bTestData, Res) == 0);
	}

	pbBuf = (PBYTE)OPENSSL_malloc(RWBUF_SIZE2);
	assert(pbBuf != NULL);

	for (i = 0; i < ITERATIONS2; ++i)
	{
		Res = SocketWrite(pSocket, g_pbTestData, RWBUF_SIZE2);
		assert(Res == RWBUF_SIZE2);

		Res = SocketRead(pSocket, pbBuf, RWBUF_SIZE2, TRUE);
		assert(Res == RWBUF_SIZE2);
		assert(memcmp((PCVOID)pbBuf, (PCVOID)g_pbTestData, Res) == 0);
	}

	OPENSSL_free((PVOID)pbBuf);
	pbBuf = NULL;

	SocketDestroy(pSocket);
	pSocket = NULL;

	return 0;
}

static DWORD WINAPI PlainServer(LPVOID pvParam)
{
	SOCKET Server = (SOCKET)pvParam,
	       Client = INVALID_SOCKET;
	BYTE   bBuf[RWBUF_SIZE];
	INT    Res;
	PBYTE  pbBuf  = NULL;

	assert(Server != INVALID_SOCKET);

	Client = WSAAccept(Server, NULL, NULL, NULL, (DWORD_PTR)NULL);
	assert(Client != INVALID_SOCKET);

	Res = WaitForSingleObject(g_hClientEvent, WAIT_TIME);
	assert(Res == WAIT_OBJECT_0);

	Res = shutdown(Client, SD_BOTH);
	assert(Res == 0);
	Res = closesocket(Client);
	assert(Res == 0);
	Client = INVALID_SOCKET;

	Res = SetEvent(g_hServerEvent);
	assert(Res == TRUE);

	Client = WSAAccept(Server, NULL, NULL, NULL, (DWORD_PTR)NULL);
	assert(Client != INVALID_SOCKET);

	Res = WaitForSingleObject(g_hClientEvent, WAIT_TIME);
	assert(Res == WAIT_OBJECT_0);

	Res = recv(Client, (PCHAR)bBuf, sizeof(bBuf), 0);
	assert(Res == sizeof(g_bTestData));
	assert(memcmp((PCVOID)bBuf, (PCVOID)g_bTestData, Res) == 0);

	Res = PlainWrite(Client, bBuf, Res);
	assert(Res == sizeof(g_bTestData));

	Res = SetEvent(g_hServerEvent);
	assert(Res == TRUE);

	pbBuf = (PBYTE)OPENSSL_malloc(RWBUF_SIZE2);
	assert(pbBuf != NULL);

	Res = PlainRead(Client, pbBuf, RWBUF_SIZE2);
	assert(Res == RWBUF_SIZE2);
	assert(memcmp((PCVOID)pbBuf, (PCVOID)g_pbTestData, Res) == 0);

	Res = PlainWrite(Client, pbBuf, Res);
	assert(Res == RWBUF_SIZE2);

	OPENSSL_free((PVOID)pbBuf);
	pbBuf = NULL;

	Res = WaitForSingleObject(g_hClientEvent, WAIT_TIME);
	assert(Res == WAIT_OBJECT_0);

	Res = shutdown(Client, SD_BOTH);
	assert(Res == 0);
	Res = closesocket(Client);
	assert(Res == 0);
	Client = INVALID_SOCKET;

	Res = closesocket(Server);
	assert(Res == 0);
	Server = INVALID_SOCKET;

	Res = SetEvent(g_hServerEvent);
	assert(Res == TRUE);

	return 0;
}

static DWORD WINAPI SecureServer(LPVOID pvParam)
{
	SOCKET   Server = (SOCKET)pvParam,
	         Client = INVALID_SOCKET;
	PSSL_CTX pCtx   = NULL;
	PSSL     pSSL   = NULL;
	BYTE     bBuf[RWBUF_SIZE];
	INT      Res;
	PBYTE    pbBuf  = NULL;

	assert(Server != INVALID_SOCKET);

	pCtx = SSL_CTX_new(TLS_server_method());
	assert(pCtx != NULL);

	SSL_CTX_clear_mode(pCtx, SSL_MODE_ENABLE_PARTIAL_WRITE);
	SSL_CTX_set_mode(pCtx, SSL_MODE_AUTO_RETRY);

	SSL_CTX_set_verify(pCtx, SSL_VERIFY_PEER, NULL);
	SSL_CTX_load_verify_locations(pCtx, "..\\Misc\\client\\cert.pem", NULL);
	SSL_CTX_use_certificate_file(pCtx, "..\\Misc\\server\\cert.pem", SSL_FILETYPE_PEM);
	SSL_CTX_use_PrivateKey_file(pCtx, "..\\Misc\\server\\key.pem", SSL_FILETYPE_PEM);

	SSL_CTX_set_options(pCtx, SSL_OP_NO_COMPRESSION);
	SSL_CTX_set_options(pCtx, SSL_OP_NO_RENEGOTIATION);
	SSL_CTX_set_session_cache_mode(pCtx, SSL_SESS_CACHE_OFF);

	SSL_CTX_set_min_proto_version(pCtx, TLS1_3_VERSION);
	SSL_CTX_set_max_proto_version(pCtx, TLS1_3_VERSION);

	Client = WSAAccept(Server, NULL, NULL, NULL, (DWORD_PTR)NULL);
	assert(Client != INVALID_SOCKET);

	pSSL = SSL_new(pCtx);
	assert(pSSL != NULL);

	Res = SSL_set_fd(pSSL, (INT)Client);
	assert(Res == OPENSSL_OK);

	Res = SSL_accept(pSSL);
	assert(Res == OPENSSL_OK);

	Res = WaitForSingleObject(g_hClientEvent, WAIT_TIME);
	assert(Res == WAIT_OBJECT_0);

	Res = SSL_read(pSSL, (PVOID)bBuf, sizeof(bBuf));
	assert(Res == sizeof(g_bTestData));
	assert(memcmp((PCVOID)bBuf, (PCVOID)g_bTestData, Res) == 0);

	Res = SSL_write(pSSL, (PCVOID)bBuf, Res);
	assert(Res == sizeof(g_bTestData));

	Res = SetEvent(g_hServerEvent);
	assert(Res == TRUE);

	pbBuf = (PBYTE)OPENSSL_malloc(RWBUF_SIZE2);
	assert(pbBuf != NULL);

	Res = SecureRead(pSSL, pbBuf, RWBUF_SIZE2);
	assert(Res == RWBUF_SIZE2);
	assert(memcmp((PCVOID)pbBuf, (PCVOID)g_pbTestData, Res) == 0);

	Res = SSL_write(pSSL, (PCVOID)pbBuf, Res);
	assert(Res == RWBUF_SIZE2);

	OPENSSL_free((PVOID)pbBuf);
	pbBuf = NULL;

	Res = WaitForSingleObject(g_hClientEvent, WAIT_TIME);
	assert(Res == WAIT_OBJECT_0);

	Res = SSL_shutdown(pSSL);
	assert(Res == 0);
	SSL_free(pSSL);
	pSSL = NULL;

	SSL_CTX_free(pCtx);
	pCtx = NULL;

	Res = shutdown(Client, SD_BOTH);
	assert(Res == 0);
	Res = closesocket(Client);
	assert(Res == 0);
	Client = INVALID_SOCKET;

	Res = closesocket(Server);
	assert(Res == 0);
	Server = INVALID_SOCKET;

	Res = SetEvent(g_hServerEvent);
	assert(Res == TRUE);

	return 0;
}

static DWORD WINAPI PlainMultithreadedServer(LPVOID pvParam)
{
	SOCKET Server = (SOCKET)pvParam,
	       Client = INVALID_SOCKET;
	HANDLE hThreads[THREAD_COUNT];
	DWORD  i;
	INT    Res;

	assert(Server != INVALID_SOCKET);

	ZeroMemory((PVOID)&hThreads, sizeof(hThreads));

	for (i = 0; i < ARRAYSIZE(hThreads); ++i)
	{
		Client = WSAAccept(Server, NULL, NULL, NULL, (DWORD_PTR)NULL);
		assert(Client != INVALID_SOCKET);

		hThreads[i] = CreateThread(NULL, 0, (PTHREAD_START_ROUTINE)PlainMultithreadedServerWorker, (PVOID)Client, 0, NULL);
		assert(hThreads[i] != NULL);
	}

	Res = WaitForMultipleObjects(ARRAYSIZE(hThreads), hThreads, TRUE, WAIT_TIME);
	assert(Res == WAIT_OBJECT_0);

	for (i = 0; i < ARRAYSIZE(hThreads); ++i)
	{
		CloseHandle(hThreads[i]);
		hThreads[i] = NULL;
	}

	Res = closesocket(Server);
	assert(Res == 0);
	Server = INVALID_SOCKET;

	return 0;
}

static DWORD WINAPI PlainMultithreadedServerWorker(LPVOID pvParam)
{
	SOCKET Client = (SOCKET)pvParam;
	DWORD  i;
	BYTE   bBuf[RWBUF_SIZE];
	INT    Res;
	PBYTE  pbBuf  = NULL;

	for (i = 0; i < ITERATIONS; ++i)
	{
		Res = recv(Client, (PCHAR)bBuf, sizeof(bBuf), 0);
		assert(Res == sizeof(g_bTestData));
		assert(memcmp((PCVOID)bBuf, (PCVOID)g_bTestData, Res) == 0);

		Res = PlainWrite(Client, bBuf, Res);
		assert(Res == sizeof(g_bTestData));
	}

	pbBuf = (PBYTE)OPENSSL_malloc(RWBUF_SIZE2);
	assert(pbBuf != NULL);

	for (i = 0; i < ITERATIONS2; ++i)
	{
		Res = PlainRead(Client, pbBuf, RWBUF_SIZE2);
		assert(Res == RWBUF_SIZE2);
		assert(memcmp((PCVOID)pbBuf, (PCVOID)g_pbTestData, Res) == 0);

		Res = PlainWrite(Client, pbBuf, Res);
		assert(Res == RWBUF_SIZE2);
	}

	OPENSSL_free((PVOID)pbBuf);
	pbBuf = NULL;

	Res = shutdown(Client, SD_BOTH);
	assert(Res == 0);
	Res = closesocket(Client);
	assert(Res == 0);
	Client = INVALID_SOCKET;

	return 0;
}

static DWORD WINAPI SecureMultithreadedServer(LPVOID pvParam)
{
	SOCKET   Server = (SOCKET)pvParam,
	         Client = INVALID_SOCKET;
	PSSL_CTX pCtx   = NULL;
	PSSL     pSSL   = NULL;
	HANDLE   hThreads[THREAD_COUNT];
	DWORD    i;
	INT      Res;

	assert(Server != INVALID_SOCKET);

	pCtx = SSL_CTX_new(TLS_server_method());
	assert(pCtx != NULL);

	SSL_CTX_clear_mode(pCtx, SSL_MODE_ENABLE_PARTIAL_WRITE);
	SSL_CTX_set_mode(pCtx, SSL_MODE_AUTO_RETRY);

	SSL_CTX_set_verify(pCtx, SSL_VERIFY_PEER, NULL);
	SSL_CTX_load_verify_locations(pCtx, "..\\Misc\\client\\cert.pem", NULL);
	SSL_CTX_use_certificate_file(pCtx, "..\\Misc\\server\\cert.pem", SSL_FILETYPE_PEM);
	SSL_CTX_use_PrivateKey_file(pCtx, "..\\Misc\\server\\key.pem", SSL_FILETYPE_PEM);

	SSL_CTX_set_options(pCtx, SSL_OP_NO_COMPRESSION);
	SSL_CTX_set_options(pCtx, SSL_OP_NO_RENEGOTIATION);
	SSL_CTX_set_session_cache_mode(pCtx, SSL_SESS_CACHE_OFF);

	SSL_CTX_set_min_proto_version(pCtx, TLS1_3_VERSION);
	SSL_CTX_set_max_proto_version(pCtx, TLS1_3_VERSION);

	ZeroMemory((PVOID)&hThreads, sizeof(hThreads));

	for (i = 0; i < ARRAYSIZE(hThreads); ++i)
	{
		Client = WSAAccept(Server, NULL, NULL, NULL, (DWORD_PTR)NULL);
		assert(Client != INVALID_SOCKET);

		pSSL = SSL_new(pCtx);
		assert(pSSL != NULL);

		Res = SSL_set_fd(pSSL, (INT)Client);
		assert(Res == OPENSSL_OK);

		Res = SSL_accept(pSSL);
		assert(Res == OPENSSL_OK);

		hThreads[i] = CreateThread(NULL, 0, (PTHREAD_START_ROUTINE)SecureMultithreadedServerWorker, (PVOID)pSSL, 0, NULL);
		assert(hThreads[i] != NULL);
	}

	Res = WaitForMultipleObjects(ARRAYSIZE(hThreads), hThreads, TRUE, WAIT_TIME);
	assert(Res == WAIT_OBJECT_0);

	for (i = 0; i < ARRAYSIZE(hThreads); ++i)
	{
		CloseHandle(hThreads[i]);
		hThreads[i] = NULL;
	}

	Res = closesocket(Server);
	assert(Res == 0);
	Server = INVALID_SOCKET;

	SSL_CTX_free(pCtx);
	pCtx = NULL;

	return 0;
}

static DWORD WINAPI SecureMultithreadedServerWorker(LPVOID pvParam)
{
	PSSL   pSSL   = (PSSL)pvParam;
	DWORD  i;
	BYTE   bBuf[RWBUF_SIZE];
	INT    Res;
	PBYTE  pbBuf  = NULL;
	SOCKET Client = INVALID_SOCKET;

	for (i = 0; i < ITERATIONS; ++i)
	{
		Res = SSL_read(pSSL, (PVOID)bBuf, sizeof(bBuf));
		assert(Res == sizeof(g_bTestData));
		assert(memcmp((PCVOID)bBuf, (PCVOID)g_bTestData, Res) == 0);

		Res = SSL_write(pSSL, (PCVOID)bBuf, Res);
		assert(Res == sizeof(g_bTestData));
	}

	pbBuf = (PBYTE)OPENSSL_malloc(RWBUF_SIZE2);
	assert(pbBuf != NULL);

	for (i = 0; i < ITERATIONS2; ++i)
	{
		Res = SecureRead(pSSL, pbBuf, RWBUF_SIZE2);
		assert(Res == RWBUF_SIZE2);
		assert(memcmp((PCVOID)pbBuf, (PCVOID)g_pbTestData, Res) == 0);

		Res = SSL_write(pSSL, (PCVOID)pbBuf, Res);
		assert(Res == RWBUF_SIZE2);
	}

	OPENSSL_free((PVOID)pbBuf);
	pbBuf = NULL;

	Client = SSL_get_fd(pSSL);
	assert(Client != 0);
	assert(Client != INVALID_SOCKET);

	Res = SSL_shutdown(pSSL);
	assert(Res == 0);
	SSL_free(pSSL);
	pSSL = NULL;

	Res = shutdown(Client, SD_BOTH);
	assert(Res == 0);
	Res = closesocket(Client);
	assert(Res == 0);
	Client = INVALID_SOCKET;

	return 0;
}

INT wmain(INT Argc, WCHAR* pArgv[], WCHAR* pEnv[])
{
	DWORD i;

	wprintf(L"OpenSSL version: %S\n\n", OPENSSL_VERSION_TEXT);

	Init();

	TestMemoryFunctions();

	TestPlainMode();
	TestSecureMode();

	TestThreadSafety(FALSE);
	TestThreadSafety(TRUE);

	TestPunycodeConversion();

	for (i = 0; i < ITERATIONS2; ++i)
	{
		TestThreadSafety(FALSE);
		TestThreadSafety(TRUE);
	}

	Cleanup();

	wprintf(L"All tests passed\n\n");
	system("pause");

	return 0;
}
