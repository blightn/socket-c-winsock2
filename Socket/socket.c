#include "socket.h"

#ifdef WITH_DEBUG_OUTPUT
#	define DEBUG_MSGW(format, ...)  { \
	                                    SYSTEMTIME Time123; \
	                                    WCHAR      Tmp123[512]; \
	                                    INT        Res123; \
	                                    GetLocalTime(&Time123); \
	                                    Res123 = wsprintfW(Tmp123, L"[%02u:%02u:%02u:%03u]: " __FILEW__ L" - " __FUNCTIONW__ L"(): " format L"\n", \
		                                    Time123.wHour, Time123.wMinute, Time123.wSecond, Time123.wMilliseconds, __VA_ARGS__); \
	                                    if (Res123 >= 512) DebugBreak(); \
	                                    OutputDebugStringW(Tmp123); \
	                                }
#else
#	define DEBUG_MSGW(format, ...)  {}
#endif

#ifdef _DEBUG
(*pSocketConvertToPunycode)() = (INT(*)())SocketConvertToPunycode;
#endif

VOID SocketGetMemFunctions(PPMALLOC ppMalloc, PPREALLOC ppReAlloc, PPFREE ppFree)
{
	CRYPTO_get_mem_functions(ppMalloc, ppReAlloc, ppFree);
}

BOOL SocketSetMemFunctions(PMALLOC pMalloc, PREALLOC pReAlloc, PFREE pFree)
{
	return CRYPTO_set_mem_functions(pMalloc, pReAlloc, pFree) == OPENSSL_OK;
}

BOOL SocketInit(VOID)
{
	WSADATA Data;

	return !WSAStartup(MAKEWORD(2U, 2U), &Data);
}

VOID SocketCleanup(VOID)
{
	WSACleanup();
}

PSSOCKET SocketCreate(VOID)
{
	PSSOCKET pSocket = NULL;

	if (pSocket = (PSSOCKET)OPENSSL_zalloc(sizeof(SSOCKET)))
	{
		pSocket->Socket = INVALID_SOCKET;
	}
	else
		DEBUG_MSGW(L"Can't allocate memory for pSocket");

	return pSocket;
}

VOID SocketDestroy(PSSOCKET pSocket)
{
	if (!pSocket)
	{
		DEBUG_MSGW(L"pSocket == NULL");
		return;
	}

	SocketDisconnect(pSocket);

	OPENSSL_free((PVOID)pSocket);
	pSocket = NULL;
}

// Without automatic disconnect for already connected sockets.
BOOL SocketConnect(PSSOCKET pSocket, PCWSTR pDomain, PCWSTR pPort, IP_VERSION Version)
{
	PWSTR      pConv = NULL;
	ADDRINFOW  Hints;
	PADDRINFOW pInfo = NULL;
	BOOL       Ok    = FALSE;

	if (!pSocket)
	{
		DEBUG_MSGW(L"pSocket == NULL");
		return FALSE;
	}

	if (!pDomain)
	{
		DEBUG_MSGW(L"pDomain == NULL");
		return FALSE;
	}

	if (!lstrlenW(pDomain))
	{
		DEBUG_MSGW(L"pDomain == L\"\"");
		return FALSE;
	}

	if (!pPort)
	{
		DEBUG_MSGW(L"pPort == NULL");
		return FALSE;
	}

	if (!lstrlenW(pPort))
	{
		DEBUG_MSGW(L"pPort == L\"\"");
		return FALSE;
	}

	if (Version != IPV_4 && Version != IPV_6)
	{
		DEBUG_MSGW(L"Invalid IP version: %d", Version);
		return FALSE;
	}

	SocketDisconnect(pSocket);

	if (SocketCreateSocket(pSocket, Version))
	{
		if (pConv = SocketConvertToPunycode(pDomain))
		{
			if (pSocket->pHost = SocketWToA(pConv))
			{
				ZeroMemory((PVOID)&Hints, sizeof(Hints));
				Hints.ai_family   = Version;
				Hints.ai_socktype = SOCK_STREAM;
				Hints.ai_protocol = IPPROTO_TCP;

				if (!GetAddrInfoW(pConv, pPort, &Hints, &pInfo) && pInfo)
				{
					if (WSAConnect(pSocket->Socket, pInfo->ai_addr, (INT)pInfo->ai_addrlen, NULL, NULL, NULL, NULL) != SOCKET_ERROR) // x64.
					{
						Ok = TRUE;
					}
					else
						DEBUG_MSGW(L"Can't connect to %s:%s - %d", pConv, pPort, WSAGetLastError());

					FreeAddrInfoW(pInfo);
					pInfo = NULL;
				}
				else
					DEBUG_MSGW(L"Can't resolve %s:%s - %d", pConv, pPort, WSAGetLastError());
			}
			else
				DEBUG_MSGW(L"SocketWToA() error");

			OPENSSL_free((PVOID)pConv);
			pConv = NULL;
		}
		else
			DEBUG_MSGW(L"Can't convert %s to punycode", pDomain);
	}
	else
		DEBUG_MSGW(L"Can't create the socket");

	if (!Ok)
	{
		SocketDisconnect(pSocket);
	}

	return Ok;
}

VOID SocketDisconnect(PSSOCKET pSocket)
{
	if (!pSocket)
	{
		DEBUG_MSGW(L"pSocket == NULL");
		return;
	}

	if (pSocket->pSSL)
	{
		SSL_shutdown(pSocket->pSSL);

		SSL_free(pSocket->pSSL);
		pSocket->pSSL = NULL;
	}

	if (pSocket->Socket != INVALID_SOCKET)
	{
		shutdown(pSocket->Socket, SD_BOTH);

		closesocket(pSocket->Socket);
		pSocket->Socket = INVALID_SOCKET;
	}

	if (pSocket->pHost)
	{
		OPENSSL_free((PVOID)pSocket->pHost);
		pSocket->pHost = NULL;
	}
}

BOOL SocketIsConnected(PSSOCKET pSocket)
{
	if (!pSocket)
	{
		DEBUG_MSGW(L"pSocket == NULL");
		return FALSE;
	}

	if (pSocket->Socket == INVALID_SOCKET)
	{
		DEBUG_MSGW(L"pSocket->Socket == INVALID_SOCKET");
		return FALSE;
	}

	return pSocket->pSSL ? SocketIsSecure(pSocket) : send(pSocket->Socket, (PCHAR)NULL, 0, 0) == 0 || WSAGetLastError() == WSAENOBUFS;
}

// Only for connected sockets.
BOOL SocketGetIPVersion(PSSOCKET pSocket, PIP_VERSION pVersion)
{
	WSAPROTOCOL_INFOW Info;

	if (!pSocket)
	{
		DEBUG_MSGW(L"pSocket == NULL");
		return FALSE;
	}

	if (pSocket->Socket == INVALID_SOCKET)
	{
		DEBUG_MSGW(L"pSocket->Socket == INVALID_SOCKET");
		return FALSE;
	}

	if (!pVersion)
	{
		DEBUG_MSGW(L"pVersion == NULL");
		return FALSE;
	}

	if (WSADuplicateSocketW(pSocket->Socket, GetCurrentProcessId(), &Info) == SOCKET_ERROR)
	{
		DEBUG_MSGW(L"WSADuplicateSocketW() error: %d", WSAGetLastError());
		return FALSE;
	}

	*pVersion = Info.iAddressFamily;

	return TRUE;
}

INT SocketRead(PSSOCKET pSocket, PBYTE pbData, INT Size, BOOL WaitAll)
{
	INT Read = 0;

	return SocketReadEx(pSocket, pbData, Size, &Read, WaitAll) ? Read : SSOCKET_ERROR;
}

BOOL SocketReadEx(PSSOCKET pSocket, PBYTE pbData, INT Size, PINT pRead, BOOL WaitAll)
{
	INT Read = 0,
	    Res  = 1;

	if (!pSocket)
	{
		DEBUG_MSGW(L"pSocket == NULL");
		return FALSE;
	}

	if (pSocket->Socket == INVALID_SOCKET)
	{
		DEBUG_MSGW(L"pSocket->Socket == INVALID_SOCKET");
		return FALSE;
	}

	if (!pbData)
	{
		DEBUG_MSGW(L"pbData == NULL");
		return FALSE;
	}

	if (Size <= 0)
	{
		DEBUG_MSGW(L"Size <= 0");
		return FALSE;
	}

	if (pSocket->pSSL)
	{
		if (WaitAll)
		{
			while (Size)
			{
				if ((Res = SSL_read(pSocket->pSSL, (PVOID)&pbData[Read], Size)) <= 0)
					break;

				Size -= Res;
				Read += Res;
			}

			if (Res > 0)
			{
				Res = Read;
			}
		}
		else
			Res = SSL_read(pSocket->pSSL, (PVOID)pbData, Size);
	}
	else
		Res = recv(pSocket->Socket, (PCHAR)pbData, Size, WaitAll ? MSG_WAITALL : 0);

	if (Res > 0)
	{
		DEBUG_MSGW(L"Bytes read: %d", Res);

		if (pRead)
		{
			*pRead = Res;
		}
	}
	else
	{
		if (pSocket->pSSL)
		{
			DEBUG_MSGW(L"SSL_read() error: %d", SSL_get_error(pSocket->pSSL, Res));
		}
		else
			DEBUG_MSGW(L"recv() error: %d", WSAGetLastError());
	}

	return Res > 0;
}

INT SocketWrite(PSSOCKET pSocket, PCBYTE pbData, INT Size)
{
	INT Sent = 0;

	return SocketWriteEx(pSocket, pbData, Size, &Sent) ? Sent : SSOCKET_ERROR;
}

BOOL SocketWriteEx(PSSOCKET pSocket, PCBYTE pbData, INT Size, PINT pWritten)
{
	INT Res     = 0,
	    Written = 0;

	if (!pSocket)
	{
		DEBUG_MSGW(L"pSocket == NULL");
		return FALSE;
	}

	if (pSocket->Socket == INVALID_SOCKET)
	{
		DEBUG_MSGW(L"pSocket->Socket == INVALID_SOCKET");
		return FALSE;
	}

	if (!pbData)
	{
		DEBUG_MSGW(L"pbData == NULL");
		return FALSE;
	}

	if (Size <= 0)
	{
		DEBUG_MSGW(L"Size <= 0");
		return FALSE;
	}

	if (pSocket->pSSL)
	{
		Res = SSL_write(pSocket->pSSL, (PCVOID)pbData, Size);
	}
	else
	{
		while (Size)
		{
			if ((Res = send(pSocket->Socket, (PCCHAR)&pbData[Written], Size, 0)) <= 0)
				break;

			Size    -= Res;
			Written += Res;
		}

		if (Res > 0)
		{
			Res = Written;
		}
	}

	if (Res > 0)
	{
		DEBUG_MSGW(L"Bytes sent: %d", Res);

		if (pWritten)
		{
			*pWritten = Res;
		}
	}
	else
	{
		if (pSocket->pSSL)
		{
			DEBUG_MSGW(L"SSL_write() error: %d", SSL_get_error(pSocket->pSSL, Res));
		}
		else
			DEBUG_MSGW(L"send() error: %d", WSAGetLastError());
	}

	return Res > 0;
}

// Only for connected plain sockets (pSocket->Socket != INVALID_SOCKET).
BOOL SocketReadyToRead(PSSOCKET pSocket, PBOOL pReady)
{
	if (!pSocket)
	{
		DEBUG_MSGW(L"pSocket == NULL");
		return FALSE;
	}

	if (pSocket->Socket == INVALID_SOCKET)
	{
		DEBUG_MSGW(L"pSocket->Socket == INVALID_SOCKET");
		return FALSE;
	}

	if (pSocket->pSSL)
	{
		DEBUG_MSGW(L"pSocket->pSSL != NULL");
		return FALSE;
	}

	if (!pReady)
	{
		DEBUG_MSGW(L"pReady == NULL");
		return FALSE;
	}

	return SocketReadyForAction(pSocket, SA_READ, pReady);
}

// Only for connected plain sockets (pSocket->Socket != INVALID_SOCKET).
BOOL SocketReadyToWrite(PSSOCKET pSocket, PBOOL pReady)
{
	if (!pSocket)
	{
		DEBUG_MSGW(L"pSocket == NULL");
		return FALSE;
	}

	if (pSocket->Socket == INVALID_SOCKET)
	{
		DEBUG_MSGW(L"pSocket->Socket == INVALID_SOCKET");
		return FALSE;
	}

	if (pSocket->pSSL)
	{
		DEBUG_MSGW(L"pSocket->pSSL != NULL");
		return FALSE;
	}

	if (!pReady)
	{
		DEBUG_MSGW(L"pReady == NULL");
		return FALSE;
	}

	return SocketReadyForAction(pSocket, SA_WRITE, pReady);
}

// Only for connected plain sockets (pSocket->Socket != INVALID_SOCKET).
BOOL SocketReadyTo(PSSOCKET pSocket, SOCKET_ACTION Action, PBOOL pReady)
{
	if (!pSocket)
	{
		DEBUG_MSGW(L"pSocket == NULL");
		return FALSE;
	}

	if (pSocket->Socket == INVALID_SOCKET)
	{
		DEBUG_MSGW(L"pSocket->Socket == INVALID_SOCKET");
		return FALSE;
	}

	if (pSocket->pSSL)
	{
		DEBUG_MSGW(L"pSocket->pSSL != NULL");
		return FALSE;
	}

	if (Action != SA_READ && Action != SA_WRITE)
	{
		DEBUG_MSGW(L"Invalid action: %d", Action);
		return FALSE;
	}

	if (!pReady)
	{
		DEBUG_MSGW(L"pReady == NULL");
		return FALSE;
	}

	return SocketReadyForAction(pSocket, Action, pReady);
}

BOOL SocketBytesAvailable(PSSOCKET pSocket, PDWORD pdwBytes)
{
	DWORD dwDummy;

	if (!pSocket)
	{
		DEBUG_MSGW(L"pSocket == NULL");
		return FALSE;
	}

	if (pSocket->Socket == INVALID_SOCKET)
	{
		DEBUG_MSGW(L"pSocket->Socket == INVALID_SOCKET");
		return FALSE;
	}

	if (pSocket->pSSL)
	{
		DEBUG_MSGW(L"pSocket->pSSL != NULL");
		return FALSE;
	}

	if (!pdwBytes)
	{
		DEBUG_MSGW(L"pdwBytes == 0");
		return FALSE;
	}

	if (WSAIoctl(pSocket->Socket, FIONREAD, NULL, 0, (PVOID)pdwBytes, sizeof(DWORD), &dwDummy, NULL, NULL) == SOCKET_ERROR)
	{
		DEBUG_MSGW(L"WSAIoctl() error: %d", WSAGetLastError());
		return FALSE;
	}

	return TRUE;
}

PSSL_CTX SocketCreateContext(PCCONTEXT_OPTIONS pOpts)
{
	CONTEXT_OPTIONS Opts;
	PSSL_CTX        pCtx = NULL;

	if (!pOpts)
	{
		DEBUG_MSGW(L"pOpts == NULL. Using default settings...");

		Opts.pCertPath        = NULL;
		Opts.pPrivKeyPath     = NULL;
		Opts.VerifyCert       = TRUE;
		Opts.pCAPath          = NULL;  // Use default OpenSSL CAs.
		Opts.UseCompression   = FALSE; // Disable compression by default to prevent CRIME.
		Opts.UseRenegotiation = FALSE;
		Opts.UseSessionCache  = TRUE;
		Opts.TLSMinVer        = TLSV_1_3;
		Opts.TLSMaxVer        = TLSV_1_3;

		pOpts = &Opts;
	}

	if (pCtx = SSL_CTX_new(TLS_client_method()))
	{
		if (!SocketSetupContext(pCtx, pOpts))
		{
			DEBUG_MSGW(L"Invalid option(s)");

			SocketDestroyContext(pCtx);
			pCtx = NULL;
		}
	}

	return pCtx;
}

VOID SocketDestroyContext(PSSL_CTX pCtx)
{
	if (pCtx)
	{
		SSL_CTX_free(pCtx);
		pCtx = NULL;
	}
}

BOOL SocketSecure(PSSOCKET pSocket, PSSL_CTX pCtx, PCSSL_OPTIONS pOpts)
{
	BOOL Ok = FALSE;

	if (!pSocket)
	{
		DEBUG_MSGW(L"pSocket == NULL");
		return FALSE;
	}

	if (pSocket->Socket == INVALID_SOCKET)
	{
		DEBUG_MSGW(L"pSocket->Socket == INVALID_SOCKET");
		return FALSE;
	}

	if (pSocket->pSSL)
	{
		DEBUG_MSGW(L"pSocket->pSSL != NULL");
		return FALSE;
	}

	if (!pCtx)
	{
		DEBUG_MSGW(L"pCtx == NULL");
		return FALSE;
	}

	if (!pOpts)
	{
		DEBUG_MSGW(L"pOpts == NULL. Using settings from context");
	}

	if (pSocket->pSSL = SSL_new(pCtx))
	{
		if (pOpts == NULL || SocketSetupSSL(pSocket->pSSL, pOpts))
		{
			if (SSL_set_fd(pSocket->pSSL, (INT)pSocket->Socket) == OPENSSL_OK)
			{
				if (pSocket->pHost)
				{
					SSL_set_tlsext_host_name(pSocket->pSSL, pSocket->pHost);
				}

				Ok = SSL_connect(pSocket->pSSL) == OPENSSL_OK;

				DEBUG_MSGW(L"Result of peer certificate verification: %d (0 is OK)", SSL_get_verify_result(pSocket->pSSL));
			}
			else
				DEBUG_MSGW(L"Can't assign socket for SSL");
		}
		else
			DEBUG_MSGW(L"Invalid option(s)");

		if (!Ok)
		{
			SSL_free(pSocket->pSSL);
			pSocket->pSSL = NULL;
		}
	}

	return Ok;
}

BOOL SocketIsSecure(PSSOCKET pSocket)
{
	if (!pSocket)
	{
		DEBUG_MSGW(L"pSocket == NULL");
		return FALSE;
	}

	return pSocket->pSSL != NULL && SSL_is_init_finished(pSocket->pSSL) == OPENSSL_OK;
}

static BOOL SocketSetupSocket(SOCKET Socket)
{
	BOOL      Enabled;
	KEEPALIVE KeepAlive;
	DWORD     dwBytes;
	BOOL      Ok = FALSE;

	Enabled = TRUE;

	// The SO_KEEPALIVE option for a socket is disabled (set to FALSE) by default.
	if (setsockopt(Socket, SOL_SOCKET, SO_KEEPALIVE, (PCSTR)&Enabled, sizeof(Enabled)) != SOCKET_ERROR)
	{
		// For TCP, the default keep-alive timeout is 2 hours and the keep-alive interval is 1 second.
		// On Windows Vista and later, the number of keep-alive probes (data retransmissions) is set to 10 and cannot be changed.
		KeepAlive.onoff             = TRUE;
		KeepAlive.keepalivetime     = KA_TIMEOUT;
		KeepAlive.keepaliveinterval = KA_INTERVAL;

		if (WSAIoctl(Socket, SIO_KEEPALIVE_VALS, (LPVOID)&KeepAlive, sizeof(KeepAlive), NULL, 0, &dwBytes, NULL, NULL) != SOCKET_ERROR)
		{
			Enabled = TRUE;

			if (setsockopt(Socket, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, (PCSTR)&Enabled, sizeof(Enabled)) != SOCKET_ERROR)
			{
				Ok = TRUE;
			}
			else
				DEBUG_MSGW(L"Can't enable SO_EXCLUSIVEADDRUSE feature: %d", WSAGetLastError());
		}
		else
			DEBUG_MSGW(L"Can't set SIO_KEEPALIVE_VALS option: %d", WSAGetLastError());
	}
	else
		DEBUG_MSGW(L"Can't enable SO_KEEPALIVE feature: %d", WSAGetLastError());

	return Ok;
}

static BOOL SocketSetupContext(PSSL_CTX pCtx, PCCONTEXT_OPTIONS pOpts)
{
	DWORD dwAttr;

	if (pOpts->pCertPath != NULL && pOpts->pPrivKeyPath == NULL || pOpts->pCertPath == NULL && pOpts->pPrivKeyPath != NULL)
	{
		DEBUG_MSGW(L"The certificate and private key paths must be specified both or neither");
		return FALSE;
	}

	if (pOpts->VerifyCert && pOpts->pCAPath && (dwAttr = GetFileAttributesA(pOpts->pCAPath)) == INVALID_FILE_ATTRIBUTES)
	{
		DEBUG_MSGW(L"Invalid path: %S", pOpts->pCAPath);
		return FALSE;
	}

	if (pOpts->TLSMinVer != TLSV_1_2 && pOpts->TLSMinVer != TLSV_1_3 || pOpts->TLSMaxVer != TLSV_1_2 && pOpts->TLSMaxVer != TLSV_1_3)
	{
		DEBUG_MSGW(L"Invalid TLS version(s): %d-%d", pOpts->TLSMinVer, pOpts->TLSMaxVer);
		return FALSE;
	}

	SSL_CTX_clear_mode(pCtx, SSL_MODE_ENABLE_PARTIAL_WRITE);
	SSL_CTX_set_mode(pCtx, SSL_MODE_AUTO_RETRY);

	if (pOpts->pCertPath && pOpts->pPrivKeyPath)
	{
		if (StrRStrIA(pOpts->pCertPath, NULL, ".pem"))
		{
			if (SSL_CTX_use_certificate_chain_file(pCtx, pOpts->pCertPath) != OPENSSL_OK)
			{
				DEBUG_MSGW(L"Invalid certificate path: %S", pOpts->pCertPath);
				return FALSE;
			}
		}
		else if (SSL_CTX_use_certificate_file(pCtx, pOpts->pCertPath, SSL_FILETYPE_ASN1) != OPENSSL_OK)
		{
			DEBUG_MSGW(L"Invalid certificate path: %S", pOpts->pCertPath);
			return FALSE;
		}

		if (SSL_CTX_use_PrivateKey_file(pCtx, pOpts->pPrivKeyPath, StrRStrIA(pOpts->pPrivKeyPath, NULL, ".pem") ? SSL_FILETYPE_PEM : SSL_FILETYPE_ASN1) != OPENSSL_OK)
		{
			DEBUG_MSGW(L"Invalid private key path: %S", pOpts->pPrivKeyPath);
			return FALSE;
		}

		if (SSL_CTX_check_private_key(pCtx) != OPENSSL_OK)
		{
			DEBUG_MSGW(L"Invalid private key");
			return FALSE;
		}
	}

	SSL_CTX_set_verify(pCtx, pOpts->VerifyCert ? SSL_VERIFY_PEER : SSL_VERIFY_NONE, NULL);

	if (pOpts->VerifyCert)
	{
		if (pOpts->pCAPath)
		{
			if (!SSL_CTX_load_verify_locations(pCtx, dwAttr & FILE_ATTRIBUTE_DIRECTORY ? NULL : pOpts->pCAPath, pOpts->pCAPath))
			{
				DEBUG_MSGW(L"Invalid certificate(s): %S", pOpts->pCAPath);
				return FALSE;
			}
		}
		else
		{
			if (!SSL_CTX_set_default_verify_file(pCtx))
			{
				DEBUG_MSGW(L"Can't get default OpenSSL CAs");
				return FALSE;
			}
		}
	}

	if (pOpts->UseCompression)
	{
		SSL_CTX_clear_options(pCtx, SSL_OP_NO_COMPRESSION);
	}
	else
		SSL_CTX_set_options(pCtx, SSL_OP_NO_COMPRESSION);

	if (pOpts->UseRenegotiation)
	{
		SSL_CTX_clear_options(pCtx, SSL_OP_NO_RENEGOTIATION);
	}
	else
		SSL_CTX_set_options(pCtx, SSL_OP_NO_RENEGOTIATION);

	if (!pOpts->UseSessionCache)
	{
		SSL_CTX_set_session_cache_mode(pCtx, SSL_SESS_CACHE_OFF);
	}

	SSL_CTX_set_min_proto_version(pCtx, pOpts->TLSMinVer);
	SSL_CTX_set_max_proto_version(pCtx, pOpts->TLSMaxVer);

	return TRUE;
}

static BOOL SocketSetupSSL(PSSL pSSL, PCSSL_OPTIONS pOpts)
{
	if (pOpts->pCertPath != NULL && pOpts->pPrivKeyPath == NULL || pOpts->pCertPath == NULL && pOpts->pPrivKeyPath != NULL)
	{
		DEBUG_MSGW(L"The certificate and private key paths must be specified both or neither");
		return FALSE;
	}

	if (pOpts->TLSMinVer != TLSV_1_2 && pOpts->TLSMinVer != TLSV_1_3 || pOpts->TLSMaxVer != TLSV_1_2 && pOpts->TLSMaxVer != TLSV_1_3)
	{
		DEBUG_MSGW(L"Invalid TLS version(s): %d-%d", pOpts->TLSMinVer, pOpts->TLSMaxVer);
		return FALSE;
	}

	SSL_set_mode(pSSL, SSL_MODE_AUTO_RETRY);

	if (pOpts->pCertPath && pOpts->pPrivKeyPath)
	{
		if (StrRStrIA(pOpts->pCertPath, NULL, ".pem"))
		{
			if (SSL_use_certificate_chain_file(pSSL, pOpts->pCertPath) != OPENSSL_OK)
			{
				DEBUG_MSGW(L"Invalid certificate path: %S", pOpts->pCertPath);
				return FALSE;
			}
		}
		else if (SSL_use_certificate_file(pSSL, pOpts->pCertPath, SSL_FILETYPE_ASN1) != OPENSSL_OK)
		{
			DEBUG_MSGW(L"Invalid certificate path: %S", pOpts->pCertPath);
			return FALSE;
		}

		if (SSL_use_PrivateKey_file(pSSL, pOpts->pPrivKeyPath, StrRStrIA(pOpts->pPrivKeyPath, NULL, ".pem") ? SSL_FILETYPE_PEM : SSL_FILETYPE_ASN1) != OPENSSL_OK)
		{
			DEBUG_MSGW(L"Invalid private key path: %S", pOpts->pPrivKeyPath);
			return FALSE;
		}

		// SSL_check_private_key() performs the same check for ssl. If no key/certificate was explicitly added for this ssl, the last item added into ctx will be checked.
		if (SSL_check_private_key(pSSL) != OPENSSL_OK)
		{
			DEBUG_MSGW(L"Invalid private key");
			return FALSE;
		}
	}

	SSL_set_verify(pSSL, pOpts->VerifyCert ? SSL_VERIFY_PEER : SSL_VERIFY_NONE, NULL);

	if (pOpts->UseCompression)
	{
		SSL_clear_options(pSSL, SSL_OP_NO_COMPRESSION);
	}
	else
		SSL_set_options(pSSL, SSL_OP_NO_COMPRESSION);

	if (pOpts->UseRenegotiation)
	{
		SSL_clear_options(pSSL, SSL_OP_NO_RENEGOTIATION);
	}
	else
		SSL_set_options(pSSL, SSL_OP_NO_RENEGOTIATION);

	SSL_set_min_proto_version(pSSL, pOpts->TLSMinVer);
	SSL_set_max_proto_version(pSSL, pOpts->TLSMaxVer);

	return TRUE;
}

static BOOL SocketCreateSocket(PSSOCKET pSocket, IP_VERSION Version)
{
	pSocket->Socket = WSASocketW(Version, SOCK_STREAM, IPPROTO_TCP, NULL, (GROUP)0, 0);

	if (pSocket->Socket == INVALID_SOCKET)
	{
		DEBUG_MSGW(L"WSASocketW() error: %d", WSAGetLastError());
		return FALSE;
	}

	if (!SocketSetupSocket(pSocket->Socket))
	{
		DEBUG_MSGW(L"Can't setup the socket");
		return FALSE;
	}

	return TRUE;
}

static PWSTR SocketConvertToPunycode(PCWSTR pDomain)
{
	INT   Size;
	PWSTR pRes = NULL;

	if ((Size = IdnToAscii(0, pDomain, lstrlenW(pDomain) + 1, NULL, 0)) > 0)
	{
		if (pRes = (PWSTR)OPENSSL_malloc((SIZE_T)Size * sizeof(WCHAR)))
		{
			if (IdnToAscii(0, pDomain, lstrlenW(pDomain) + 1, pRes, Size) != Size)
			{
				DEBUG_MSGW(L"Failed to convert %s: %d", pDomain, GetLastError());

				OPENSSL_free((PVOID)pRes);
				pRes = NULL;
			}
		}
		else
			DEBUG_MSGW(L"Can't allocate memory for pRes");
	}
	else
		DEBUG_MSGW(L"Can't get the required buffer size: %d", GetLastError());

	return pRes;
}

static BOOL SocketReadyForAction(PSSOCKET pSocket, SOCKET_ACTION Action, PBOOL pReady)
{
	FD_SET  fdset;
	TIMEVAL Timeout;
	INT     Res;

	FD_ZERO(&fdset);
	FD_SET(pSocket->Socket, &fdset);

	timerclear(&Timeout);

	if (Action == SA_READ)
	{
		Res = select(0, &fdset, NULL, NULL, &Timeout);
	}
	else
		Res = select(0, NULL, &fdset, NULL, &Timeout);

	if (Res == SOCKET_ERROR)
	{
		DEBUG_MSGW(L"select() error: %d", WSAGetLastError());
		return FALSE;
	}

	*pReady = Res == 1 && FD_ISSET(pSocket->Socket, &fdset);

	return TRUE;
}

static PWSTR SocketAToW(PCSTR pStr)
{
	PWSTR  pRes = NULL;
	SIZE_T i;

	if (pRes = (PWSTR)OPENSSL_malloc(((SIZE_T)lstrlenA(pStr) + 1) * sizeof(WCHAR)))
	{
		for (i = 0; pRes[i] = (WCHAR)pStr[i]; ++i);
	}

	return pRes;
}

static PSTR SocketWToA(PCWSTR pStr)
{
	PSTR   pRes = NULL;
	SIZE_T i;

	if (pRes = (PSTR)OPENSSL_malloc((SIZE_T)lstrlenW(pStr) + 1))
	{
		for (i = 0; pRes[i] = (CHAR)pStr[i]; ++i);
	}

	return pRes;
}
