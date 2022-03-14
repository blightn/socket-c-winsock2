//#include <Windows.h> // Already included in "socket.h".
#include <wchar.h>

#include "..\Socket\socket.h"

#define HOST       L"google.com"
#define HTTP_PORT  L"80"
#define HTTPS_PORT L"443"
#define REQUEST    "GET / HTTP/1.1\r\nHost: %S:%S\r\n\r\n"

INT wmain(INT Argc, WCHAR* pArgv[], WCHAR* pEnv[])
{
	PSSOCKET        pSocket = NULL;
	CHAR            Buf[512];
	INT             Read;
	CONTEXT_OPTIONS Opts;
	PSSL_CTX        pCtx    = NULL;

	if (SocketInit())
	{
		if (pSocket = SocketCreate())
		{
			// 1. HTTP GET request.
			if (SocketConnect(pSocket, HOST, HTTP_PORT, IPV_4))
			{
				wsprintfA(Buf, REQUEST, L"www."HOST, HTTP_PORT);

				if (SocketWriteEx(pSocket, (PCBYTE)Buf, lstrlenA(Buf), NULL))
				{
					if ((Read = SocketRead(pSocket, (PBYTE)Buf, sizeof(Buf) - 1, FALSE)) > 0)
					{
						Buf[Read] = '\0';
						printf("%s\n\n", Buf);
					}
				}

				SocketDisconnect(pSocket);
			}

			// 2. HTTPS GET request.
			Opts.pCertPath        = NULL;
			Opts.pPrivKeyPath     = NULL;
			Opts.VerifyCert       = TRUE;
			Opts.pCAPath          = "..\\Misc\\cacert.pem";
			Opts.UseCompression   = FALSE;
			Opts.UseRenegotiation = FALSE;
			Opts.UseSessionCache  = TRUE;
			Opts.TLSMinVer        = TLSV_1_3;
			Opts.TLSMaxVer        = TLSV_1_3;

			if (pCtx = SocketCreateContext(&Opts))
			{
				if (SocketConnect(pSocket, HOST, HTTPS_PORT, IPV_4))
				{
					if (SocketSecure(pSocket, pCtx, NULL))
					{
						wsprintfA(Buf, REQUEST, L"www."HOST, HTTPS_PORT);

						if (SocketWriteEx(pSocket, (PCBYTE)Buf, lstrlenA(Buf), NULL))
						{
							if ((Read = SocketRead(pSocket, (PBYTE)Buf, sizeof(Buf) - 1, FALSE)) > 0)
							{
								Buf[Read] = '\0';
								printf("%s\n\n", Buf);
							}
						}
					}

					SocketDisconnect(pSocket);
				}

				SocketDestroyContext(pCtx);
				pCtx = NULL;
			}

			SocketDestroy(pSocket);
			pSocket = NULL;
		}

		SocketCleanup();
	}

	wprintf(L"\n");
	system("pause");

	return 0;
}
