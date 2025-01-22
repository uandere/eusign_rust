//===============================================================================

#include "Interface/EUSignCP.h"

//-------------------------------------------------------------------------------

#include <time.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include <iconv.h>

//===============================================================================

char *PRIVATE_KEY_FILE_PATH = "./key_1134326253_1134326253.jks";
char *PRIVATE_KEY_PASSWORD = "Ktqx02712";
char *RESPONSE_FILE_PATH = "./response.json";

//===============================================================================

char *GetErrorMessage(
	unsigned long dwError);

unsigned long Initialize();

unsigned long DevelopCustomerCrypto(
	char *pszPrivKeyFilePath,
	char *pszPrivKeyPassword,
	char *pszSenderCert,
	char *pszCustomerCrypto,
	unsigned char **ppbCustomerData,
	unsigned long *pdwCustomerData,
	PEU_ENVELOP_INFO pSenderInfo,
	PEU_SIGN_INFO pSignInfo);

//===============================================================================

#define MAX_INPUT_BUFFER_SIZE 255

//===============================================================================

PEU_INTERFACE g_pIface;

//===============================================================================

#define MAX_PATH 260

char *CP1251ToUTF8(
	char *szStr)
{
	int nResult;
	char *pszResStr;
	char *pszResConvert;
	size_t nStrLength;
	size_t nUtfLength;

	iconv_t Dictionary;

	Dictionary = iconv_open("UTF-8", "CP1251");

	nStrLength = strlen(szStr) + 1;
	nUtfLength = nStrLength * 2;

	pszResStr = (char *)malloc(nUtfLength);
	pszResConvert = pszResStr;

	iconv(Dictionary, &szStr, &nStrLength, &pszResConvert, &nUtfLength);
	iconv_close(Dictionary);

	return pszResStr;
}

void ReleaseUTF8String(
	char *pszStr)
{
	free(pszStr);
}

//===============================================================================

void SystemTimeToString(
	PSYSTEMTIME pTime,
	char *pszTime)
{
	sprintf(pszTime,
			"%.2d.%.2d.%.2d %.2d:%.2d:%.2d",
			pTime->wMonth, pTime->wDay, pTime->wYear,
			pTime->wHour, pTime->wMinute, pTime->wSecond);
}

void PrintMessage(
	const char *szFormat,
	...)
{
	va_list arg;
	time_t Time;
	struct tm *pTimeInfo;
	char szTime[MAX_INPUT_BUFFER_SIZE + 1];

	time(&Time);
	pTimeInfo = localtime(&Time);
	sprintf(szTime, asctime(pTimeInfo));
	szTime[strlen(szTime) - 1] = '\0';

	printf("IIT Kaze Test[%s] ", szTime);

	va_start(arg, szFormat);
	vprintf(szFormat, arg);
	va_end(arg);

	printf("\n");
}

//===============================================================================

char *GetErrorMessage(
	unsigned long dwError)
{
	if (g_pIface == NULL)
		return "Library not loaded";

	return g_pIface->GetErrorLangDesc(
		dwError, EU_EN_LANG);
}

unsigned long Initialize()
{
	unsigned long dwError;

	g_pIface->SetUIMode(0);

	dwError = g_pIface->Initialize();
	if (dwError != EU_ERROR_NONE)
	{
		PrintMessage(GetErrorMessage(dwError));
		return dwError;
	}

	g_pIface->SetUIMode(0);

	return EU_ERROR_NONE;
}

unsigned long DevelopCustomerCrypto(
	char *pszPrivKeyFilePath,
	char *pszPrivKeyPassword,
	char *pszSenderCert,
	char *pszCustomerCrypto,
	unsigned char **ppbCustomerData,
	unsigned long *pdwCustomerData,
	PEU_ENVELOP_INFO pSenderInfo,
	PEU_SIGN_INFO pSignInfo)
{
	unsigned long dwError;

	dwError = Initialize();
	if (dwError != EU_ERROR_NONE)
	{
		return dwError;
	}

	unsigned char *pbSenderCert = NULL;
	unsigned char *pbCustomerCrypto = NULL;
	unsigned char *pbDecryptedCustomerData = NULL;

	unsigned long dwSenderCertLength;
	unsigned long dwCustomerCryptoLength;
	unsigned long dwDecryptedCustomerLength;

	dwError = g_pIface->ReadPrivateKeyFile(pszPrivKeyFilePath,
										   pszPrivKeyPassword, NULL);
	if (dwError != EU_ERROR_NONE)
		return dwError;

	dwError = g_pIface->BASE64Decode(pszSenderCert,
									 &pbSenderCert, &dwSenderCertLength);
	if (dwError != EU_ERROR_NONE)
	{
		g_pIface->ResetPrivateKey();
		return dwError;
	}

	dwError = g_pIface->BASE64Decode(pszCustomerCrypto,
									 &pbCustomerCrypto, &dwCustomerCryptoLength);
	if (dwError != EU_ERROR_NONE)
	{
		g_pIface->FreeMemory(pbSenderCert);
		g_pIface->ResetPrivateKey();
		return dwError;
	}

	dwError = g_pIface->DevelopDataEx(NULL,
									  pbCustomerCrypto, dwCustomerCryptoLength,
									  pbSenderCert, dwSenderCertLength,
									  &pbDecryptedCustomerData, &dwDecryptedCustomerLength,
									  pSenderInfo);
	if (dwError != EU_ERROR_NONE)
	{
		g_pIface->FreeMemory(pbCustomerCrypto);
		g_pIface->FreeMemory(pbSenderCert);
		g_pIface->ResetPrivateKey();
		return dwError;
	}

	g_pIface->FreeMemory(pbCustomerCrypto);
	g_pIface->FreeMemory(pbSenderCert);

	dwError = g_pIface->VerifyDataInternal(NULL,
										   pbDecryptedCustomerData, dwDecryptedCustomerLength,
										   ppbCustomerData, pdwCustomerData,
										   pSignInfo);
	if (dwError != EU_ERROR_NONE)
	{
		g_pIface->FreeSenderInfo(pSenderInfo);
		g_pIface->FreeMemory(pbDecryptedCustomerData);
		g_pIface->ResetPrivateKey();
		return dwError;
	}

	g_pIface->FreeMemory(pbDecryptedCustomerData);
	g_pIface->ResetPrivateKey();

	return EU_ERROR_NONE;
}

char g_szSenderCert[] =
	"MIIGUDCCBfigAwIBAgIUW2PYg3XZIBgEAAAALj0AALKVAAAwDQYLKoYkAgEBAQEDAQEwgcMxFjAU"
	"BgNVBAoMDdCQ0KIgItCG0IbQoiIxIDAeBgNVBAsMF9Ci0LXRgdGC0L7QstC40Lkg0KbQodCaMS4w"
	"LAYDVQQDDCXQotC10YHRgtC+0LLQuNC5INCm0KHQmiDQkNCiICLQhtCG0KIiMRQwEgYDVQQFDAtV"
	"QS0yMjcyMzQ3MjELMAkGA1UEBhMCVUExFTATBgNVBAcMDNCl0LDRgNC60ZbQsjEdMBsGA1UECAwU"
	"0KXQsNGA0LrRltCy0YHRjNC60LAwHhcNMTkwNzI0MTM0MzI1WhcNMjQwNzI0MTM0MzI1WjCCAScx"
	"LjAsBgNVBAoMJdCi0LXRgdGC0L7QstCwINC+0YDQs9Cw0L3RltC30LDRhtGW0Y8xLDAqBgNVBAsM"
	"I9Ci0LXRgdGC0L7QstC40Lkg0L/RltC00YDQvtC30LTRltC7MSQwIgYDVQQMDBvQotC10YHRgtC+"
	"0LLQsCDQv9C+0YHQsNC00LAxNzA1BgNVBAMMLtCi0LXRgdGC0L7QstC40Lkg0LrQvtGA0LjRgdGC"
	"0YPQstCw0YcgKEJhbmtJRCkxGTAXBgNVBAQMENCi0LXRgdGC0L7QstC40LkxHTAbBgNVBCoMFNCa"
	"0L7RgNC40YHRgtGD0LLQsNGHMQ4wDAYDVQQFDAUxNTY2MjELMAkGA1UEBhMCVUExETAPBgNVBAcM"
	"CNCa0LjRl9CyMIIBUTCCARIGCyqGJAIBAQEBAwEBMIIBATCBvDAPAgIBrzAJAgEBAgEDAgEFAgEB"
	"BDbzykDGaaTaFzFJyhLDLa4Ya1Osa8Y2WZferq6K0tiI+b/VNAFpTvnEJz2M/m3Cj3BqD0kQzgMC"
	"Nj///////////////////////////////////7oxdUWACajApyTwL4Gqih/Lr4DZDHqVEQUEzwQ2"
	"fIV8lMVDO/2ZHhfCJoQGWFCpoknte8JJrlpOh4aJ+HLvetUkCC7DA46a7ee6a6Ezgdl5umIaBECp"
	"1utF8TxwgoDElnsjH16t9ljrpMA3KR042WvwJcpOF/jpcg3GFbQ6KJdfC8Heo2Q4tWTqLBef0BI+"
	"bbj6xXkEAzkABDbizcCFl84tTr7nOvwbTvBFO7ZL5D2cXAJD32vQNf1XOVXV+BJLh/GV08vB3I3O"
	"nf5X/D0YTHejggJkMIICYDApBgNVHQ4EIgQg5WX1acz/4BMon8Th+WlTfxiGHdPuqufkXFd0H+BI"
	"MPswKwYDVR0jBCQwIoAgW2PYg3XZIBjNtLEOubalxppZ/UMnxnHjwfU66rAtat4wDgYDVR0PAQH/"
	"BAQDAgMIMBkGA1UdIAEB/wQPMA0wCwYJKoYkAgEBAQICMAwGA1UdEwEB/wQCMAAwNwYIKwYBBQUH"
	"AQMBAf8EKDAmMAsGCSqGJAIBAQECATAXBgYEAI5GAQIwDRMDVUFIAgMPQkACAQAwRAYDVR0fBD0w"
	"OzA5oDegNYYzaHR0cDovL2NhLmlpdC5jb20udWEvZG93bmxvYWQvY3Jscy9DQTEzLUZ1bGwtUzMu"
	"Y3JsMEUGA1UdLgQ+MDwwOqA4oDaGNGh0dHA6Ly9jYS5paXQuY29tLnVhL2Rvd25sb2FkL2NybHMv"
	"Q0ExMy1EZWx0YS1TMy5jcmwwgYEGCCsGAQUFBwEBBHUwczAvBggrBgEFBQcwAYYjaHR0cDovL2Nh"
	"LmlpdC5jb20udWEvc2VydmljZXMvb2NzcC8wQAYIKwYBBQUHMAKGNGh0dHA6Ly9jYS5paXQuY29t"
	"LnVhL2Rvd25sb2FkL2NlcnRpZmljYXRlcy9jYWlpdC5wN2IwPgYIKwYBBQUHAQsEMjAwMC4GCCsG"
	"AQUFBzADhiJodHRwOi8vY2EuaWl0LmNvbS51YS9zZXJ2aWNlcy90c3AvMEMGA1UdCQQ8MDowGgYM"
	"KoYkAgEBAQsBBAIBMQoTCDExMjIzMzQ0MBwGDCqGJAIBAQELAQQBATEMEwoxMTEyMjIzMzM5MA0G"
	"CyqGJAIBAQEBAwEBA0MABECs5TyRWcjIGf5sKZLdlyKy9evfteTwWcriGLVZN3DYWl0B3WTm+PKO"
	"K1bzItEt/bcSWoEP635w4xlfG4hIh8ct";

char g_szCustomerCrypto[] =
	"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";

int main()
{
	unsigned long dwError;
	unsigned char *pbCustomerData = NULL;
	unsigned long dwCustomerData;

	char *pszCustomerData;

	char szTime[MAX_INPUT_BUFFER_SIZE + 1];
	char *pszTmp;

	EU_ENVELOP_INFO SenderInfo;
	EU_SIGN_INFO SignInfo;

	if (!EULoad())
	{
		PrintMessage(GetErrorMessage(EU_ERROR_LIBRARY_LOAD));

		return 1;
	}

	g_pIface = EUGetInterface();

	dwError = DevelopCustomerCrypto(
		PRIVATE_KEY_FILE_PATH,
		PRIVATE_KEY_PASSWORD,
		g_szSenderCert,
		g_szCustomerCrypto,
		&pbCustomerData,
		&dwCustomerData,
		&SenderInfo,
		&SignInfo);
	if (dwError != EU_ERROR_NONE)
	{
		PrintMessage(GetErrorMessage(dwError));

		g_pIface->Finalize();
		EUUnload();

		return 1;
	}

	pszCustomerData = (char *)malloc(dwCustomerData + 1);
	if (pszCustomerData == NULL)
	{
		PrintMessage(GetErrorMessage(EU_ERROR_MEMORY_ALLOCATION));

		g_pIface->FreeSignInfo(&SignInfo);
		g_pIface->FreeSenderInfo(&SenderInfo);
		g_pIface->FreeMemory(pbCustomerData);

		g_pIface->Finalize();
		EUUnload();

		return 1;
	}

	memcpy(pszCustomerData, pbCustomerData, dwCustomerData);
	pszCustomerData[dwCustomerData] = 0;

	g_pIface->FreeMemory(pbCustomerData);

	pszTmp = CP1251ToUTF8("³������ �� BankID ������������ ������. ������������ ����");
	PrintMessage(pszTmp);
	ReleaseUTF8String(pszTmp);
	PrintMessage(pszCustomerData);
	pszTmp = CP1251ToUTF8("���������� ��� ����������");
	PrintMessage(pszTmp);
	ReleaseUTF8String(pszTmp);
	pszTmp = CP1251ToUTF8("³��������");
	PrintMessage(pszTmp);
	ReleaseUTF8String(pszTmp);
	pszTmp = CP1251ToUTF8(SenderInfo.pszSubjCN);
	PrintMessage(pszTmp);
	ReleaseUTF8String(pszTmp);
	pszTmp = CP1251ToUTF8("���, �� ����� ����������");
	PrintMessage(pszTmp);
	ReleaseUTF8String(pszTmp);
	pszTmp = CP1251ToUTF8(SenderInfo.pszIssuerCN);
	PrintMessage(pszTmp);
	ReleaseUTF8String(pszTmp);
	pszTmp = CP1251ToUTF8("������� ����� �����������");
	PrintMessage(pszTmp);
	ReleaseUTF8String(pszTmp);
	pszTmp = CP1251ToUTF8(SenderInfo.pszSerial);
	PrintMessage(pszTmp);
	ReleaseUTF8String(pszTmp);
	pszTmp = CP1251ToUTF8("���������� ��� �����");
	PrintMessage(pszTmp);
	ReleaseUTF8String(pszTmp);
	pszTmp = CP1251ToUTF8("ϳ��������");
	PrintMessage(pszTmp);
	ReleaseUTF8String(pszTmp);
	pszTmp = CP1251ToUTF8(SignInfo.pszSubjCN);
	PrintMessage(pszTmp);
	ReleaseUTF8String(pszTmp);
	pszTmp = CP1251ToUTF8("���, �� ����� ����������");
	PrintMessage(pszTmp);
	ReleaseUTF8String(pszTmp);
	pszTmp = CP1251ToUTF8(SignInfo.pszIssuerCN);
	PrintMessage(pszTmp);
	ReleaseUTF8String(pszTmp);
	pszTmp = CP1251ToUTF8("������� ����� �����������");
	PrintMessage(pszTmp);
	ReleaseUTF8String(pszTmp);
	pszTmp = CP1251ToUTF8(SignInfo.pszSerial);
	PrintMessage(pszTmp);
	ReleaseUTF8String(pszTmp);

	SystemTimeToString(&SignInfo.Time, szTime);
	if (SignInfo.bTimeAvail)
	{
		if (SignInfo.bTimeStamp)
			pszTmp = CP1251ToUTF8("̳��� ����");
		else
			pszTmp = CP1251ToUTF8("��� ������");

		PrintMessage(pszTmp);
		ReleaseUTF8String(pszTmp);

		PrintMessage(szTime);
	}

	free(pszCustomerData);

	g_pIface->FreeSignInfo(&SignInfo);
	g_pIface->FreeSenderInfo(&SenderInfo);

	getchar();

	g_pIface->Finalize();
	EUUnload();

	return 0;
}

//===============================================================================
