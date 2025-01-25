#include "Interface/EUSignCP.h"

#include <iostream>
#include <time.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <fstream>
#include <vector>
#include <list>
#include <sstream>
#include <unordered_map>
#include <bitset>
#include <filesystem>

#include <iconv.h>

#define PRIVATE_KEY_FILE_PATH "./Modules/PKey/key_1134326253_1134326253.jks"
#define PRIVATE_KEY_PASSWORD "Ktqx02712"
#define RESPONSE_FILE_PATH "./Modules/Data/response.json"

#define CAS_JSON_PATH "./Modules/Settings/CAs.json";

#define CA_CERTIFICATES_PATH "./Modules/Certificates/CACertificates.p7b";

#define SZ_PATH "./Modules/Certificates";

#define PROXY_USE 0;

#define PROXY_ADDRESS "";

#define PROXY_PORT "3128";

#define PROXY_USER "";

#define PROXY_PASSWORD "";

#define DEFAULT_OCSP_SERVER "czo.gov.ua";

#define DEFAULT_TSP_SERVER "ca.iit.com.ua";

const std::unordered_map<char16_t, unsigned char> unicodeToWin1251 = {

	{0xD081, 0xA8},
	{0xD090, 0xC0},
	{0xD091, 0xC1},
	{0xD092, 0xC2},
	{0xD093, 0xC3},
	{0xD094, 0xC4},
	{0xD095, 0xC5},
	{0xD096, 0xC6},
	{0xD097, 0xC7},
	{0xD098, 0xC8},
	{0xD099, 0xC9},
	{0xD09A, 0xCA},
	{0xD09B, 0xCB},
	{0xD09C, 0xCC},
	{0xD09D, 0xCD},
	{0xD09E, 0xCE},
	{0xD09F, 0xCF},
	{0xD0A0, 0xD0},
	{0xD0A1, 0xD1},
	{0xD0A2, 0xD2},
	{0xD0A3, 0xD3},
	{0xD0A4, 0xD4},
	{0xD0A5, 0xD5},
	{0xD0A6, 0xD6},
	{0xD0A7, 0xD7},
	{0xD0A8, 0xD8},
	{0xD0A9, 0xD9},
	{0xD0AA, 0xDA},
	{0xD0AB, 0xDB},
	{0xD0AC, 0xDC},
	{0xD0AD, 0xDD},
	{0xD0AE, 0xDE},
	{0xD0AF, 0xDF},
	{0xD0B0, 0xE0},
	{0xD0B1, 0xE1},
	{0xD0B2, 0xE2},
	{0xD0B3, 0xE3},
	{0xD0B4, 0xE4},
	{0xD0B5, 0xE5},
	{0xD0B6, 0xE6},
	{0xD0B7, 0xE7},
	{0xD0B8, 0xE8},
	{0xD0B9, 0xE9},
	{0xD0BA, 0xEA},
	{0xD0BB, 0xEB},
	{0xD0BC, 0xEC},
	{0xD0BD, 0xED},
	{0xD0Be, 0xEE},
	{0xD0BF, 0xEF},
	{0xD180, 0xF0},
	{0xD181, 0xF1},
	{0xD182, 0xF2},
	{0xD183, 0xF3},
	{0xD184, 0xF4},
	{0xD185, 0xF5},
	{0xD186, 0xF6},
	{0xD187, 0xF7},
	{0xD188, 0xF8},
	{0xD189, 0xF9},
	{0xD18A, 0xFA},
	{0xD18B, 0xFB},
	{0xD18C, 0xFC},
	{0xD18D, 0xFD},
	{0xD18E, 0xFE},
	{0xD18F, 0xFF},
	{0xD191, 0xB8},

	{0xD290, 0xA5},
	{0xD084, 0xAA},
	{0xD086, 0xB2},
	{0xD087, 0xAF},
	{0xD194, 0xBA},
	{0xD196, 0xB3},
	{0xD197, 0xBF},
	{0xD291, 0xB4},
	{0x2090, 0x20},
	{0xC2AB, 0xAB},
	{0xC2BB, 0xBB},
};

struct CASettings
{
	std::vector<std::string> issuerCNsv;
	std::string address;
	std::string ocspAccessPointAddress;
	std::string ocspAccessPointPort;
	std::string cmpAddress;
	std::string tspAddress;
	std::string tspAddressPort;
	bool certsInKey;
	bool directAccess;
	bool qscdSNInCert;
	int cmpCompatibility;
	std::string codeEDRPOU;
};

struct BankIDResponse
{
	std::string state;
	std::string cert;
	std::string customerCrypto;
};

#define PRIVATE_KEY_FILE_PATH "./Modules/PKey/key_1134326253_1134326253.jks"
#define PRIVATE_KEY_PASSWORD "Ktqx02712"
#define RESPONSE_FILE_PATH "./Modules/Data/response.json"

char *GetErrorMessage(
	unsigned long dwError);

unsigned long Initialize();

#define MAX_INPUT_BUFFER_SIZE 255

PEU_INTERFACE g_pIface;
void *pvContext;
std::vector<CASettings> CAs;
BankIDResponse BIDresp;

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

	va_start(arg, szFormat);
	vprintf(szFormat, arg);
	va_end(arg);

	printf("\n");
}

char *GetErrorMessage(
	unsigned long dwError)
{
	if (g_pIface == NULL)
		return "Library not loaded";

	return g_pIface->GetErrorLangDesc(
		dwError, EU_EN_LANG);
}

void removeCharacterIfImmediatelyFollowedBy(
	std::string &str,
	char target,
	char nextChar)
{
	for (size_t i = 0; i < str.size() - 1; ++i)
	{
		if (str[i] == target && str[i + 1] == nextChar)
		{
			str.erase(i, 1);
		}
	}
}

std::string readFileToString(const std::string &filePath)
{
	std::ifstream file(filePath);
	if (!file)
	{
		std::cerr << "IIT EU Sign Usage: cannot open file for writing: " << filePath << std::endl;
		return "";
	}
	std::ostringstream ss;
	ss << file.rdbuf();
	return ss.str();
}

std::string getValue(
	const std::string &json,
	const std::string &key)
{
	int isFined = json.find("\"" + key + "\"");
	std::size_t start;
	if (isFined != std::string::npos)
	{
		start = json.find("\"" + key + "\"") + key.size() + 3;
	}
	else
	{
		return "";
	}
	std::size_t end = json.find_first_of(",}", start);
	std::string res = json.substr(start, end - start);
	return json.substr(start, end - start);
}

std::vector<uint8_t> cp1251ToBinary(const std::string &cp1251_str)
{
	std::vector<uint8_t> res;

	for (unsigned char ch : cp1251_str)
	{

		res.push_back(std::bitset<8>(ch).to_ulong());
	}
	return res;
}

std::string utf16BinaryToWin1251(const std::vector<uint8_t> &utf16_data)
{
	std::string win1251Str;

	for (size_t i = 0; i + 1 < utf16_data.size() + 1; i += 2)
	{
		if (utf16_data[i] == 226 && utf16_data[i + 1] == 128 && utf16_data[i + 2] == 156)
		{
			i += 3;
			win1251Str += '"';
		}
		if (utf16_data[i] == 226 && utf16_data[i + 1] == 128 && utf16_data[i + 2] == 157)
		{
			i += 3;
			win1251Str += '"';
		}
		if (i < utf16_data.size())
		{
			if (utf16_data[i] < 128)
			{
				win1251Str += utf16_data[i];
				i--;
				continue;
			}

			char16_t ch = static_cast<char16_t>((utf16_data[i] << 8) | (utf16_data[i + 1]));

			if (ch <= 0x7F)
			{
				win1251Str += static_cast<char>(ch);
			}
			else if (unicodeToWin1251.find(ch) != unicodeToWin1251.end())
			{
				win1251Str += unicodeToWin1251.at(ch);
			}
			else
			{
				win1251Str += '?';
			}
		}
		else
		{
			break;
		}
	}

	return win1251Str;
}

std::vector<std::string> parseArray(
	const std::string &json,
	const std::string &key)
{
	std::vector<std::string> result;
	std::size_t start = json.find("\"" + key + "\"");
	if (start == std::string::npos)
		return result;

	start = json.find("[", start) + 1;
	std::size_t end = json.find("]", start);
	std::string elements = json.substr(start, end - start);

	std::istringstream ss(elements);
	std::string item;
	while (std::getline(ss, item, ','))
	{

		item.erase(0, item.find_first_of("\"") + 1);
		item.erase(item.find_last_of("\""));
		removeCharacterIfImmediatelyFollowedBy(item, '\\', '"');
		std::vector<uint8_t> binaryStr = cp1251ToBinary(item);
		std::string win1251Str = utf16BinaryToWin1251(binaryStr);
		result.push_back(win1251Str);
	}
	return result;
}

CASettings parseCA(const std::string &json)
{
	CASettings ca;

	ca.issuerCNsv = parseArray(json, "issuerCNs");

	std::string address = getValue(json, "address");
	if (!address.empty())
	{
		address.erase(0, address.find_first_of("\"") + 1);
		address.erase(address.find_last_of("\""));
		ca.address = address;
	}

	std::string ocspAccessPointAddress = getValue(json, "ocspAccessPointAddress");
	if (!ocspAccessPointAddress.empty())
	{
		ocspAccessPointAddress.erase(0, ocspAccessPointAddress.find_first_of("\"") + 1);
		ocspAccessPointAddress.erase(ocspAccessPointAddress.find_last_of("\""));
		ca.ocspAccessPointAddress = ocspAccessPointAddress;
	}

	std::string ocspAccessPointPort = getValue(json, "ocspAccessPointPort");
	if (!ocspAccessPointPort.empty())
	{
		ocspAccessPointPort.erase(0, ocspAccessPointPort.find_first_of("\"") + 1);
		ocspAccessPointPort.erase(ocspAccessPointPort.find_last_of("\""));
		ca.ocspAccessPointPort = ocspAccessPointPort;
	}

	std::string cmpAddress = getValue(json, "cmpAddress");
	if (!cmpAddress.empty())
	{
		cmpAddress.erase(0, cmpAddress.find_first_of("\"") + 1);
		cmpAddress.erase(cmpAddress.find_last_of("\""));
		ca.cmpAddress = cmpAddress;
	}

	std::string tspAddress = getValue(json, "tspAddress");
	if (!tspAddress.empty())
	{
		tspAddress.erase(0, tspAddress.find_first_of("\"") + 1);
		tspAddress.erase(tspAddress.find_last_of("\""));
		ca.tspAddress = tspAddress;
	}

	std::string tspAddressPort = getValue(json, "tspAddressPort");
	if (!tspAddressPort.empty())
	{
		tspAddressPort.erase(0, tspAddressPort.find_first_of("\"") + 1);
		tspAddressPort.erase(tspAddressPort.find_last_of("\""));
		ca.tspAddressPort = tspAddressPort;
	}

	std::string certsInKey = getValue(json, "certsInKey");
	if (!certsInKey.empty())
	{
		certsInKey.erase(0, certsInKey.find_first_of('t'));
		certsInKey.erase(certsInKey.find_last_of('e') + 1);
		if (certsInKey == "true")
		{
			ca.certsInKey = 1;
		}
		else
		{
			ca.certsInKey = 0;
		}
	}
	else
	{
		ca.certsInKey = 0;
	}

	std::string directAccess = getValue(json, "directAccess");
	if (!directAccess.empty())
	{
		directAccess.erase(0, directAccess.find_first_of('t'));
		directAccess.erase(directAccess.find_last_of('e') + 1);
		if (directAccess == "true")
		{
			ca.directAccess = 1;
		}
		else
		{
			ca.directAccess = 0;
		}
	}
	else
	{
		ca.directAccess = 0;
	}

	std::string qscdSNInCert = getValue(json, "qscdSNInCert");
	if (!qscdSNInCert.empty())
	{
		qscdSNInCert.erase(0, qscdSNInCert.find_first_of('t'));
		qscdSNInCert.erase(qscdSNInCert.find_last_of('e') + 1);
		if (qscdSNInCert == "true")
		{
			ca.qscdSNInCert = 1;
		}
		else
		{
			ca.qscdSNInCert = 0;
		}
	}
	else
	{
		ca.qscdSNInCert = 0;
	}

	std::string cmpCompatibilityStr = getValue(json, "cmpCompatibility");

	if (!cmpCompatibilityStr.empty())
	{
		std::string result;
		for (char ch : cmpCompatibilityStr)
		{
			int v = ch;
			if ((v >= 48 && v <= 57))
			{
				result += ch;
			}
		}
		int cmpCompatibility = std::stoi(result);
		ca.cmpCompatibility = cmpCompatibility;
	}
	else
	{
		ca.cmpCompatibility = -1;
	}

	std::string codeEDRPOU = getValue(json, "codeEDRPOU");
	if (!codeEDRPOU.empty())
	{
		codeEDRPOU.erase(0, codeEDRPOU.find_first_of("\"") + 1);
		codeEDRPOU.erase(codeEDRPOU.find_last_of("\""));
		ca.codeEDRPOU = codeEDRPOU;
	}

	return ca;
}

std::vector<CASettings> parseCAsArray(const std::string &jsonArray)
{
	std::vector<CASettings> ca;

	std::size_t start = jsonArray.find("{");
	while (start != std::string::npos)
	{
		std::size_t end = jsonArray.find("}", start);
		if (end == std::string::npos)
			break;

		std::string jsonObject = jsonArray.substr(start, end - start + 1);
		ca.push_back(parseCA(jsonObject));

		start = jsonArray.find("{", end);
	}

	return ca;
}

std::vector<uint8_t> ReadAllBytes(char *filePath)
{

	std::ifstream file(filePath, std::ios::binary | std::ios::ate);

	if (!file)
	{
		std::cerr << "IIT EU Sign Usage: Cannot open file for writing: " << filePath << std::endl;
		return {};
	}

	std::streamsize fileSize = file.tellg();
	file.seekg(0, std::ios::beg);

	std::vector<uint8_t> buffer(fileSize);

	if (!file.read(reinterpret_cast<char *>(buffer.data()), fileSize))
	{
		std::cerr << "IIT EU Sign Usage: cannot read from the file: " << filePath << std::endl;
		return {};
	}

	file.close();
	return buffer;
}

void WriteAllText(
	char *filePath,
	std::string data)
{

	std::ofstream outFile(filePath, std::ios::binary);
	if (!outFile)
	{
		std::cerr << "IIT EU Sign Usage: File " << filePath << " cannot be opened\n";
	}

	outFile.write(data.data(), data.size());
	if (!outFile)
	{
		std::cerr << "IIT EU Sign Usage: cannot write to file " << filePath << "\n";
	}

	outFile.close();
}

unsigned long Initialize()
{
	unsigned long dwError;
	unsigned int nSign = EU_SIGN_TYPE_CADES_T;
	int nSaveSettings = EU_SETTINGS_ID_NONE;

	g_pIface->SetUIMode(0);

	dwError = g_pIface->Initialize();
	if (dwError != EU_ERROR_NONE)
	{
		PrintMessage(GetErrorMessage(dwError));
		return dwError;
	}

	g_pIface->SetRuntimeParameter(EU_SAVE_SETTINGS_PARAMETER, &nSaveSettings, EU_SAVE_SETTINGS_PARAMETER_LENGTH);

	g_pIface->SetRuntimeParameter(EU_SIGN_TYPE_PARAMETER, &nSign, EU_SIGN_TYPE_LENGTH);

	g_pIface->SetUIMode(0);

	g_pIface->SetModeSettings(0);

	char *pszPath = SZ_PATH;
	int bCheckCRLs = 0;
	int bAutoRefresh = 1;
	int bOwnCRLsOnly = 0;
	int bFullAndDeltaCRLs = 0;
	int bAutoDownloadCRLs = 0;
	int bSaveLoadedCerts = 0;
	unsigned long dwExpireTime = 3600;

	dwError = g_pIface->SetFileStoreSettings(
		pszPath, bCheckCRLs, bAutoRefresh, bOwnCRLsOnly,
		bFullAndDeltaCRLs, bAutoDownloadCRLs, bSaveLoadedCerts,
		dwExpireTime);
	if (dwError != EU_ERROR_NONE)
		return dwError;

	int bUseProxy = PROXY_USE;
	int bProxyAnonymous = 0;
	char *pszProxyAddress = PROXY_ADDRESS;
	char *pszProxyPort = PROXY_PORT;
	char *pszProxyUser = PROXY_USER;
	char *pszProxyPassword = "";
	int bProxySavePassword = 1;

	dwError = g_pIface->SetProxySettings(
		bUseProxy, bProxyAnonymous,
		pszProxyAddress, pszProxyPort,
		pszProxyUser, pszProxyPassword,
		bProxySavePassword);
	if (dwError != EU_ERROR_NONE)
		return dwError;

	int bUseOCSP = 1;
	int bBeforeStore = 1;
	char *pszOCSPAddress = DEFAULT_OCSP_SERVER;
	char *pszOCSPPort = "80";

	dwError = g_pIface->SetOCSPSettings(
		bUseOCSP, bBeforeStore, pszOCSPAddress, pszOCSPPort);
	if (dwError != EU_ERROR_NONE)
		return dwError;

	g_pIface->SetOCSPAccessInfoModeSettings(1);
	if (dwError != EU_ERROR_NONE)
		return dwError;

	std::string filePath = CAS_JSON_PATH;
	std::string jsonStr = readFileToString(filePath);
	CAs = parseCAsArray(jsonStr);

	for (int i = 0; i < CAs.size(); i++)
	{
		for (int j = 0; j < CAs[i].issuerCNsv.size(); j++)
		{
			dwError = g_pIface->SetOCSPAccessInfoSettings(
				(char *)CAs[i].issuerCNsv[j].c_str(),
				(char *)CAs[i].ocspAccessPointAddress.c_str(),
				(char *)CAs[i].ocspAccessPointPort.c_str());
			if (dwError != EU_ERROR_NONE)
				return dwError;
		}
	}

	int bUseTSP = 1;
	char *pszTSPAddress = DEFAULT_TSP_SERVER;
	char *pszTSPPort = "80";

	dwError = g_pIface->SetTSPSettings(
		bUseTSP, pszTSPAddress, pszTSPPort);
	if (dwError != EU_ERROR_NONE)
		return dwError;

	int bUseLDAP = 0;
	char *pszLDAPAddress = "";
	char *pszLDAPPort = "";
	int bLDAPAnonymous = 1;
	char *pszLDAPUser = "";
	char *pszLDAPPassword = "";

	dwError = g_pIface->SetLDAPSettings(
		bUseLDAP, pszLDAPAddress, pszLDAPPort,
		bLDAPAnonymous, pszLDAPUser, pszLDAPPassword);
	if (dwError != EU_ERROR_NONE)
		return dwError;

	int bUseCMP = 1;
	char *pszCMPAddress = "";
	char *pszCMPPort = "80";
	char *pszCMPCommonName = "";

	dwError = g_pIface->SetCMPSettings(
		bUseCMP, pszCMPAddress, pszCMPPort, pszCMPCommonName);
	if (dwError != EU_ERROR_NONE)
		return dwError;

	char *path = CA_CERTIFICATES_PATH;
	std::vector<uint8_t> res = ReadAllBytes(path);
	g_pIface->SaveCertificates(res.data(), res.size());

	dwError = g_pIface->CtxCreate(&pvContext);
	if (dwError != EU_ERROR_NONE)
	{
		PrintMessage(GetErrorMessage(dwError));
		return dwError;
	}

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
		printf("%d", dwError);
		return dwError;
	}

	// PrintMessage(pszCustomerCrypto);

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
									  NULL, 0,

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

	char *developedSign;

	dwError = g_pIface->BASE64Encode(pbDecryptedCustomerData, dwDecryptedCustomerLength, &developedSign);

	dwError = g_pIface->VerifyDataInternal(
		developedSign, 0, 0,

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

char g_szSenderCert[] = "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";

char g_szCustomerCrypto[] = "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";

int main()
{
	unsigned long dwError;
	unsigned char *pbCustomerData = NULL;
	unsigned long dwCustomerData;

	char *pszCustomerData;

	char szTime[MAX_INPUT_BUFFER_SIZE + 1];
	char *pszTmp;

	EU_ENVELOP_INFO senderInfo;
	EU_SIGN_INFO signInfo;

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
		&senderInfo,
		&signInfo);
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

		g_pIface->FreeSignInfo(&signInfo);
		g_pIface->FreeSenderInfo(&senderInfo);
		g_pIface->FreeMemory(pbCustomerData);

		g_pIface->Finalize();
		EUUnload();

		return 1;
	}

	memcpy(pszCustomerData, pbCustomerData, dwCustomerData);
	pszCustomerData[dwCustomerData] = 0;

	g_pIface->FreeMemory(pbCustomerData);

	std::string customerData = pszCustomerData;
	WriteAllText("./Modules/Data/data.json", customerData);

	pszTmp = CP1251ToUTF8(pszCustomerData);
	ReleaseUTF8String(pszTmp);

	pszTmp = CP1251ToUTF8((char*)"IIT EU Sign Usage: The response was decoded successfully: ");
	PrintMessage(pszTmp);
	ReleaseUTF8String(pszTmp);
	std::cout << "\t";
	std::cout << customerData << "\n";

	SystemTimeToString(&signInfo.Time, szTime);
	if (signInfo.bTimeAvail)
	{
		SystemTimeToString(&signInfo.Time, szTime);
		std::cout << "IIT EU Sign Usage: ";
		if (signInfo.bTimeStamp)
			pszTmp = CP1251ToUTF8("Time label: ");
		else
			pszTmp = CP1251ToUTF8("Time of the signature: ");
		PrintMessage(pszTmp);
		ReleaseUTF8String(pszTmp);

		std::cout << "\t";
		PrintMessage(szTime);
	}

	free(pszCustomerData);

	g_pIface->FreeSignInfo(&signInfo);
	g_pIface->FreeSenderInfo(&senderInfo);

	getchar();

	g_pIface->Finalize();
	EUUnload();

	return 0;
}
