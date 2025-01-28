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


#define PRIVATE_KEY_FILE_PATH "./Modules/PKey/key_1134326253_1134326253.jks"
#define PRIVATE_KEY_PASSWORD "Ktqx02712"
#define RESPONSE_FILE_PATH "./Modules/Data/response.json"

#define CAS_JSON_PATH "./Modules/Settings/CAs.json"
#define CA_CERTIFICATES_PATH "./Modules/Certificates/CACertificates.p7b"
#define SZ_PATH "./Modules/Certificates"

#define PROXY_USE 0
#define PROXY_ADDRESS ""
#define PROXY_PORT "3128"
#define PROXY_USER ""
#define PROXY_PASSWORD ""

#define DEFAULT_OCSP_SERVER "czo.gov.ua"
#define DEFAULT_TSP_SERVER "ca.iit.com.ua"

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

char *GetErrorMessage(unsigned long dwError);
unsigned long Initialize();

PEU_INTERFACE g_pIface;
void *pvContext;
std::vector<CASettings> CAs;
BankIDResponse BIDresp;

#define MAX_INPUT_BUFFER_SIZE 255

void ReleaseUTF8String(char *pszStr)
{
    free(pszStr);
}

void SystemTimeToString(PSYSTEMTIME pTime, char *pszTime)
{
    sprintf(pszTime,
            "%.2d.%.2d.%.2d %.2d:%.2d:%.2d",
            pTime->wMonth, pTime->wDay, pTime->wYear,
            pTime->wHour, pTime->wMinute, pTime->wSecond);
}

void PrintMessage(const char *szFormat, ...)
{
    va_list arg;
    time_t Time;
    struct tm *pTimeInfo;
    char szTime[MAX_INPUT_BUFFER_SIZE + 1];

    time(&Time);
    pTimeInfo = localtime(&Time);
    sprintf(szTime, "%s", asctime(pTimeInfo));
    szTime[strlen(szTime) - 1] = '\0';

    va_start(arg, szFormat);
    vprintf(szFormat, arg);
    va_end(arg);

    printf("\n");
}

char *GetErrorMessage(unsigned long dwError)
{
    if (g_pIface == NULL)
        return (char *)"Library not loaded";

    return g_pIface->GetErrorLangDesc(dwError, EU_EN_LANG);
}

void removeCharacterIfImmediatelyFollowedBy(std::string &str, char target, char nextChar)
{
    for (size_t i = 0; i + 1 < str.size(); /* no increment here */)
    {
        if (str[i] == target && str[i + 1] == nextChar)
        {
            str.erase(i, 1);
        }
        else
        {
            ++i;
        }
    }
}

std::string readFileToString(const std::string &filePath)
{
    std::ifstream file(filePath);
    if (!file)
    {
        std::cerr << "IIT EU Sign Usage: cannot open file for reading: " << filePath << std::endl;
        return "";
    }
    std::ostringstream ss;
    ss << file.rdbuf();
    return ss.str();
}

std::string getValue(const std::string &json, const std::string &key)
{
    int isFined = json.find("\"" + key + "\"");
    if (isFined == std::string::npos)
        return "";

    std::size_t start = json.find("\"" + key + "\"") + key.size() + 3;
    std::size_t end = json.find_first_of(",}", start);
    return json.substr(start, end - start);
}

std::vector<std::string> parseArray(const std::string &json, const std::string &key)
{
    std::vector<std::string> result;
    std::size_t start = json.find("\"" + key + "\"");
    if (start == std::string::npos)
        return result;

    start = json.find("[", start);
    if (start == std::string::npos)
        return result;

    start += 1; // move past '['
    std::size_t end = json.find("]", start);
    if (end == std::string::npos)
        return result;

    std::string elements = json.substr(start, end - start);

    std::istringstream ss(elements);
    std::string item;
    while (std::getline(ss, item, ','))
    {
        // Strip surrounding quotes if present
        auto firstQuotePos = item.find_first_of("\"");
        auto lastQuotePos = item.find_last_of("\"");
        if (firstQuotePos != std::string::npos && lastQuotePos != std::string::npos && lastQuotePos > firstQuotePos)
        {
            item = item.substr(firstQuotePos + 1, lastQuotePos - firstQuotePos - 1);
        }
        removeCharacterIfImmediatelyFollowedBy(item, '\\', '"');
        result.push_back(item);
    }
    return result;
}

CASettings parseCA(const std::string &json)
{
    CASettings ca;

    ca.issuerCNsv = parseArray(json, "issuerCNs");

    auto address = getValue(json, "address");
    if (!address.empty())
    {
        // remove surrounding quotes
        auto firstQuotePos = address.find_first_of("\"");
        auto lastQuotePos = address.find_last_of("\"");
        if (firstQuotePos != std::string::npos && lastQuotePos != std::string::npos && lastQuotePos > firstQuotePos)
            address = address.substr(firstQuotePos + 1, lastQuotePos - firstQuotePos - 1);
        ca.address = address;
    }

    auto ocspAccessPointAddress = getValue(json, "ocspAccessPointAddress");
    if (!ocspAccessPointAddress.empty())
    {
        auto firstQuotePos = ocspAccessPointAddress.find_first_of("\"");
        auto lastQuotePos = ocspAccessPointAddress.find_last_of("\"");
        if (firstQuotePos != std::string::npos && lastQuotePos != std::string::npos && lastQuotePos > firstQuotePos)
            ocspAccessPointAddress = ocspAccessPointAddress.substr(firstQuotePos + 1, lastQuotePos - firstQuotePos - 1);
        ca.ocspAccessPointAddress = ocspAccessPointAddress;
    }

    auto ocspAccessPointPort = getValue(json, "ocspAccessPointPort");
    if (!ocspAccessPointPort.empty())
    {
        auto firstQuotePos = ocspAccessPointPort.find_first_of("\"");
        auto lastQuotePos = ocspAccessPointPort.find_last_of("\"");
        if (firstQuotePos != std::string::npos && lastQuotePos != std::string::npos && lastQuotePos > firstQuotePos)
            ocspAccessPointPort = ocspAccessPointPort.substr(firstQuotePos + 1, lastQuotePos - firstQuotePos - 1);
        ca.ocspAccessPointPort = ocspAccessPointPort;
    }

    auto cmpAddress = getValue(json, "cmpAddress");
    if (!cmpAddress.empty())
    {
        auto firstQuotePos = cmpAddress.find_first_of("\"");
        auto lastQuotePos = cmpAddress.find_last_of("\"");
        if (firstQuotePos != std::string::npos && lastQuotePos != std::string::npos && lastQuotePos > firstQuotePos)
            cmpAddress = cmpAddress.substr(firstQuotePos + 1, lastQuotePos - firstQuotePos - 1);
        ca.cmpAddress = cmpAddress;
    }

    auto tspAddress = getValue(json, "tspAddress");
    if (!tspAddress.empty())
    {
        auto firstQuotePos = tspAddress.find_first_of("\"");
        auto lastQuotePos = tspAddress.find_last_of("\"");
        if (firstQuotePos != std::string::npos && lastQuotePos != std::string::npos && lastQuotePos > firstQuotePos)
            tspAddress = tspAddress.substr(firstQuotePos + 1, lastQuotePos - firstQuotePos - 1);
        ca.tspAddress = tspAddress;
    }

    auto tspAddressPort = getValue(json, "tspAddressPort");
    if (!tspAddressPort.empty())
    {
        auto firstQuotePos = tspAddressPort.find_first_of("\"");
        auto lastQuotePos = tspAddressPort.find_last_of("\"");
        if (firstQuotePos != std::string::npos && lastQuotePos != std::string::npos && lastQuotePos > firstQuotePos)
            tspAddressPort = tspAddressPort.substr(firstQuotePos + 1, lastQuotePos - firstQuotePos - 1);
        ca.tspAddressPort = tspAddressPort;
    }

    auto certsInKey = getValue(json, "certsInKey");
    if (certsInKey.find("true") != std::string::npos)
        ca.certsInKey = true;
    else
        ca.certsInKey = false;

    auto directAccess = getValue(json, "directAccess");
    if (directAccess.find("true") != std::string::npos)
        ca.directAccess = true;
    else
        ca.directAccess = false;

    auto qscdSNInCert = getValue(json, "qscdSNInCert");
    if (qscdSNInCert.find("true") != std::string::npos)
        ca.qscdSNInCert = true;
    else
        ca.qscdSNInCert = false;

    auto cmpCompatibilityStr = getValue(json, "cmpCompatibility");
    if (!cmpCompatibilityStr.empty())
    {
        std::string numericOnly;
        for (char ch : cmpCompatibilityStr)
        {
            if (ch >= '0' && ch <= '9')
                numericOnly.push_back(ch);
        }
        if (!numericOnly.empty())
            ca.cmpCompatibility = std::stoi(numericOnly);
        else
            ca.cmpCompatibility = -1;
    }
    else
    {
        ca.cmpCompatibility = -1;
    }

    auto codeEDRPOU = getValue(json, "codeEDRPOU");
    if (!codeEDRPOU.empty())
    {
        auto firstQuotePos = codeEDRPOU.find_first_of("\"");
        auto lastQuotePos = codeEDRPOU.find_last_of("\"");
        if (firstQuotePos != std::string::npos && lastQuotePos != std::string::npos && lastQuotePos > firstQuotePos)
            codeEDRPOU = codeEDRPOU.substr(firstQuotePos + 1, lastQuotePos - firstQuotePos - 1);
        ca.codeEDRPOU = codeEDRPOU;
    }

    return ca;
}

std::vector<CASettings> parseCAsArray(const std::string &jsonArray)
{
    std::vector<CASettings> caList;
    std::size_t start = jsonArray.find("{");

    while (start != std::string::npos)
    {
        std::size_t end = jsonArray.find("}", start);
        if (end == std::string::npos)
            break;

        std::string jsonObject = jsonArray.substr(start, end - start + 1);
        caList.push_back(parseCA(jsonObject));

        start = jsonArray.find("{", end);
    }
    return caList;
}

std::vector<uint8_t> ReadAllBytes(const char *filePath)
{
    std::ifstream file(filePath, std::ios::binary | std::ios::ate);
    if (!file)
    {
        std::cerr << "IIT EU Sign Usage: Cannot open file for reading: " << filePath << std::endl;
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

void WriteAllText(const char *filePath, const std::string &data)
{
    std::ofstream outFile(filePath, std::ios::binary);
    if (!outFile)
    {
        std::cerr << "IIT EU Sign Usage: File " << filePath << " cannot be opened\n";
        return;
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

    // File store settings
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

    // Proxy settings
    int bUseProxy = PROXY_USE;
    int bProxyAnonymous = 0;
    char *pszProxyAddress = (char *)PROXY_ADDRESS;
    char *pszProxyPort = (char *)PROXY_PORT;
    char *pszProxyUser = (char *)PROXY_USER;
    char *pszProxyPassword = (char *)PROXY_PASSWORD;
    int bProxySavePassword = 1;

    dwError = g_pIface->SetProxySettings(
        bUseProxy, bProxyAnonymous,
        pszProxyAddress, pszProxyPort,
        pszProxyUser, pszProxyPassword,
        bProxySavePassword);
    if (dwError != EU_ERROR_NONE)
        return dwError;

    // OCSP settings
    int bUseOCSP = 1;
    int bBeforeStore = 1;
    char *pszOCSPAddress = (char *)DEFAULT_OCSP_SERVER;
    char *pszOCSPPort = (char *)"80";

    dwError = g_pIface->SetOCSPSettings(bUseOCSP, bBeforeStore, pszOCSPAddress, pszOCSPPort);
    if (dwError != EU_ERROR_NONE)
        return dwError;

    g_pIface->SetOCSPAccessInfoModeSettings(1);
    if (dwError != EU_ERROR_NONE)
        return dwError;

    // Read CAs from JSON
    {
        std::string filePath = CAS_JSON_PATH;
        std::string jsonStr = readFileToString(filePath);
        CAs = parseCAsArray(jsonStr);

        for (size_t i = 0; i < CAs.size(); i++)
        {
            for (size_t j = 0; j < CAs[i].issuerCNsv.size(); j++)
            {
                dwError = g_pIface->SetOCSPAccessInfoSettings(
                    (char *)CAs[i].issuerCNsv[j].c_str(),
                    (char *)CAs[i].ocspAccessPointAddress.c_str(),
                    (char *)CAs[i].ocspAccessPointPort.c_str());
                if (dwError != EU_ERROR_NONE)
                    return dwError;
            }
        }
    }

    // TSP settings
    int bUseTSP = 1;
    char *pszTSPAddress = (char *)DEFAULT_TSP_SERVER;
    char *pszTSPPort = (char *)"80";

    dwError = g_pIface->SetTSPSettings(bUseTSP, pszTSPAddress, pszTSPPort);
    if (dwError != EU_ERROR_NONE)
        return dwError;

    // LDAP settings (unused, but configured)
    int bUseLDAP = 0;
    char *pszLDAPAddress = (char *)"";
    char *pszLDAPPort = (char *)"";
    int bLDAPAnonymous = 1;
    char *pszLDAPUser = (char *)"";
    char *pszLDAPPassword = (char *)"";

    dwError = g_pIface->SetLDAPSettings(bUseLDAP, pszLDAPAddress, pszLDAPPort,
                                        bLDAPAnonymous, pszLDAPUser, pszLDAPPassword);
    if (dwError != EU_ERROR_NONE)
        return dwError;

    // CMP settings (unused, but configured)
    int bUseCMP = 1;
    char *pszCMPAddress = (char *)"";
    char *pszCMPPort = (char *)"80";
    char *pszCMPCommonName = (char *)"";

    dwError = g_pIface->SetCMPSettings(bUseCMP, pszCMPAddress, pszCMPPort, pszCMPCommonName);
    if (dwError != EU_ERROR_NONE)
        return dwError;

    // Load CA certificates
    {
        char *path = (char *)CA_CERTIFICATES_PATH;
        std::vector<uint8_t> res = ReadAllBytes(path);
        g_pIface->SaveCertificates(res.data(), res.size());
    }

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
    unsigned long dwError = Initialize();
    if (dwError != EU_ERROR_NONE)
    {
        printf("%lu\n", dwError);
        return dwError;
    }

    unsigned char *pbSenderCert = NULL;
    unsigned char *pbCustomerCrypto = NULL;
    unsigned char *pbDecryptedCustomerData = NULL;

    unsigned long dwSenderCertLength;
    unsigned long dwCustomerCryptoLength;
    unsigned long dwDecryptedCustomerLength;

    // Read private key
    dwError = g_pIface->ReadPrivateKeyFile(pszPrivKeyFilePath, pszPrivKeyPassword, NULL);
    if (dwError != EU_ERROR_NONE)
        return dwError;

    // Decode Sender cert
    dwError = g_pIface->BASE64Decode(pszSenderCert, &pbSenderCert, &dwSenderCertLength);
    if (dwError != EU_ERROR_NONE)
    {
        g_pIface->ResetPrivateKey();
        return dwError;
    }

    // Decode Customer Crypto
    dwError = g_pIface->BASE64Decode(pszCustomerCrypto, &pbCustomerCrypto, &dwCustomerCryptoLength);
    if (dwError != EU_ERROR_NONE)
    {
        g_pIface->FreeMemory(pbSenderCert);
        g_pIface->ResetPrivateKey();
        return dwError;
    }

    // Develop data
    dwError = g_pIface->DevelopDataEx(
        NULL,
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

    // Re-sign data to verify
    char *developedSign = nullptr;
    dwError = g_pIface->BASE64Encode(pbDecryptedCustomerData, dwDecryptedCustomerLength, &developedSign);
    if (dwError != EU_ERROR_NONE)
    {
        g_pIface->FreeMemory(pbDecryptedCustomerData);
        g_pIface->ResetPrivateKey();
        return dwError;
    }

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

    // Cleanup
    g_pIface->FreeMemory(pbDecryptedCustomerData);
    g_pIface->ResetPrivateKey();

    return EU_ERROR_NONE;
}

// Example hard-coded data placeholders
char g_szSenderCert[] = "MIIFrDCCBVSgAwIBAgIUXphNUm+C848EAAAAc4OuAXED6AUwDQYLKoYkAgEBAQEDAQEwgb4xKTAnBgNVBAoMINCQ0KIg0JrQkSAi0J/QoNCY0JLQkNCi0JHQkNCd0JoiMT0wOwYDVQQDDDTQmtCd0JXQlNCfINCQ0KbQodCaINCQ0KIg0JrQkSAi0J/QoNCY0JLQkNCi0JHQkNCd0JoiMRkwFwYDVQQFExBVQS0xNDM2MDU3MC0yMzEwMQswCQYDVQQGEwJVQTERMA8GA1UEBwwI0JrQuNGX0LIxFzAVBgNVBGEMDk5UUlVBLTE0MzYwNTcwMB4XDTI1MDEyNzE1NDk1NFoXDTI2MDEyNzIxNTk1OVowgfQxIjAgBgNVBAoMGdCk0IbQl9CY0KfQndCQINCe0KHQntCR0JAxMTAvBgNVBAMMKNCU0JXQnNCn0KPQmiDQndCQ0JfQkNCgINCG0JPQntCg0J7QktCY0KcxFTATBgNVBAQMDNCU0JXQnNCn0KPQmjEkMCIGA1UEKgwb0J3QkNCX0JDQoCDQhtCT0J7QoNCe0JLQmNCnMRkwFwYDVQQFExBUSU5VQS0zNzkyOTA5NjM0MQswCQYDVQQGEwJVQTEZMBcGA1UEBwwQ0JPQntCg0J7QlNCY0KnQlTEbMBkGA1UECAwS0JLQntCb0JjQndCh0KzQmtCQMIGIMGAGCyqGJAIBAQEBAwEBMFEGDSqGJAIBAQEBAwEBAgYEQKnW60XxPHCCgMSWeyMfXq32WOukwDcpHTjZa/Alyk4X+OlyDcYVtDool18Lwd6jZDi1ZOosF5/QEj5tuPrFeQQDJAAEIXR9+ymPS8+qqqyiyRrKD3IV16LSYSax2D6Xna2tOQywAaOCAsMwggK/MCkGA1UdDgQiBCAGp2QdD1q9WHlbsrCSNsq8xkmY/GfxUdgvEAsKoFRxhDArBgNVHSMEJDAigCBemE1Sb4Lzj/S+LkAEaA3+s6/KwuQEdU0H0K5MhLB8HTAOBgNVHQ8BAf8EBAMCBsAwSAYDVR0gBEEwPzA9BgkqhiQCAQEBAgIwMDAuBggrBgEFBQcCARYiaHR0cHM6Ly9hY3NrLnByaXZhdGJhbmsudWEvYWNza2RvYzAJBgNVHRMEAjAAMGoGCCsGAQUFBwEDBF4wXDAIBgYEAI5GAQEwLAYGBACORgEFMCIwIBYaaHR0cHM6Ly9hY3NrLnByaXZhdGJhbmsudWETAmVuMBUGCCsGAQUFBwsCMAkGBwQAi+xJAQEwCwYJKoYkAgEBAQIBMD4GA1UdHwQ3MDUwM6AxoC+GLWh0dHA6Ly9hY3NrLnByaXZhdGJhbmsudWEvY3JsL1BCLTIwMjMtUzI0LmNybDBJBgNVHS4EQjBAMD6gPKA6hjhodHRwOi8vYWNzay5wcml2YXRiYW5rLnVhL2NybGRlbHRhL1BCLURlbHRhLTIwMjMtUzI0LmNybDCBhQYIKwYBBQUHAQEEeTB3MDQGCCsGAQUFBzABhihodHRwOi8vYWNzay5wcml2YXRiYW5rLnVhL3NlcnZpY2VzL29jc3AvMD8GCCsGAQUFBzAChjNodHRwOi8vYWNzay5wcml2YXRiYW5rLnVhL2FyY2gvZG93bmxvYWQvUEItMjAyMy5wN2IwQwYIKwYBBQUHAQsENzA1MDMGCCsGAQUFBzADhidodHRwOi8vYWNzay5wcml2YXRiYW5rLnVhL3NlcnZpY2VzL3RzcC8wPAYDVR0JBDUwMzAcBgwqhiQCAQEBCwEEAQExDBMKMzc5MjkwOTYzNDATBgwqhiQCAQEBCwEEBwExAxMBMDANBgsqhiQCAQEBAQMBAQNDAARA90nJatow7LTl08fxOgL+ASXqg7n7xRocbkoyAzYXNn3/wH5ka+Htm4118C8hp+/m1TOh6Zxw+To9Wbu9bAITCw==";


char g_szCustomerCrypto[] = "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";

int main()
{
    unsigned long dwError;
    unsigned char *pbCustomerData = NULL;
    unsigned long dwCustomerData = 0;

    EU_ENVELOP_INFO senderInfo;
    EU_SIGN_INFO signInfo;

    // Load the EUSignCP library
    if (!EULoad())
    {
        PrintMessage(GetErrorMessage(EU_ERROR_LIBRARY_LOAD));
        return 1;
    }

    g_pIface = EUGetInterface();

    // Decrypt / develop the customer crypto
    dwError = DevelopCustomerCrypto(
        (char *)PRIVATE_KEY_FILE_PATH,
        (char *)PRIVATE_KEY_PASSWORD,
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

    // Convert raw bytes to string
    char *pszCustomerData = (char *)malloc(dwCustomerData + 1);
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
    pszCustomerData[dwCustomerData] = '\0';

    g_pIface->FreeMemory(pbCustomerData);

    // Write result to a file
    std::string customerData = pszCustomerData;
    WriteAllText("./Modules/Data/data.json", customerData);

    std::cout << customerData << "\n";

    free(pszCustomerData);

    g_pIface->FreeSignInfo(&signInfo);
    g_pIface->FreeSenderInfo(&senderInfo);

    // Finalize the library
    g_pIface->Finalize();
    EUUnload();

    return 0;
}
