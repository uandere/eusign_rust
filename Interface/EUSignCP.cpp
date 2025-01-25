//=============================================================================

#include "EUSignCP.h"

//=============================================================================

#define DLL_PROCESS_ATTACH	1
#define DLL_PROCESS_DETACH	0
#define DLL_THREAD_ATTACH	2
#define DLL_THREAD_DETACH	3

#define MAX_PATH			260

//=============================================================================

typedef void*				HMODULE;

//-----------------------------------------------------------------------------

typedef int (*FARPROC) ();

typedef int (*PDLLMAIN) (
	HMODULE			hInstance,
	unsigned long	dwReason,
	void*);

//=============================================================================

FARPROC GetProcAddress(
	HMODULE		hModule,
	const char*		lpProcName)
{
	return (FARPROC) dlsym(
		hModule, lpProcName);
}

void* LoadLibraryA(
	const char*		lpLibFileName)
{
	HMODULE			hModule;

	hModule = dlopen(lpLibFileName, RTLD_NOW);
	if (!hModule)
		return NULL;

	PDLLMAIN pDllMain = (PDLLMAIN) 
		GetProcAddress(hModule, "DllMain");
	if (pDllMain)
	{
		int blLoadResult = pDllMain(
			hModule, DLL_PROCESS_ATTACH, NULL);
		if (blLoadResult == 0)
		{
			dlclose(hModule);
			return NULL;
		}
	}

	return hModule;
}

int FreeLibrary(
	HMODULE hModule)
{
	PDLLMAIN pDllMain = (PDLLMAIN) GetProcAddress(
		hModule, "DllMain");
	if (pDllMain)
	{
		int blLoadResult = pDllMain(
			hModule, DLL_PROCESS_DETACH, NULL);
		if (blLoadResult == 0)
		{
			dlclose(hModule);
			return 0;
		}
	}

	return (dlclose(hModule) == 0);
}

//=============================================================================

#ifndef PC_STATIC_LIBS
static	HMODULE			s_hLibrary = NULL;
#endif // PC_STATIC_LIBS
static	EU_INTERFACE	s_Iface;

//=============================================================================

int EULoad()
{
	unsigned long	dwI;

#ifndef PC_STATIC_LIBS
	char 	szLibFile[MAX_PATH * 4 + 1];

	if (s_hLibrary != NULL)
		return 1;

#ifdef PC_LIBS_IN_CURRENT
	getcwd(szLibFile, sizeof(szLibFile));

	if (szLibFile[strlen(szLibFile) - 1] != '/')
		strcat(szLibFile, "/");

	strcat(szLibFile, EU_LIBRARY_NAME);

	s_hLibrary = LoadLibraryA(szLibFile);
#else // PC_LIBS_IN_CURRENT
	s_hLibrary = LoadLibraryA(EU_LIBRARY_NAME);
#endif // PC_LIBS_IN_CURRENT
	if(!s_hLibrary)
		return 0;

	s_Iface.Initialize = (PEU_INITIALIZE) 
		GetProcAddress(s_hLibrary, "EUInitialize");
	s_Iface.IsInitialized = (PEU_IS_INITIALIZED) 
		GetProcAddress(s_hLibrary, "EUIsInitialized");
	s_Iface.Finalize = (PEU_FINALIZE) 
		GetProcAddress(s_hLibrary, "EUFinalize");

	s_Iface.SetSettings = (PEU_SET_SETTINGS) 
		GetProcAddress(s_hLibrary, "EUSetSettings");

	s_Iface.ShowCertificates = (PEU_SHOW_CERTIFICATES) 
		GetProcAddress(s_hLibrary, "EUShowCertificates");
	s_Iface.ShowCRLs = (PEU_SHOW_CRLS) 
		GetProcAddress(s_hLibrary, "EUShowCRLs");

	s_Iface.GetPrivateKeyMedia = (PEU_GET_PRIVATE_KEY_MEDIA) 
		GetProcAddress(s_hLibrary, "EUGetPrivateKeyMedia");
	s_Iface.ReadPrivateKey = (PEU_READ_PRIVATE_KEY) 
		GetProcAddress(s_hLibrary, "EUReadPrivateKey");
	s_Iface.IsPrivateKeyReaded = (PEU_IS_PRIVATE_KEY_READED) 
		GetProcAddress(s_hLibrary, "EUIsPrivateKeyReaded");
	s_Iface.ResetPrivateKey = (PEU_RESET_PRIVATE_KEY) 
		GetProcAddress(s_hLibrary, "EUResetPrivateKey");
	s_Iface.FreeCertOwnerInfo = (PEU_FREE_CERT_OWNER_INFO) 
		GetProcAddress(s_hLibrary, "EUFreeCertOwnerInfo");

	s_Iface.ShowOwnCertificate = (PEU_SHOW_OWN_CERTIFICATE) 
		GetProcAddress(s_hLibrary, "EUShowOwnCertificate");
	s_Iface.ShowSignInfo = (PEU_SHOW_SIGN_INFO) 
		GetProcAddress(s_hLibrary, "EUShowSignInfo");
	s_Iface.FreeSignInfo = (PEU_FREE_SIGN_INFO) 
		GetProcAddress(s_hLibrary, "EUFreeSignInfo");

	s_Iface.FreeMemory = (PEU_FREE_MEMORY) 
		GetProcAddress(s_hLibrary, "EUFreeMemory");

	s_Iface.GetErrorDesc = (PEU_GET_ERROR_DESC) 
		GetProcAddress(s_hLibrary, "EUGetErrorDesc");

	s_Iface.SignData = (PEU_SIGN_DATA) 
		GetProcAddress(s_hLibrary, "EUSignData");
	s_Iface.VerifyData = (PEU_VERIFY_DATA) 
		GetProcAddress(s_hLibrary, "EUVerifyData");

	s_Iface.SignDataContinue = (PEU_SIGN_DATA_CONTINUE) 
		GetProcAddress(s_hLibrary, "EUSignDataContinue");
	s_Iface.SignDataEnd = (PEU_SIGN_DATA_END) 
		GetProcAddress(s_hLibrary, "EUSignDataEnd");
	s_Iface.VerifyDataBegin = (PEU_VERIFY_DATA_BEGIN) 
		GetProcAddress(s_hLibrary, "EUVerifyDataBegin");
	s_Iface.VerifyDataContinue = (PEU_VERIFY_DATA_CONTINUE) 
		GetProcAddress(s_hLibrary, "EUVerifyDataContinue");
	s_Iface.VerifyDataEnd = (PEU_VERIFY_DATA_END) 
		GetProcAddress(s_hLibrary, "EUVerifyDataEnd");
	s_Iface.ResetOperation = (PEU_RESET_OPERATION)
		GetProcAddress(s_hLibrary, "EUResetOperation");

	s_Iface.SignFile = (PEU_SIGN_FILE)
		GetProcAddress(s_hLibrary, "EUSignFile");
	s_Iface.VerifyFile = (PEU_VERIFY_FILE)
		GetProcAddress(s_hLibrary, "EUVerifyFile");

	s_Iface.SignDataInternal = (PEU_SIGN_DATA_INTERNAL) 
		GetProcAddress(s_hLibrary, "EUSignDataInternal");
	s_Iface.VerifyDataInternal = (PEU_VERIFY_DATA_INTERNAL) 
		GetProcAddress(s_hLibrary, "EUVerifyDataInternal");

	s_Iface.SelectCertInfo = (PEU_SELECT_CERTIFICATE_INFO) 
		GetProcAddress(s_hLibrary, "EUSelectCertificateInfo");

	s_Iface.SetUIMode = (PEU_SET_UI_MODE)
		GetProcAddress(s_hLibrary, "EUSetUIMode");

	s_Iface.HashData = (PEU_HASH_DATA)
		GetProcAddress(s_hLibrary, "EUHashData");
	s_Iface.HashDataContinue = (PEU_HASH_DATA_CONTINUE)
		GetProcAddress(s_hLibrary, "EUHashDataContinue");
	s_Iface.HashDataEnd = (PEU_HASH_DATA_END)
		GetProcAddress(s_hLibrary, "EUHashDataEnd");
	s_Iface.HashFile = (PEU_HASH_FILE)
		GetProcAddress(s_hLibrary, "EUHashFile");
	s_Iface.SignHash = (PEU_SIGN_HASH)
		GetProcAddress(s_hLibrary, "EUSignHash");
	s_Iface.VerifyHash = (PEU_VERIFY_HASH)
		GetProcAddress(s_hLibrary, "EUVerifyHash");

	s_Iface.EnumKeyMediaTypes = (PEU_ENUM_KEY_MEDIA_TYPES)
		GetProcAddress(s_hLibrary, "EUEnumKeyMediaTypes");
	s_Iface.EnumKeyMediaDevices = (PEU_ENUM_KEY_MEDIA_DEVICES)
		GetProcAddress(s_hLibrary, "EUEnumKeyMediaDevices");

	s_Iface.GetFileStoreSettings = (PEU_GET_FILE_STORE_SETTINGS)
		GetProcAddress(s_hLibrary, "EUGetFileStoreSettings");
	s_Iface.SetFileStoreSettings = (PEU_SET_FILE_STORE_SETTINGS)
		GetProcAddress(s_hLibrary, "EUSetFileStoreSettings");
	s_Iface.GetProxySettings = (PEU_GET_PROXY_SETTINGS)
		GetProcAddress(s_hLibrary, "EUGetProxySettings");
	s_Iface.SetProxySettings = (PEU_SET_PROXY_SETTINGS)
		GetProcAddress(s_hLibrary, "EUSetProxySettings");
	s_Iface.GetOCSPSettings = (PEU_GET_OCSP_SETTINGS)
		GetProcAddress(s_hLibrary, "EUGetOCSPSettings");
	s_Iface.SetOCSPSettings = (PEU_SET_OCSP_SETTINGS)
		GetProcAddress(s_hLibrary, "EUSetOCSPSettings");
	s_Iface.GetTSPSettings = (PEU_GET_TSP_SETTINGS)
		GetProcAddress(s_hLibrary, "EUGetTSPSettings");
	s_Iface.SetTSPSettings = (PEU_SET_TSP_SETTINGS)
		GetProcAddress(s_hLibrary, "EUSetTSPSettings");
	s_Iface.GetLDAPSettings = (PEU_GET_LDAP_SETTINGS)
		GetProcAddress(s_hLibrary, "EUGetLDAPSettings");
	s_Iface.SetLDAPSettings = (PEU_SET_LDAP_SETTINGS)
		GetProcAddress(s_hLibrary, "EUSetLDAPSettings");

	s_Iface.GetCertificatesCount = (PEU_GET_CERTIFICATES_COUNT)
		GetProcAddress(s_hLibrary, "EUGetCertificatesCount");
	s_Iface.EnumCertificates = (PEU_ENUM_CERTIFICATES)
		GetProcAddress(s_hLibrary, "EUEnumCertificates");
	s_Iface.GetCRLsCount = (PEU_GET_CRLS_COUNT)
		GetProcAddress(s_hLibrary, "EUGetCRLsCount");
	s_Iface.EnumCRLs = (PEU_ENUM_CRLS)
		GetProcAddress(s_hLibrary, "EUEnumCRLs");
	s_Iface.FreeCRLInfo = (PEU_FREE_CRL_INFO)
		GetProcAddress(s_hLibrary, "EUFreeCRLInfo");

	s_Iface.GetCertificateInfo = (PEU_GET_CERTIFICATE_INFO)
		GetProcAddress(s_hLibrary, "EUGetCertificateInfo");
	s_Iface.FreeCertificateInfo = (PEU_FREE_CERTIFICATE_INFO)
		GetProcAddress(s_hLibrary, "EUFreeCertificateInfo");
	s_Iface.GetCRLDetailedInfo = (PEU_GET_CRL_DETAILED_INFO)
		GetProcAddress(s_hLibrary, "EUGetCRLDetailedInfo");
	s_Iface.FreeCRLDetailedInfo = (PEU_FREE_CRL_DETAILED_INFO)
		GetProcAddress(s_hLibrary, "EUFreeCRLDetailedInfo");

	s_Iface.GetCMPSettings = (PEU_GET_CMP_SETTINGS)
		GetProcAddress(s_hLibrary, "EUGetCMPSettings");
	s_Iface.SetCMPSettings = (PEU_SET_CMP_SETTINGS)
		GetProcAddress(s_hLibrary, "EUSetCMPSettings");
	s_Iface.DoesNeedSetSettings = (PEU_DOES_NEED_SET_SETTINGS)
		GetProcAddress(s_hLibrary, "EUDoesNeedSetSettings");

	s_Iface.GetPrivateKeyMediaSettings =
		(PEU_GET_PRIVATE_KEY_MEDIA_SETTINGS)
		GetProcAddress(s_hLibrary, "EUGetPrivateKeyMediaSettings");
	s_Iface.SetPrivateKeyMediaSettings =
		(PEU_SET_PRIVATE_KEY_MEDIA_SETTINGS)
		GetProcAddress(s_hLibrary, "EUSetPrivateKeyMediaSettings");

	s_Iface.SelectCMPServer = (PEU_SELECT_CMP_SERVER)
		GetProcAddress(s_hLibrary, "EUSelectCMPServer");

	s_Iface.RawSignData = (PEU_RAW_SIGN_DATA)
		GetProcAddress(s_hLibrary, "EURawSignData");
	s_Iface.RawVerifyData = (PEU_RAW_VERIFY_DATA)
		GetProcAddress(s_hLibrary, "EURawVerifyData");
	s_Iface.RawSignHash = (PEU_RAW_SIGN_HASH)
		GetProcAddress(s_hLibrary, "EURawSignHash");
	s_Iface.RawVerifyHash = (PEU_RAW_VERIFY_HASH)
		GetProcAddress(s_hLibrary, "EURawVerifyHash");
	s_Iface.RawSignFile = (PEU_RAW_SIGN_FILE)
		GetProcAddress(s_hLibrary, "EURawSignFile");
	s_Iface.RawVerifyFile = (PEU_RAW_VERIFY_FILE)
		GetProcAddress(s_hLibrary, "EURawVerifyFile");

	s_Iface.BASE64Encode = (PEU_BASE64_ENCODE)
		GetProcAddress(s_hLibrary, "EUBASE64Encode");
	s_Iface.BASE64Decode = (PEU_BASE64_DECODE)
		GetProcAddress(s_hLibrary, "EUBASE64Decode");

	s_Iface.EnvelopData = (PEU_ENVELOP_DATA)
		GetProcAddress(s_hLibrary, "EUEnvelopData");
	s_Iface.DevelopData = (PEU_DEVELOP_DATA)
		GetProcAddress(s_hLibrary, "EUDevelopData");
	s_Iface.ShowSenderInfo = (PEU_SHOW_SENDER_INFO)
		GetProcAddress(s_hLibrary, "EUShowSenderInfo");
	s_Iface.FreeSenderInfo = (PEU_FREE_SENDER_INFO)
		GetProcAddress(s_hLibrary, "EUFreeSenderInfo");

	s_Iface.ParseCertificate = (PEU_PARSE_CERTIFICATE)
		GetProcAddress(s_hLibrary, "EUParseCertificate");

	s_Iface.ReadPrivateKeyBinary = (PEU_READ_PRIVATE_KEY_BINARY) 
		GetProcAddress(s_hLibrary, "EUReadPrivateKeyBinary");
	s_Iface.ReadPrivateKeyFile = (PEU_READ_PRIVATE_KEY_FILE) 
		GetProcAddress(s_hLibrary, "EUReadPrivateKeyFile");

	s_Iface.SessionDestroy = (PEU_SESSION_DESTROY)
		GetProcAddress(s_hLibrary, "EUSessionDestroy");
	s_Iface.ClientSessionCreateStep1 =
		(PEU_CLIENT_SESSION_CREATE_STEP1)
		GetProcAddress(s_hLibrary, "EUClientSessionCreateStep1");
	s_Iface.ServerSessionCreateStep1 =
		(PEU_SERVER_SESSION_CREATE_STEP1)
		GetProcAddress(s_hLibrary, "EUServerSessionCreateStep1");
	s_Iface.ClientSessionCreateStep2 =
		(PEU_CLIENT_SESSION_CREATE_STEP2)
		GetProcAddress(s_hLibrary, "EUClientSessionCreateStep2");
	s_Iface.ServerSessionCreateStep2 =
		(PEU_SERVER_SESSION_CREATE_STEP2)
		GetProcAddress(s_hLibrary, "EUServerSessionCreateStep2");
	s_Iface.SessionIsInitialized = (PEU_SESSION_IS_INITIALIZED)
		GetProcAddress(s_hLibrary, "EUSessionIsInitialized");
	s_Iface.SessionSave = (PEU_SESSION_SAVE)
		GetProcAddress(s_hLibrary, "EUSessionSave");
	s_Iface.SessionLoad = (PEU_SESSION_LOAD)
		GetProcAddress(s_hLibrary, "EUSessionLoad");
	s_Iface.SessionCheckCertificates =
		(PEU_SESSION_CHECK_CERTIFICATES)
		GetProcAddress(s_hLibrary, "EUSessionCheckCertificates");
	s_Iface.SessionEncrypt = (PEU_SESSION_ENCRYPT)
		GetProcAddress(s_hLibrary, "EUSessionEncrypt");
	s_Iface.SessionEncryptContinue = (PEU_SESSION_ENCRYPT_CONTINUE)
		GetProcAddress(s_hLibrary, "EUSessionEncryptContinue");
	s_Iface.SessionDecrypt = (PEU_SESSION_DECRYPT)
		GetProcAddress(s_hLibrary, "EUSessionDecrypt");
	s_Iface.SessionDecryptContinue = (PEU_SESSION_DECRYPT_CONTINUE)
		GetProcAddress(s_hLibrary, "EUSessionDecryptContinue");

	s_Iface.IsSignedData = (PEU_IS_SIGNED_DATA)
		GetProcAddress(s_hLibrary, "EUIsSignedData");
	s_Iface.IsEnvelopedData = (PEU_IS_ENVELOPED_DATA)
		GetProcAddress(s_hLibrary, "EUIsEnvelopedData");

	s_Iface.SessionGetPeerCertificateInfo =
		(PEU_SESSION_GET_PEER_CERTIFICATE_INFO)
		GetProcAddress(s_hLibrary, "EUSessionGetPeerCertificateInfo");

	s_Iface.SaveCertificate = (PEU_SAVE_CERTIFICATE)
		GetProcAddress(s_hLibrary, "EUSaveCertificate");
	s_Iface.RefreshFileStore = (PEU_REFRESH_FILE_STORE)
		GetProcAddress(s_hLibrary, "EURefreshFileStore");

	s_Iface.GetModeSettings = (PEU_GET_MODE_SETTINGS)
		GetProcAddress(s_hLibrary, "EUGetModeSettings");
	s_Iface.SetModeSettings = (PEU_SET_MODE_SETTINGS)
		GetProcAddress(s_hLibrary, "EUSetModeSettings");

	s_Iface.CheckCertificate = (PEU_CHECK_CERTIFICATE)
		GetProcAddress(s_hLibrary, "EUCheckCertificate");

	s_Iface.EnvelopFile = (PEU_ENVELOP_FILE)
		GetProcAddress(s_hLibrary, "EUEnvelopFile");
	s_Iface.DevelopFile = (PEU_DEVELOP_FILE)
		GetProcAddress(s_hLibrary, "EUDevelopFile");
	s_Iface.IsSignedFile = (PEU_IS_SIGNED_FILE)
		GetProcAddress(s_hLibrary, "EUIsSignedFile");
	s_Iface.IsEnvelopedFile = (PEU_IS_ENVELOPED_FILE)
		GetProcAddress(s_hLibrary, "EUIsEnvelopedFile");

	s_Iface.GetCertificate = (PEU_GET_CERTIFICATE)
		GetProcAddress(s_hLibrary, "EUGetCertificate");
	s_Iface.GetOwnCertificate = (PEU_GET_OWN_CERTIFICATE)
		GetProcAddress(s_hLibrary, "EUGetOwnCertificate");

	s_Iface.EnumOwnCertificates = (PEU_ENUM_OWN_CERTIFICATES)
		GetProcAddress(s_hLibrary, "EUEnumOwnCertificates");
	s_Iface.GetCertificateInfoEx = (PEU_GET_CERTIFICATE_INFO_EX)
		GetProcAddress(s_hLibrary, "EUGetCertificateInfoEx");
	s_Iface.FreeCertificateInfoEx = (PEU_FREE_CERTIFICATE_INFO_EX)
		GetProcAddress(s_hLibrary, "EUFreeCertificateInfoEx");

	s_Iface.GetReceiversCertificates = (PEU_GET_RECEIVERS_CERTIFICATES)
		GetProcAddress(s_hLibrary, "EUGetReceiversCertificates");
	s_Iface.FreeReceiversCertificates = (PEU_FREE_RECEIVERS_CERTIFICATES)
		GetProcAddress(s_hLibrary, "EUFreeReceiversCertificates");

	s_Iface.GeneratePrivateKey = (PEU_GENERATE_PRIVATE_KEY)
		GetProcAddress(s_hLibrary, "EUGeneratePrivateKey");
	s_Iface.ChangePrivateKeyPassword = (PEU_CHANGE_PRIVATE_KEY_PASSWORD)
		GetProcAddress(s_hLibrary, "EUChangePrivateKeyPassword");
	s_Iface.BackupPrivateKey = (PEU_BACKUP_PRIVATE_KEY)
		GetProcAddress(s_hLibrary, "EUBackupPrivateKey");
	s_Iface.DestroyPrivateKey = (PEU_DESTROY_PRIVATE_KEY)
		GetProcAddress(s_hLibrary, "EUDestroyPrivateKey");
	s_Iface.IsHardwareKeyMedia = (PEU_IS_HARDWARE_KEY_MEDIA)
		GetProcAddress(s_hLibrary, "EUIsHardwareKeyMedia");
	s_Iface.IsPrivateKeyExists = (PEU_IS_PRIVATE_KEY_EXISTS)
		GetProcAddress(s_hLibrary, "EUIsPrivateKeyExists");

	s_Iface.GetCRInfo = (PEU_GET_CR_INFO)
		GetProcAddress(s_hLibrary, "EUGetCRInfo");
	s_Iface.FreeCRInfo = (PEU_FREE_CR_INFO)
		GetProcAddress(s_hLibrary, "EUFreeCRInfo");

	s_Iface.SaveCertificates = (PEU_SAVE_CERTIFICATES)
		GetProcAddress(s_hLibrary, "EUSaveCertificates");
	s_Iface.SaveCRL = (PEU_SAVE_CRL)
		GetProcAddress(s_hLibrary, "EUSaveCRL");

	s_Iface.GetCertificateByEMail = (PEU_GET_CERTIFICATE_BY_EMAIL)
		GetProcAddress(s_hLibrary, "EUGetCertificateByEMail");
	s_Iface.GetCertificateByNBUCode =
		(PEU_GET_CERTIFICATE_BY_NBU_CODE)
		GetProcAddress(s_hLibrary, "EUGetCertificateByNBUCode");

	s_Iface.AppendSign = (PEU_APPEND_SIGN)
		GetProcAddress(s_hLibrary, "EUAppendSign");
	s_Iface.AppendSignInternal = (PEU_APPEND_SIGN_INTERNAL)
		GetProcAddress(s_hLibrary, "EUAppendSignInternal");
	s_Iface.VerifyDataSpecific = (PEU_VERIFY_DATA_SPECIFIC)
		GetProcAddress(s_hLibrary, "EUVerifyDataSpecific");
	s_Iface.VerifyDataInternalSpecific =
		(PEU_VERIFY_DATA_INTERNAL_SPECIFIC)
		GetProcAddress(s_hLibrary, "EUVerifyDataInternalSpecific");
	s_Iface.AppendSignBegin = (PEU_APPEND_SIGN_BEGIN)
		GetProcAddress(s_hLibrary, "EUAppendSignBegin");
	s_Iface.VerifyDataSpecificBegin =
		(PEU_VERIFY_DATA_SPECIFIC_BEGIN)
		GetProcAddress(s_hLibrary, "EUVerifyDataSpecificBegin");
	s_Iface.AppendSignFile = (PEU_APPEND_SIGN_FILE)
		GetProcAddress(s_hLibrary, "EUAppendSignFile");
	s_Iface.VerifyFileSpecific = (PEU_VERIFY_FILE_SPECIFIC)
		GetProcAddress(s_hLibrary, "EUVerifyFileSpecific");
	s_Iface.AppendSignHash = (PEU_APPEND_SIGN_HASH)
		GetProcAddress(s_hLibrary, "EUAppendSignHash");
	s_Iface.VerifyHashSpecific = (PEU_VERIFY_HASH_SPECIFIC)
		GetProcAddress(s_hLibrary, "EUVerifyHashSpecific");
	s_Iface.GetSignsCount = (PEU_GET_SIGNS_COUNT)
		GetProcAddress(s_hLibrary, "EUGetSignsCount");
	s_Iface.GetSignerInfo = (PEU_GET_SIGNER_INFO)
		GetProcAddress(s_hLibrary, "EUGetSignerInfo");
	s_Iface.GetFileSignsCount = (PEU_GET_FILE_SIGNS_COUNT)
		GetProcAddress(s_hLibrary, "EUGetFileSignsCount");
	s_Iface.GetFileSignerInfo = (PEU_GET_FILE_SIGNER_INFO)
		GetProcAddress(s_hLibrary, "EUGetFileSignerInfo");

	s_Iface.IsAlreadySigned = (PEU_IS_ALREADY_SIGNED)
		GetProcAddress(s_hLibrary, "EUIsAlreadySigned");
	s_Iface.IsFileAlreadySigned = (PEU_IS_FILE_ALREADY_SIGNED)
		GetProcAddress(s_hLibrary, "EUIsFileAlreadySigned");

	s_Iface.HashDataWithParams = (PEU_HASH_DATA_WITH_PARAMS)
		GetProcAddress(s_hLibrary, "EUHashDataWithParams");
	s_Iface.HashDataBeginWithParams = (PEU_HASH_DATA_BEGIN_WITH_PARAMS)
		GetProcAddress(s_hLibrary, "EUHashDataBeginWithParams");
	s_Iface.HashFileWithParams = (PEU_HASH_FILE_WITH_PARAMS)
		GetProcAddress(s_hLibrary, "EUHashFileWithParams");

	s_Iface.EnvelopDataEx = (PEU_ENVELOP_DATA_EX)
		GetProcAddress(s_hLibrary, "EUEnvelopDataEx");

	s_Iface.SetSettingsFilePath = (PEU_SET_SETTINGS_FILE_PATH)
		GetProcAddress(s_hLibrary, "EUSetSettingsFilePath");

	s_Iface.SetKeyMediaPassword = (PEU_SET_KEY_MEDIA_PASSWORD)
		GetProcAddress(s_hLibrary, "EUSetKeyMediaPassword");
	s_Iface.GeneratePrivateKeyEx = (PEU_GENERATE_PRIVATE_KEY_EX)
		GetProcAddress(s_hLibrary, "EUGeneratePrivateKeyEx");

	s_Iface.GetErrorLangDesc = (PEU_GET_ERROR_LANG_DESC)
		GetProcAddress(s_hLibrary, "EUGetErrorLangDesc");

	s_Iface.EnvelopFileEx = (PEU_ENVELOP_FILE_EX)
		GetProcAddress(s_hLibrary, "EUEnvelopFileEx");

	s_Iface.IsCertificates = (PEU_IS_CERTIFICATES)
		GetProcAddress(s_hLibrary, "EUIsCertificates");
	s_Iface.IsCertificatesFile = (PEU_IS_CERTIFICATES_FILE)
		GetProcAddress(s_hLibrary, "EUIsCertificatesFile");

	s_Iface.EnumCertificatesByOCode = (PEU_ENUM_CERTIFICATES_BY_O_CODE)
		GetProcAddress(s_hLibrary, "EUEnumCertificatesByOCode");
	s_Iface.GetCertificatesByOCode = (PEU_GET_CERTIFICATES_BY_O_CODE)
		GetProcAddress(s_hLibrary, "EUGetCertificatesByOCode");

	s_Iface.SetPrivateKeyMediaSettingsProtected =
		(PEU_SET_PRIVATE_KEY_MEDIA_SETTINGS_PROTECTED)
		GetProcAddress(s_hLibrary,
			"EUSetPrivateKeyMediaSettingsProtected");

	s_Iface.EnvelopDataToRecipients = (PEU_ENVELOP_DATA_TO_RECIPIENTS)
		GetProcAddress(s_hLibrary, "EUEnvelopDataToRecipients");
	s_Iface.EnvelopFileToRecipients = (PEU_ENVELOP_FILE_TO_RECIPIENTS)
		GetProcAddress(s_hLibrary, "EUEnvelopFileToRecipients");
	
	s_Iface.EnvelopDataExWithDynamicKey =
		(PEU_ENVELOP_DATA_EX_WITH_DYNAMIC_KEY)
		GetProcAddress(s_hLibrary,
			"EUEnvelopDataExWithDynamicKey");
	s_Iface.EnvelopDataToRecipientsWithDynamicKey =
		(PEU_ENVELOP_DATA_TO_RECIPIENTS_WITH_DYNAMIC_KEY)
		GetProcAddress(s_hLibrary,
			"EUEnvelopDataToRecipientsWithDynamicKey");
	s_Iface.EnvelopFileExWithDynamicKey =
		(PEU_ENVELOP_FILE_EX_WITH_DYNAMIC_KEY)
		GetProcAddress(s_hLibrary,
			"EUEnvelopFileExWithDynamicKey");
	s_Iface.EnvelopFileToRecipientsWithDynamicKey =
		(PEU_ENVELOP_FILE_TO_RECIPIENTS_WITH_DYNAMIC_KEY)
		GetProcAddress(s_hLibrary,
			"EUEnvelopFileToRecipientsWithDynamicKey");

	s_Iface.SavePrivateKey = (PEU_SAVE_PRIVATE_KEY)
		GetProcAddress(s_hLibrary, "EUSavePrivateKey");
	s_Iface.LoadPrivateKey = (PEU_LOAD_PRIVATE_KEY)
		GetProcAddress(s_hLibrary, "EULoadPrivateKey");
	s_Iface.ChangeSoftwarePrivateKeyPassword =
		(PEU_CHANGE_SOFTWARE_PRIVATE_KEY_PASSWORD)
		GetProcAddress(s_hLibrary,
			"EUChangeSoftwarePrivateKeyPassword");

	s_Iface.HashDataBeginWithParamsCtx =
		(PEU_HASH_DATA_BEGIN_WITH_PARAMS_CTX)
		GetProcAddress(s_hLibrary, "EUHashDataBeginWithParamsCtx");
	s_Iface.HashDataContinueCtx = (PEU_HASH_DATA_CONTINUE_CTX)
		GetProcAddress(s_hLibrary, "EUHashDataContinueCtx");
	s_Iface.HashDataEndCtx = (PEU_HASH_DATA_END_CTX)
		GetProcAddress(s_hLibrary, "EUHashDataEndCtx");

	s_Iface.GetCertificateByKeyInfo = (PEU_GET_CERTIFICATE_BY_KEY_INFO)
		GetProcAddress(s_hLibrary, "EUGetCertificateByKeyInfo");

	s_Iface.SavePrivateKeyEx = (PEU_SAVE_PRIVATE_KEY_EX)
		GetProcAddress(s_hLibrary, "EUSavePrivateKeyEx");
	s_Iface.LoadPrivateKeyEx = (PEU_LOAD_PRIVATE_KEY_EX)
		GetProcAddress(s_hLibrary, "EULoadPrivateKeyEx");

	s_Iface.CreateEmptySign = (PEU_CREATE_EMPTY_SIGN)
		GetProcAddress(s_hLibrary, "EUCreateEmptySign");
	s_Iface.CreateSigner = (PEU_CREATE_SIGNER)
		GetProcAddress(s_hLibrary, "EUCreateSigner");
	s_Iface.AppendSigner = (PEU_APPEND_SIGNER)
		GetProcAddress(s_hLibrary, "EUAppendSigner");

	s_Iface.SetRuntimeParameter = (PEU_SET_RUNTIME_PARAMETER)
		GetProcAddress(s_hLibrary, "EUSetRuntimeParameter");

	s_Iface.EnvelopDataToRecipientsEx =
		(PEU_ENVELOP_DATA_TO_RECIPIENTS_EX)
		GetProcAddress(s_hLibrary, "EUEnvelopDataToRecipientsEx");
	s_Iface.EnvelopFileToRecipientsEx =
		(PEU_ENVELOP_FILE_TO_RECIPIENTS_EX)
		GetProcAddress(s_hLibrary, "EUEnvelopFileToRecipientsEx");
	s_Iface.EnvelopDataToRecipientsWithOCode =
		(PEU_ENVELOP_DATA_TO_RECIPIENTS_WITH_O_CODE)
		GetProcAddress(s_hLibrary, "EUEnvelopDataToRecipientsWithOCode");

	s_Iface.SignDataContinueCtx = (PEU_SIGN_DATA_CONTINUE_CTX)
		GetProcAddress(s_hLibrary, "EUSignDataContinueCtx");
	s_Iface.SignDataEndCtx = (PEU_SIGN_DATA_END_CTX)
		GetProcAddress(s_hLibrary, "EUSignDataEndCtx");
	s_Iface.VerifyDataBeginCtx = (PEU_VERIFY_DATA_BEGIN_CTX) 
		GetProcAddress(s_hLibrary, "EUVerifyDataBeginCtx");
	s_Iface.VerifyDataContinueCtx = (PEU_VERIFY_DATA_CONTINUE_CTX) 
		GetProcAddress(s_hLibrary, "EUVerifyDataContinueCtx");
	s_Iface.VerifyDataEndCtx = (PEU_VERIFY_DATA_END_CTX) 
		GetProcAddress(s_hLibrary, "EUVerifyDataEndCtx");
	s_Iface.ResetOperationCtx = (PEU_RESET_OPERATION_CTX)
		GetProcAddress(s_hLibrary, "EUResetOperationCtx");

	s_Iface.SignDataRSA = (PEU_SIGN_DATA_RSA)
		GetProcAddress(s_hLibrary, "EUSignDataRSA");
	s_Iface.SignDataRSAContinue = (PEU_SIGN_DATA_RSA_CONTINUE)
		GetProcAddress(s_hLibrary, "EUSignDataRSAContinue");
	s_Iface.SignDataRSAEnd = (PEU_SIGN_DATA_RSA_END)
		GetProcAddress(s_hLibrary, "EUSignDataRSAEnd");
	s_Iface.SignFileRSA = (PEU_SIGN_FILE_RSA)
		GetProcAddress(s_hLibrary, "EUSignFileRSA");
	s_Iface.SignDataRSAContinueCtx = (PEU_SIGN_DATA_RSA_CONTINUE_CTX)
		GetProcAddress(s_hLibrary, "EUSignDataRSAContinueCtx");
	s_Iface.SignDataRSAEndCtx = (PEU_SIGN_DATA_RSA_END_CTX)
		GetProcAddress(s_hLibrary, "EUSignDataRSAEndCtx");

	s_Iface.DownloadFileViaHTTP = (PEU_DOWNLOAD_FILE_VIA_HTTP)
		GetProcAddress(s_hLibrary, "EUDownloadFileViaHTTP");

	s_Iface.ParseCRL = (PEU_PARSE_CRL)
		GetProcAddress(s_hLibrary, "EUParseCRL");

	s_Iface.IsOldFormatSign = (PEU_IS_OLD_FORMAT_SIGN)
		GetProcAddress(s_hLibrary, "EUIsOldFormatSign");
	s_Iface.IsOldFormatSignFile = (PEU_IS_OLD_FORMAT_SIGN_FILE)
		GetProcAddress(s_hLibrary, "EUIsOldFormatSignFile");

	s_Iface.GetPrivateKeyMediaEx = (PEU_GET_PRIVATE_KEY_MEDIA_EX)
		GetProcAddress(s_hLibrary, "EUGetPrivateKeyMediaEx");

	s_Iface.GetKeyInfo = (PEU_GET_KEY_INFO)
		GetProcAddress(s_hLibrary, "EUGetKeyInfo");
	s_Iface.GetKeyInfoBinary = (PEU_GET_KEY_INFO_BINARY)
		GetProcAddress(s_hLibrary, "EUGetKeyInfoBinary");
	s_Iface.GetKeyInfoFile = (PEU_GET_KEY_INFO_FILE)
		GetProcAddress(s_hLibrary, "EUGetKeyInfoFile");
	s_Iface.GetCertificatesByKeyInfo = (PEU_GET_CERTIFICATES_BY_KEY_INFO)
		GetProcAddress(s_hLibrary, "EUGetCertificatesByKeyInfo");

	s_Iface.EnvelopAppendData = (PEU_ENVELOP_APPEND_DATA)
		GetProcAddress(s_hLibrary, "EUEnvelopAppendData");
	s_Iface.EnvelopAppendFile = (PEU_ENVELOP_APPEND_FILE)
		GetProcAddress(s_hLibrary, "EUEnvelopAppendFile");
	s_Iface.EnvelopAppendDataEx = (PEU_ENVELOP_APPEND_DATA_EX)
		GetProcAddress(s_hLibrary, "EUEnvelopAppendDataEx");
	s_Iface.EnvelopAppendFileEx = (PEU_ENVELOP_APPEND_FILE_EX)
		GetProcAddress(s_hLibrary, "EUEnvelopAppendFileEx");

	s_Iface.GetStorageParameter = (PEU_GET_STORAGE_PARAMETER)
		GetProcAddress(s_hLibrary, "EUGetStorageParameter");
	s_Iface.SetStorageParameter = (PEU_SET_STORAGE_PARAMETER)
		GetProcAddress(s_hLibrary, "EUSetStorageParameter");

	s_Iface.DevelopDataEx = (PEU_DEVELOP_DATA_EX)
		GetProcAddress(s_hLibrary, "EUDevelopDataEx");
	s_Iface.DevelopFileEx = (PEU_DEVELOP_FILE_EX)
		GetProcAddress(s_hLibrary, "EUDevelopFileEx");

	s_Iface.GetOCSPAccessInfoModeSettings =
		(PEU_GET_OCSP_ACCESS_INFO_MODE_SETTINGS)
		GetProcAddress(s_hLibrary, "EUGetOCSPAccessInfoModeSettings");
	s_Iface.SetOCSPAccessInfoModeSettings =
		(PEU_SET_OCSP_ACCESS_INFO_MODE_SETTINGS)
		GetProcAddress(s_hLibrary, "EUSetOCSPAccessInfoModeSettings");

	s_Iface.EnumOCSPAccessInfoSettings = 
		(PEU_ENUM_OCSP_ACCESS_INFO_SETTINGS)
		GetProcAddress(s_hLibrary, "EUEnumOCSPAccessInfoSettings");
	s_Iface.GetOCSPAccessInfoSettings = 
		(PEU_GET_OCSP_ACCESS_INFO_SETTINGS)
		GetProcAddress(s_hLibrary, "EUGetOCSPAccessInfoSettings");
	s_Iface.SetOCSPAccessInfoSettings = 
		(PEU_SET_OCSP_ACCESS_INFO_SETTINGS)
		GetProcAddress(s_hLibrary, "EUSetOCSPAccessInfoSettings");
	s_Iface.DeleteOCSPAccessInfoSettings = 
		(PEU_DELETE_OCSP_ACCESS_INFO_SETTINGS)
		GetProcAddress(s_hLibrary, "EUDeleteOCSPAccessInfoSettings");

	s_Iface.CheckCertificateByIssuerAndSerial =
		(PEU_CHECK_CERTIFICATE_BY_ISSUER_AND_SERIAL)
		GetProcAddress(s_hLibrary, "EUCheckCertificateByIssuerAndSerial");

	s_Iface.ParseCertificateEx = (PEU_PARSE_CERTIFICATE_EX)
		GetProcAddress(s_hLibrary, "EUParseCertificateEx");

	s_Iface.CheckCertificateByIssuerAndSerialEx =
		(PEU_CHECK_CERTIFICATE_BY_ISSUER_AND_SERIAL_EX)
		GetProcAddress(s_hLibrary, "EUCheckCertificateByIssuerAndSerialEx");

	s_Iface.ClientDynamicKeySessionCreate =
		(PEU_CLIENT_DYNAMIC_KEY_SESSION_CREATE)
		GetProcAddress(s_hLibrary, "EUClientDynamicKeySessionCreate");
	s_Iface.ServerDynamicKeySessionCreate =
		(PEU_SERVER_DYNAMIC_KEY_SESSION_CREATE)
		GetProcAddress(s_hLibrary, "EUServerDynamicKeySessionCreate");

	s_Iface.GetSenderInfo = (PEU_GET_SENDER_INFO)
		GetProcAddress(s_hLibrary, "EUGetSenderInfo");
	s_Iface.GetFileSenderInfo = (PEU_GET_FILE_SENDER_INFO)
		GetProcAddress(s_hLibrary, "EUGetFileSenderInfo");

	s_Iface.SCClientIsRunning =
		(PEU_SC_CLIENT_IS_RUNNING)
		GetProcAddress(s_hLibrary, "EUSCClientIsRunning");
	s_Iface.SCClientStart =
		(PEU_SC_CLIENT_START)
		GetProcAddress(s_hLibrary, "EUSCClientStart");
	s_Iface.SCClientStop =
		(PEU_SC_CLIENT_STOP)
		GetProcAddress(s_hLibrary, "EUSCClientStop");
	s_Iface.SCClientAddGate =
		(PEU_SC_CLIENT_ADD_GATE)
		GetProcAddress(s_hLibrary, "EUSCClientAddGate");
	s_Iface.SCClientRemoveGate =
		(PEU_SC_CLIENT_REMOVE_GATE)
		GetProcAddress(s_hLibrary, "EUSCClientRemoveGate");
	s_Iface.SCClientGetStatistic =
		(PEU_SC_CLIENT_GET_STATISTIC)
		GetProcAddress(s_hLibrary, "EUSCClientGetStatistic");
	s_Iface.SCClientFreeStatistic =
		(PEU_SC_CLIENT_FREE_STATISTIC)
		GetProcAddress(s_hLibrary, "EUSCClientFreeStatistic");

	s_Iface.GetRecipientsCount =
		(PEU_GET_RECIPIENTS_COUNT)
		GetProcAddress(s_hLibrary, "EUGetRecipientsCount");
	s_Iface.GetFileRecipientsCount =
		(PEU_GET_FILE_RECIPIENTS_COUNT)
		GetProcAddress(s_hLibrary, "EUGetFileRecipientsCount");
	s_Iface.GetRecipientInfo =
		(PEU_GET_RECIPIENT_INFO)
		GetProcAddress(s_hLibrary, "EUGetRecipientInfo");
	s_Iface.GetFileRecipientInfo =
		(PEU_GET_FILE_RECIPIENT_INFO)
		GetProcAddress(s_hLibrary, "EUGetFileRecipientInfo");

	s_Iface.CtxCreate =
		(PEU_CTX_CREATE)
		GetProcAddress(s_hLibrary, "EUCtxCreate");
	s_Iface.CtxFree =
		(PEU_CTX_FREE)
		GetProcAddress(s_hLibrary, "EUCtxFree");
	s_Iface.CtxSetParameter =
		(PEU_CTX_SET_PARAMETER)
		GetProcAddress(s_hLibrary, "EUCtxSetParameter");
	s_Iface.CtxReadPrivateKey =
		(PEU_CTX_READ_PRIVATE_KEY)
		GetProcAddress(s_hLibrary, "EUCtxReadPrivateKey");
	s_Iface.CtxReadPrivateKeyBinary =
		(PEU_CTX_READ_PRIVATE_KEY_BINARY)
		GetProcAddress(s_hLibrary, "EUCtxReadPrivateKeyBinary");
	s_Iface.CtxReadPrivateKeyFile =
		(PEU_CTX_READ_PRIVATE_KEY_FILE)
		GetProcAddress(s_hLibrary, "EUCtxReadPrivateKeyFile");
	s_Iface.CtxFreePrivateKey =
		(PEU_CTX_FREE_PRIVATE_KEY)
		GetProcAddress(s_hLibrary, "EUCtxFreePrivateKey");

	s_Iface.CtxDevelopData = (PEU_CTX_DEVELOP_DATA)
		GetProcAddress(s_hLibrary, "EUCtxDevelopData");
	s_Iface.CtxDevelopFile = (PEU_CTX_DEVELOP_FILE)
		GetProcAddress(s_hLibrary, "EUCtxDevelopFile");

	s_Iface.CtxFreeMemory = (PEU_CTX_FREE_MEMORY)
		GetProcAddress(s_hLibrary, "EUCtxFreeMemory");
	s_Iface.CtxFreeCertOwnerInfo = (PEU_CTX_FREE_CERT_OWNER_INFO)
		GetProcAddress(s_hLibrary, "EUCtxFreeCertOwnerInfo");
	s_Iface.CtxFreeCertificateInfoEx = 
		(PEU_CTX_FREE_CERTIFICATE_INFO_EX)
		GetProcAddress(s_hLibrary, "EUCtxFreeCertificateInfoEx");
	s_Iface.CtxFreeSignInfo = (PEU_CTX_FREE_SIGN_INFO)
		GetProcAddress(s_hLibrary, "EUCtxFreeSignInfo");
	s_Iface.CtxFreeSenderInfo = (PEU_CTX_FREE_SENDER_INFO)
		GetProcAddress(s_hLibrary, "EUCtxFreeSenderInfo");

	s_Iface.CtxGetOwnCertificate = (PEU_CTX_GET_OWN_CERTIFICATE)
		GetProcAddress(s_hLibrary, "EUCtxGetOwnCertificate");
	s_Iface.CtxEnumOwnCertificates = (PEU_CTX_ENUM_OWN_CERTIFICATES)
		GetProcAddress(s_hLibrary, "EUCtxEnumOwnCertificates");

	s_Iface.CtxHashData = (PEU_CTX_HASH_DATA)
		GetProcAddress(s_hLibrary, "EUCtxHashData");
	s_Iface.CtxHashFile = (PEU_CTX_HASH_FILE)
		GetProcAddress(s_hLibrary, "EUCtxHashFile");
	s_Iface.CtxHashDataBegin = (PEU_CTX_HASH_DATA_BEGIN)
		GetProcAddress(s_hLibrary, "EUCtxHashDataBegin");
	s_Iface.CtxHashDataContinue = (PEU_CTX_HASH_DATA_CONTINUE)
		GetProcAddress(s_hLibrary, "EUCtxHashDataContinue");
	s_Iface.CtxHashDataEnd = (PEU_CTX_HASH_DATA_END)
		GetProcAddress(s_hLibrary, "EUCtxHashDataEnd");
	s_Iface.CtxFreeHash = (PEU_CTX_FREE_HASH)
		GetProcAddress(s_hLibrary, "EUCtxFreeHash");

	s_Iface.CtxSignHash = (PEU_CTX_SIGN_HASH)
		GetProcAddress(s_hLibrary, "EUCtxSignHash");
	s_Iface.CtxSignHashValue = (PEU_CTX_SIGN_HASH_VALUE)
		GetProcAddress(s_hLibrary, "EUCtxSignHashValue");
	s_Iface.CtxSignData = (PEU_CTX_SIGN_DATA)
		GetProcAddress(s_hLibrary, "EUCtxSignData");
	s_Iface.CtxSignFile = (PEU_CTX_SIGN_FILE)
		GetProcAddress(s_hLibrary, "EUCtxSignFile");
	s_Iface.CtxIsAlreadySigned = (PEU_CTX_IS_ALREADY_SIGNED)
		GetProcAddress(s_hLibrary, "EUCtxIsAlreadySigned");
	s_Iface.CtxIsFileAlreadySigned = 
		(PEU_CTX_IS_FILE_ALREADY_SIGNED)
		GetProcAddress(s_hLibrary, "EUCtxIsFileAlreadySigned");
	s_Iface.CtxAppendSignHash = (PEU_CTX_APPEND_SIGN_HASH)
		GetProcAddress(s_hLibrary, "EUCtxAppendSignHash");
	s_Iface.CtxAppendSignHashValue = 
		(PEU_CTX_APPEND_SIGN_HASH_VALUE)
		GetProcAddress(s_hLibrary, "EUCtxAppendSignHashValue");
	s_Iface.CtxAppendSign = (PEU_CTX_APPEND_SIGN)
		GetProcAddress(s_hLibrary, "EUCtxAppendSign");
	s_Iface.CtxAppendSignFile = (PEU_CTX_APPEND_SIGN_FILE)
		GetProcAddress(s_hLibrary, "EUCtxAppendSignFile");
	s_Iface.CtxCreateEmptySign = (PEU_CTX_CREATE_EMPTY_SIGN)
		GetProcAddress(s_hLibrary, "EUCtxCreateEmptySign");
	s_Iface.CtxCreateSigner = (PEU_CTX_CREATE_SIGNER)
		GetProcAddress(s_hLibrary, "EUCtxCreateSigner");
	s_Iface.CtxAppendSigner = (PEU_CTX_APPEND_SIGNER)
		GetProcAddress(s_hLibrary, "EUCtxAppendSigner");
	s_Iface.CtxGetSignsCount = (PEU_CTX_GET_SIGNS_COUNT)
		GetProcAddress(s_hLibrary, "EUCtxGetSignsCount");
	s_Iface.CtxGetFileSignsCount = (PEU_CTX_GET_FILE_SIGNS_COUNT)
		GetProcAddress(s_hLibrary, "EUCtxGetFileSignsCount");
	s_Iface.CtxGetSignerInfo = (PEU_CTX_GET_SIGNER_INFO)
		GetProcAddress(s_hLibrary, "EUCtxGetSignerInfo");
	s_Iface.CtxGetFileSignerInfo = (PEU_CTX_GET_FILE_SIGNER_INFO)
		GetProcAddress(s_hLibrary, "EUCtxGetFileSignerInfo");
	s_Iface.CtxVerifyHash = (PEU_CTX_VERIFY_HASH)
		GetProcAddress(s_hLibrary, "EUCtxVerifyHash");
	s_Iface.CtxVerifyHashValue = (PEU_CTX_VERIFY_HASH_VALUE)
		GetProcAddress(s_hLibrary, "EUCtxVerifyHashValue");
	s_Iface.CtxVerifyData = (PEU_CTX_VERIFY_DATA)
		GetProcAddress(s_hLibrary, "EUCtxVerifyData");
	s_Iface.CtxVerifyDataInternal = (PEU_CTX_VERIFY_DATA_INTERNAL)
		GetProcAddress(s_hLibrary, "EUCtxVerifyDataInternal");
	s_Iface.CtxVerifyFile = (PEU_CTX_VERIFY_FILE)
		GetProcAddress(s_hLibrary, "EUCtxVerifyFile");

	s_Iface.CtxEnvelopData = (PEU_CTX_ENVELOP_DATA)
		GetProcAddress(s_hLibrary, "EUCtxEnvelopData");
	s_Iface.CtxEnvelopFile = (PEU_CTX_ENVELOP_FILE)
		GetProcAddress(s_hLibrary, "EUCtxEnvelopFile");
	s_Iface.CtxGetSenderInfo = (PEU_CTX_GET_SENDER_INFO)
		GetProcAddress(s_hLibrary, "EUCtxGetSenderInfo");
	s_Iface.CtxGetFileSenderInfo = (PEU_CTX_GET_FILE_SENDER_INFO)
		GetProcAddress(s_hLibrary, "EUCtxGetFileSenderInfo");
	s_Iface.CtxGetRecipientsCount = (PEU_CTX_GET_RECIPIENTS_COUNT)
		GetProcAddress(s_hLibrary, "EUCtxGetRecipientsCount");
	s_Iface.CtxGetFileRecipientsCount = 
		(PEU_CTX_GET_FILE_RECIPIENTS_COUNT)
		GetProcAddress(s_hLibrary, "EUCtxGetFileRecipientsCount");
	s_Iface.CtxGetRecipientInfo = (PEU_CTX_GET_RECIPIENT_INFO)
		GetProcAddress(s_hLibrary, "EUCtxGetRecipientInfo");
	s_Iface.CtxGetFileRecipientInfo = 
		(PEU_CTX_GET_FILE_RECIPIENT_INFO)
		GetProcAddress(s_hLibrary, "EUCtxGetFileRecipientInfo");
	s_Iface.CtxEnvelopAppendData = (PEU_CTX_ENVELOP_APPEND_DATA)
		GetProcAddress(s_hLibrary, "EUCtxEnvelopAppendData");
	s_Iface.CtxEnvelopAppendFile = (PEU_CTX_ENVELOP_APPEND_FILE)
		GetProcAddress(s_hLibrary, "EUCtxEnvelopAppendFile");

	s_Iface.EnumJKSPrivateKeys = (PEU_ENUM_JKS_PRIVATE_KEYS)
		GetProcAddress(s_hLibrary, "EUEnumJKSPrivateKeys");
	s_Iface.EnumJKSPrivateKeysFile = (PEU_ENUM_JKS_PRIVATE_KEYS_FILE)
		GetProcAddress(s_hLibrary, "EUEnumJKSPrivateKeysFile");
	s_Iface.FreeCertificatesArray = (PEU_FREE_CERTIFICATES_ARRAY)
		GetProcAddress(s_hLibrary, "EUFreeCertificatesArray");
	s_Iface.GetJKSPrivateKey = (PEU_GET_JKS_PRIVATE_KEY)
		GetProcAddress(s_hLibrary, "EUGetJKSPrivateKey");
	s_Iface.GetJKSPrivateKeyFile = (PEU_GET_JKS_PRIVATE_KEY_FILE)
		GetProcAddress(s_hLibrary, "EUGetJKSPrivateKeyFile");

	s_Iface.CtxGetDataFromSignedData = (PEU_CTX_GET_DATA_FROM_SIGNED_DATA)
		GetProcAddress(s_hLibrary, "EUCtxGetDataFromSignedData");
	s_Iface.CtxGetDataFromSignedFile = (PEU_CTX_GET_DATA_FROM_SIGNED_FILE)
		GetProcAddress(s_hLibrary, "EUCtxGetDataFromSignedFile");

	s_Iface.SetSettingsRegPath = (PEU_SET_SETTINGS_REG_PATH)
		GetProcAddress(s_hLibrary, "EUSetSettingsRegPath");

	s_Iface.CtxIsDataInSignedDataAvailable = (PEU_CTX_IS_DATA_IN_SIGNED_DATA_AVAILABLE)
		GetProcAddress(s_hLibrary, "EUCtxIsDataInSignedDataAvailable");
	s_Iface.CtxIsDataInSignedFileAvailable = (PEU_CTX_IS_DATA_IN_SIGNED_FILE_AVAILABLE)
		GetProcAddress(s_hLibrary, "EUCtxIsDataInSignedFileAvailable");

	s_Iface.GetCertificateFromSignedData = (PEU_GET_CERTIFICATE_FROM_SIGNED_DATA)
		GetProcAddress(s_hLibrary, "EUGetCertificateFromSignedData");
	s_Iface.GetCertificateFromSignedFile = (PEU_GET_CERTIFICATE_FROM_SIGNED_FILE)
		GetProcAddress(s_hLibrary, "EUGetCertificateFromSignedFile");

	s_Iface.IsDataInSignedDataAvailable = (PEU_IS_DATA_IN_SIGNED_DATA_AVAILABLE)
		GetProcAddress(s_hLibrary, "EUIsDataInSignedDataAvailable");
	s_Iface.IsDataInSignedFileAvailable = (PEU_IS_DATA_IN_SIGNED_FILE_AVAILABLE)
		GetProcAddress(s_hLibrary, "EUIsDataInSignedFileAvailable");
	s_Iface.GetDataFromSignedData = (PEU_GET_DATA_FROM_SIGNED_DATA)
		GetProcAddress(s_hLibrary, "EUGetDataFromSignedData");
	s_Iface.GetDataFromSignedFile = (PEU_GET_DATA_FROM_SIGNED_FILE)
		GetProcAddress(s_hLibrary, "EUGetDataFromSignedFile");

	s_Iface.GetCertificatesFromLDAPByEDRPOUCode = 
		(PEU_GET_CERTIFICATES_FROM_LDAP_BY_EDRPOU_CODE)
		GetProcAddress(s_hLibrary, "EUGetCertificatesFromLDAPByEDRPOUCode");

	s_Iface.ProtectDataByPassword = (PEU_PROTECT_DATA_BY_PASSWORD)
		GetProcAddress(s_hLibrary, "EUProtectDataByPassword");
	s_Iface.UnprotectDataByPassword = (PEU_UNPROTECT_DATA_BY_PASSWORD)
		GetProcAddress(s_hLibrary, "EUUnprotectDataByPassword");

	s_Iface.FreeTimeInfo = (PEU_FREE_TIME_INFO)
		GetProcAddress(s_hLibrary, "EUFreeTimeInfo");
	s_Iface.GetSignTimeInfo = (PEU_GET_SIGN_TIME_INFO)
		GetProcAddress(s_hLibrary, "EUGetSignTimeInfo");
	s_Iface.GetFileSignTimeInfo = (PEU_GET_FILE_SIGN_TIME_INFO)
		GetProcAddress(s_hLibrary, "EUGetFileSignTimeInfo");

	s_Iface.VerifyHashOnTime = (PEU_VERIFY_HASH_ON_TIME)
		GetProcAddress(s_hLibrary, "EUVerifyHashOnTime");
	s_Iface.VerifyDataOnTime = (PEU_VERIFY_DATA_ON_TIME)
		GetProcAddress(s_hLibrary, "EUVerifyDataOnTime");
	s_Iface.VerifyDataInternalOnTime = (PEU_VERIFY_DATA_INTERNAL_ON_TIME)
		GetProcAddress(s_hLibrary, "EUVerifyDataInternalOnTime");
	s_Iface.VerifyDataOnTimeBegin = (PEU_VERIFY_DATA_ON_TIME_BEGIN)
		GetProcAddress(s_hLibrary, "EUVerifyDataOnTimeBegin");
	s_Iface.VerifyFileOnTime = (PEU_VERIFY_FILE_ON_TIME)
		GetProcAddress(s_hLibrary, "EUVerifyFileOnTime");

	s_Iface.VerifyHashOnTimeEx = (PEU_VERIFY_HASH_ON_TIME_EX)
		GetProcAddress(s_hLibrary, "EUVerifyHashOnTimeEx");
	s_Iface.VerifyDataOnTimeEx = (PEU_VERIFY_DATA_ON_TIME_EX)
		GetProcAddress(s_hLibrary, "EUVerifyDataOnTimeEx");
	s_Iface.VerifyDataInternalOnTimeEx = (PEU_VERIFY_DATA_INTERNAL_ON_TIME_EX)
		GetProcAddress(s_hLibrary, "EUVerifyDataInternalOnTimeEx");
	s_Iface.VerifyDataOnTimeBeginEx = (PEU_VERIFY_DATA_ON_TIME_BEGIN_EX)
		GetProcAddress(s_hLibrary, "EUVerifyDataOnTimeBeginEx");
	s_Iface.VerifyFileOnTimeEx = (PEU_VERIFY_FILE_ON_TIME_EX)
		GetProcAddress(s_hLibrary, "EUVerifyFileOnTimeEx");

	s_Iface.CtxEnumPrivateKeyInfo = (PEU_CTX_ENUM_PRIVATE_KEY_INFO)
		GetProcAddress(s_hLibrary, "EUCtxEnumPrivateKeyInfo");
	s_Iface.CtxExportPrivateKeyContainer = 
		(PEU_CTX_EXPORT_PRIVATE_KEY_CONTAINER)
		GetProcAddress(s_hLibrary, "EUCtxExportPrivateKeyContainer");
	s_Iface.CtxExportPrivateKeyPFXContainer = 
		(PEU_CTX_EXPORT_PRIVATE_KEY_PFX_CONTAINER)
		GetProcAddress(s_hLibrary, "EUCtxExportPrivateKeyPFXContainer");
	s_Iface.CtxExportPrivateKeyContainerFile = 
		(PEU_CTX_EXPORT_PRIVATE_KEY_CONTAINER_FILE)
		GetProcAddress(s_hLibrary, "EUCtxExportPrivateKeyContainerFile");
	s_Iface.CtxExportPrivateKeyPFXContainerFile = 
		(PEU_CTX_EXPORT_PRIVATE_KEY_PFX_CONTAINER_FILE)
		GetProcAddress(s_hLibrary, "EUCtxExportPrivateKeyPFXContainerFile");
	s_Iface.CtxGetCertificateFromPrivateKey = 
		(PEU_CTX_GET_CERTIFICATE_FROM_PRIVATE_KEY)
		GetProcAddress(s_hLibrary, "EUCtxGetCertificateFromPrivateKey");

	s_Iface.RawEnvelopData = (PEU_RAW_ENVELOP_DATA)
		GetProcAddress(s_hLibrary, "EURawEnvelopData");
	s_Iface.RawDevelopData = (PEU_RAW_DEVELOP_DATA)
		GetProcAddress(s_hLibrary, "EURawDevelopData");

	s_Iface.RawVerifyDataEx = (PEU_RAW_VERIFY_DATA_EX)
		GetProcAddress(s_hLibrary, "EURawVerifyDataEx");

	s_Iface.EnvelopDataRSAEx = (PEU_ENVELOP_DATA_RSA_EX)
		GetProcAddress(s_hLibrary, "EUEnvelopDataRSAEx");
	s_Iface.EnvelopDataRSA = (PEU_ENVELOP_DATA_RSA)
		GetProcAddress(s_hLibrary, "EUEnvelopDataRSA");
	s_Iface.EnvelopFileRSAEx = (PEU_ENVELOP_FILE_RSA_EX)
		GetProcAddress(s_hLibrary, "EUEnvelopFileRSAEx");
	s_Iface.EnvelopFileRSA = (PEU_ENVELOP_FILE_RSA)
		GetProcAddress(s_hLibrary, "EUEnvelopFileRSA");
	s_Iface.GetReceiversCertificatesRSA =
		(PEU_GET_RECEIVERS_CERTIFICATES_RSA)
		GetProcAddress(s_hLibrary, "EUGetReceiversCertificatesRSA");
	s_Iface.EnvelopDataToRecipientsRSA =
		(PEU_ENVELOP_DATA_TO_RECIPIENTS_RSA)
		GetProcAddress(s_hLibrary, "EUEnvelopDataToRecipientsRSA");
	s_Iface.EnvelopFileToRecipientsRSA =
		(PEU_ENVELOP_FILE_TO_RECIPIENTS_RSA)
		GetProcAddress(s_hLibrary, "EUEnvelopFileToRecipientsRSA");

	s_Iface.RemoveSign = (PEU_REMOVE_SIGN)
		GetProcAddress(s_hLibrary, "EURemoveSign");
	s_Iface.RemoveSignFile = (PEU_REMOVE_SIGN_FILE)
		GetProcAddress(s_hLibrary, "EURemoveSignFile");

	s_Iface.DevCtxEnum = (PEU_DEV_CTX_ENUM)
		GetProcAddress(s_hLibrary, "EUDevCtxEnum");
	s_Iface.DevCtxOpen = (PEU_DEV_CTX_OPEN)
		GetProcAddress(s_hLibrary, "EUDevCtxOpen");
	s_Iface.DevCtxEnumVirtual = (PEU_DEV_CTX_ENUM_VIRTUAL)
		GetProcAddress(s_hLibrary, "EUDevCtxEnumVirtual");
	s_Iface.DevCtxOpenVirtual =
		(PEU_DEV_CTX_OPEN_VIRTUAL)
		GetProcAddress(s_hLibrary, "EUDevCtxOpenVirtual");
	s_Iface.DevCtxClose = (PEU_DEV_CTX_CLOSE)
		GetProcAddress(s_hLibrary, "EUDevCtxClose");
	s_Iface.DevCtxBeginPersonalization =
		(PEU_DEV_CTX_BEGIN_PERSONALIZATION)
		GetProcAddress(s_hLibrary, "EUDevCtxBeginPersonalization");
	s_Iface.DevCtxContinuePersonalization =
		(PEU_DEV_CTX_CONTINUE_PERSONALIZATION)
		GetProcAddress(s_hLibrary, "EUDevCtxContinuePersonalization");
	s_Iface.DevCtxEndPersonalization =
		(PEU_DEV_CTX_END_PERSONALIZATION)
		GetProcAddress(s_hLibrary, "EUDevCtxEndPersonalization");
	s_Iface.DevCtxGetData = (PEU_DEV_CTX_GET_DATA)
		GetProcAddress(s_hLibrary, "EUDevCtxGetData");
	s_Iface.DevCtxUpdateData = (PEU_DEV_CTX_UPDATE_DATA)
		GetProcAddress(s_hLibrary, "EUDevCtxUpdateData");
	s_Iface.DevCtxSignData = (PEU_DEV_CTX_SIGN_DATA)
		GetProcAddress(s_hLibrary, "EUDevCtxSignData");
	s_Iface.DevCtxChangePassword = (PEU_DEV_CTX_CHANGE_PASSWORD)
		GetProcAddress(s_hLibrary, "EUDevCtxChangePassword");
	s_Iface.DevCtxUpdateSystemPublicKey = (PEU_DEV_CTX_UPDATE_SYSTEM_PUBLIC_KEY)
		GetProcAddress(s_hLibrary, "EUDevCtxUpdateSystemPublicKey");
	s_Iface.DevCtxSignSystemPublicKey = (PEU_DEV_CTX_SIGN_SYSTEM_PUBLIC_KEY)
		GetProcAddress(s_hLibrary, "EUDevCtxSignSystemPublicKey");

	s_Iface.GetReceiversCertificatesEx = (PEU_GET_RECEIVERS_CERTIFICATES_EX)
		GetProcAddress(s_hLibrary, "EUGetReceiversCertificatesEx");

	s_Iface.AppendTransportHeader = (PEU_APPEND_TRANSPORT_HEADER)
		GetProcAddress(s_hLibrary, "EUAppendTransportHeader");
	s_Iface.ParseTransportHeader = (PEU_PARSE_TRANSPORT_HEADER)
		GetProcAddress(s_hLibrary, "EUParseTransportHeader");
	s_Iface.AppendCryptoHeader = (PEU_APPEND_CRYPTO_HEADER)
		GetProcAddress(s_hLibrary, "EUAppendCryptoHeader");
	s_Iface.ParseCryptoHeader = (PEU_PARSE_CRYPTO_HEADER)
		GetProcAddress(s_hLibrary, "EUParseCryptoHeader");

	s_Iface.EnvelopDataToRecipientsOffline = 
		(PEU_ENVELOP_DATA_TO_RECIPIENTS_OFFLINE)
		GetProcAddress(s_hLibrary, "EUEnvelopDataToRecipientsOffline");

	s_Iface.DevCtxGeneratePrivateKey = (PEU_DEV_CTX_GENERATE_PRIVATE_KEY)
		GetProcAddress(s_hLibrary, "EUDevCtxGeneratePrivateKey");

	s_Iface.GeneratePRNGSequence = (PEU_GENERATE_PRNG_SEQUENCE)
		GetProcAddress(s_hLibrary, "EUGeneratePRNGSequence");

	s_Iface.SetSettingsFilePathEx = (PEU_SET_SETTINGS_FILE_PATH_EX)
		GetProcAddress(s_hLibrary, "EUSetSettingsFilePathEx");

	s_Iface.ChangeOwnCertificatesStatus = (PEU_CHANGE_OWN_CERTIFICATES_STATUS)
		GetProcAddress(s_hLibrary, "EUChangeOwnCertificatesStatus");
	s_Iface.CtxChangeOwnCertificatesStatus = (PEU_CTX_CHANGE_OWN_CERTIFICATES_STATUS)
		GetProcAddress(s_hLibrary, "EUCtxChangeOwnCertificatesStatus");

	s_Iface.GetCertificatesByNBUCodeAndCMP = 
		(PEU_GET_CERTIFICATES_BY_NBU_CODE_AND_CMP)
		GetProcAddress(s_hLibrary, "EUGetCertificatesByNBUCodeAndCMP");

	s_Iface.EnumCertificatesEx = (PEU_ENUM_CERTIFICATES_EX)
		GetProcAddress(s_hLibrary, "EUEnumCertificatesEx");

	s_Iface.MakeNewCertificate = (PEU_MAKE_NEW_CERTIFICATE)
		GetProcAddress(s_hLibrary, "EUMakeNewCertificate");

	s_Iface.CreateSignerBegin = (PEU_CREATE_SIGNER_BEGIN)
		GetProcAddress(s_hLibrary, "EUCreateSignerBegin");
	s_Iface.CreateSignerEnd = (PEU_CREATE_SIGNER_END)
		GetProcAddress(s_hLibrary, "EUCreateSignerEnd");

	s_Iface.ClientDynamicKeySessionLoad = (PEU_CLIENT_DYNAMIC_KEY_SESSION_LOAD)
		GetProcAddress(s_hLibrary, "EUClientDynamicKeySessionLoad");

	s_Iface.DevCtxOpenIDCard = (PEU_DEV_CTX_OPEN_IDCARD)
		GetProcAddress(s_hLibrary, "EUDevCtxOpenIDCard");
	s_Iface.DevCtxChangeIDCardPasswords = (PEU_DEV_CTX_CHANGE_IDCARD_PASSWORDS)
		GetProcAddress(s_hLibrary, "EUDevCtxChangeIDCardPasswords");
	s_Iface.DevCtxAuthenticateIDCard = (PEU_DEV_CTX_AUTHENTICATE_IDCARD)
		GetProcAddress(s_hLibrary, "EUDevCtxAuthenticateIDCard");
	s_Iface.DevCtxVerifyIDCardData = (PEU_DEV_CTX_VERIFY_IDCARD_DATA)
		GetProcAddress(s_hLibrary, "EUDevCtxVerifyIDCardData");
	s_Iface.DevCtxUpdateIDCardData = (PEU_DEV_CTX_UPDATE_IDCARD_DATA)
		GetProcAddress(s_hLibrary, "EUDevCtxUpdateIDCardData");
	s_Iface.DevCtxEnumIDCardData = (PEU_DEV_CTX_ENUM_IDCARD_DATA)
		GetProcAddress(s_hLibrary, "EUDevCtxEnumIDCardData");

	s_Iface.EnvelopDataWithSettings = (PEU_ENVELOP_DATA_WITH_SETTINGS)
		GetProcAddress(s_hLibrary, "EUEnvelopDataWithSettings");
	s_Iface.EnvelopDataToRecipientsWithSettings = 
		(PEU_ENVELOP_DATA_TO_RECIPIENTS_WITH_SETTINGS)
		GetProcAddress(s_hLibrary, "EUEnvelopDataToRecipientsWithSettings");

	s_Iface.ShowSecureConfirmDialog = (PEU_SHOW_SECURE_CONFIRM_DIALOG)
		GetProcAddress(s_hLibrary, "EUShowSecureConfirmDialog");

	s_Iface.CtxClientSessionCreateStep1 = (PEU_CTX_CLIENT_SESSION_CREATE_STEP1)
		GetProcAddress(s_hLibrary, "EUCtxClientSessionCreateStep1");
	s_Iface.CtxServerSessionCreateStep1 = (PEU_CTX_SERVER_SESSION_CREATE_STEP1)
		GetProcAddress(s_hLibrary, "EUCtxServerSessionCreateStep1");
	s_Iface.CtxSessionLoad = (PEU_CTX_SESSION_LOAD)
		GetProcAddress(s_hLibrary, "EUCtxSessionLoad");
	s_Iface.CtxServerDynamicKeySessionCreate = 
		(PEU_CTX_SERVER_DYNAMIC_KEY_SESSION_CREATE)
		GetProcAddress(s_hLibrary, "EUCtxServerDynamicKeySessionCreate");

	s_Iface.CtxGetSignValue = (PEU_CTX_GET_SIGN_VALUE)
		GetProcAddress(s_hLibrary, "EUCtxGetSignValue");
	s_Iface.AppendSignerUnsignedAttribute =
		(PEU_APPEND_SIGNER_UNSIGNED_ATTRIBUTE)
		GetProcAddress(s_hLibrary, "EUAppendSignerUnsignedAttribute");
	s_Iface.CheckCertificateByOCSP = (PEU_CHECK_CERTIFICATE_BY_OCSP)
		GetProcAddress(s_hLibrary, "EUCheckCertificateByOCSP");
	s_Iface.GetOCSPResponse = (PEU_GET_OCSP_RESPONSE)
		GetProcAddress(s_hLibrary, "EUGetOCSPResponse");
	s_Iface.CheckOCSPResponse = (PEU_CHECK_OCSP_RESPONSE)
		GetProcAddress(s_hLibrary, "EUCheckOCSPResponse");
	s_Iface.CheckCertificateByOCSPResponse =
		(PEU_CHECK_CERTIFICATE_BY_OCSP_RESPONSE)
		GetProcAddress(s_hLibrary, "EUCheckCertificateByOCSPResponse");
	s_Iface.CreateRevocationInfoAttributes =
		(PEU_CREATE_REVOCATION_INFO_ATTRIBUTES)
		GetProcAddress(s_hLibrary, "EUCreateRevocationInfoAttributes");
	s_Iface.GetCertificateChain = (PEU_GET_CERTIFICATE_CHAIN)
		GetProcAddress(s_hLibrary, "EUGetCertificateChain");
	s_Iface.CreateCACertificateInfoAttributes =
		(PEU_CREATE_CA_CERTIFICATE_INFO_ATTRIBUTES)
		GetProcAddress(s_hLibrary, "EUCreateCACertificateInfoAttributes");
	s_Iface.GetTSP = (PEU_GET_TSP) GetProcAddress(s_hLibrary, "EUGetTSP");
	s_Iface.CheckTSP = (PEU_CHECK_TSP) GetProcAddress(s_hLibrary, "EUCheckTSP");
	s_Iface.CtxClientSessionCreate = (PEU_CTX_CLIENT_SESSION_CREATE)
		GetProcAddress(s_hLibrary, "EUCtxClientSessionCreate");
	s_Iface.CtxServerSessionCreate = (PEU_CTX_SERVER_SESSION_CREATE)
		GetProcAddress(s_hLibrary, "EUCtxServerSessionCreate");

	s_Iface.CtxIsNamedPrivateKeyExists = (PEU_CTX_IS_NAMED_PRIVATE_KEY_EXISTS)
		GetProcAddress(s_hLibrary, "EUCtxIsNamedPrivateKeyExists");
	s_Iface.CtxGenerateNamedPrivateKey = (PEU_CTX_GENERATE_NAMED_PRIVATE_KEY)
		GetProcAddress(s_hLibrary, "EUCtxGenerateNamedPrivateKey");
	s_Iface.CtxReadNamedPrivateKey = (PEU_CTX_READ_NAMED_PRIVATE_KEY)
		GetProcAddress(s_hLibrary, "EUCtxReadNamedPrivateKey");
	s_Iface.CtxDestroyNamedPrivateKey = (PEU_CTX_DESTROY_NAMED_PRIVATE_KEY)
		GetProcAddress(s_hLibrary, "EUCtxDestroyNamedPrivateKey");

	s_Iface.CtxChangeNamedPrivateKeyPassword =
		(PEU_CTX_CHANGE_NAMED_PRIVATE_KEY_PASSWORD)
		GetProcAddress(s_hLibrary, "EUCtxChangeNamedPrivateKeyPassword");
	s_Iface.GetTSPByAccessInfo = (PEU_GET_TSP_BY_ACCESS_INFO)
		GetProcAddress(s_hLibrary, "EUGetTSPByAccessInfo");

	s_Iface.GetCertificateByFingerprint =
		(PEU_GET_CERTIFICATE_BY_FINGERPRINT)
		GetProcAddress(s_hLibrary, "EUGetCertificateByFingerprint");
	s_Iface.FreeCertificates = (PEU_FREE_CERTIFICATES)
		GetProcAddress(s_hLibrary, "EUFreeCertificates");
	s_Iface.GetCertificatesByEDRPOUAndDRFOCode =
		(PEU_GET_CERTIFICATES_BY_EDRPOU_AND_DRFO_CODE)
		GetProcAddress(s_hLibrary, "EUGetCertificatesByEDRPOUAndDRFOCode");

	s_Iface.SetOCSPResponseExpireTime =
		(PEU_SET_OCSP_RESPONSE_EXPIRE_TIME)
		GetProcAddress(s_hLibrary, "EUSetOCSPResponseExpireTime");
	s_Iface.GetOCSPResponseByAccessInfo =
		(PEU_GET_OCSP_RESPONSE_BY_ACCESS_INFO)
		GetProcAddress(s_hLibrary, "EUGetOCSPResponseByAccessInfo");

	s_Iface.DeleteCertificate = (PEU_DELETE_CERTIFICATE)
		GetProcAddress(s_hLibrary, "EUDeleteCertificate");

	s_Iface.SetKeyMediaUserPassword = (PEU_SET_KEY_MEDIA_USER_PASSWORD)
		GetProcAddress(s_hLibrary, "EUSetKeyMediaUserPassword");

	s_Iface.CheckDataStruct = (PEU_CHECK_DATA_STRUCT)
		GetProcAddress(s_hLibrary, "EUCheckDataStruct");
	s_Iface.CheckFileStruct = (PEU_CHECK_FILE_STRUCT)
		GetProcAddress(s_hLibrary, "EUCheckFileStruct");

	s_Iface.DevCtxEnumIDCardDataChangeDate = (PEU_DEV_CTX_ENUM_IDCARD_DATA_CHANGE_DATE)
		GetProcAddress(s_hLibrary, "EUDevCtxEnumIDCardDataChangeDate");

	s_Iface.GetDataHashFromSignedData = (PEU_GET_DATA_HASH_FROM_SIGNED_DATA)
		GetProcAddress(s_hLibrary, "EUGetDataHashFromSignedData");
	s_Iface.GetDataHashFromSignedFile = (PEU_GET_DATA_HASH_FROM_SIGNED_FILE)
		GetProcAddress(s_hLibrary, "EUGetDataHashFromSignedFile");

	s_Iface.DevCtxVerifyIDCardSecurityObjectDocument =
		(PEU_DEV_CTX_VERIFY_IDCARD_SECURITY_OBJECT_DOCUMENT)
		GetProcAddress(s_hLibrary, "EUDevCtxVerifyIDCardSecurityObjectDocument");

	s_Iface.VerifyDataWithParams = (PEU_VERIFY_DATA_WITH_PARAMS)
		GetProcAddress(s_hLibrary, "EUVerifyDataWithParams");
	s_Iface.VerifyDataInternalWithParams = (PEU_VERIFY_DATA_INTERNAL_WITH_PARAMS)
		GetProcAddress(s_hLibrary, "EUVerifyDataInternalWithParams");

	s_Iface.CtxGetNamedPrivateKeyInfo = (PEU_CTX_GET_NAMED_PRIVATE_KEY_INFO)
		GetProcAddress(s_hLibrary, "EUCtxGetNamedPrivateKeyInfo");

	s_Iface.GetCertificateByKeyInfoEx = (PEU_GET_CERTIFICATE_BY_KEY_INFO_EX)
		GetProcAddress(s_hLibrary, "EUGetCertificateByKeyInfoEx");

	s_Iface.ShowCertificate = (PEU_SHOW_CERTIFICATE)
		GetProcAddress(s_hLibrary, "EUShowCertificate");

	s_Iface.AppendFileTransportHeader = (PEU_APPEND_FILE_TRANSPORT_HEADER)
		GetProcAddress(s_hLibrary, "EUAppendFileTransportHeader");
	s_Iface.ParseFileTransportHeader = (PEU_PARSE_FILE_TRANSPORT_HEADER)
		GetProcAddress(s_hLibrary, "EUParseFileTransportHeader");
	s_Iface.AppendFileCryptoHeader = (PEU_APPEND_FILE_CRYPTO_HEADER)
		GetProcAddress(s_hLibrary, "EUAppendFileCryptoHeader");
	s_Iface.ParseFileCryptoHeader = (PEU_PARSE_FILE_CRYPTO_HEADER)
		GetProcAddress(s_hLibrary, "EUParseFileCryptoHeader");

	s_Iface.FreeKeyMediaDeviceInfo = (PEU_FREE_KEY_MEDIA_DEVICE_INFO)
		GetProcAddress(s_hLibrary, "EUFreeKeyMediaDeviceInfo");
	s_Iface.GetKeyMediaDeviceInfo = (PEU_GET_KEY_MEDIA_DEVICE_INFO)
		GetProcAddress(s_hLibrary, "EUGetKeyMediaDeviceInfo");
	s_Iface.CtxEnumNamedPrivateKeys = (PEU_CTX_ENUM_NAMED_PRIVATE_KEYS)
		GetProcAddress(s_hLibrary, "EUCtxEnumNamedPrivateKeys");

	s_Iface.DevCtxInternalAuthenticateIDCard = (PEU_DEV_CTX_INTERNAL_AUTHENTICATE_IDCARD)
		GetProcAddress(s_hLibrary, "EUDevCtxInternalAuthenticateIDCard");
#else // PC_STATIC_LIBS
	s_Iface.Initialize = EUInitialize;
	s_Iface.IsInitialized = EUIsInitialized;
	s_Iface.Finalize = EUFinalize;

	s_Iface.SetSettings = EUSetSettings;

	s_Iface.ShowCertificates = EUShowCertificates;
	s_Iface.ShowCRLs = EUShowCRLs;

	s_Iface.GetPrivateKeyMedia = EUGetPrivateKeyMedia;
	s_Iface.ReadPrivateKey = EUReadPrivateKey;
	s_Iface.IsPrivateKeyReaded = EUIsPrivateKeyReaded;
	s_Iface.ResetPrivateKey = EUResetPrivateKey;
	s_Iface.FreeCertOwnerInfo = EUFreeCertOwnerInfo;

	s_Iface.ShowOwnCertificate = EUShowOwnCertificate;
	s_Iface.ShowSignInfo = EUShowSignInfo;
	s_Iface.FreeSignInfo = EUFreeSignInfo;

	s_Iface.FreeMemory = EUFreeMemory;

	s_Iface.GetErrorDesc = EUGetErrorDesc;

	s_Iface.SignData = EUSignData;
	s_Iface.VerifyData = EUVerifyData;

	s_Iface.SignDataContinue = EUSignDataContinue;
	s_Iface.SignDataEnd = EUSignDataEnd;
	s_Iface.VerifyDataBegin = EUVerifyDataBegin;
	s_Iface.VerifyDataContinue = EUVerifyDataContinue;
	s_Iface.VerifyDataEnd = EUVerifyDataEnd;
	s_Iface.ResetOperation = EUResetOperation;

	s_Iface.SignFile = EUSignFile;
	s_Iface.VerifyFile = EUVerifyFile;

	s_Iface.SignDataInternal = EUSignDataInternal;
	s_Iface.VerifyDataInternal = EUVerifyDataInternal;

	s_Iface.SelectCertInfo = EUSelectCertificateInfo;

	s_Iface.SetUIMode = EUSetUIMode;

	s_Iface.HashData = EUHashData;
	s_Iface.HashDataContinue = EUHashDataContinue;
	s_Iface.HashDataEnd = EUHashDataEnd;
	s_Iface.HashFile = EUHashFile;
	s_Iface.SignHash = EUSignHash;
	s_Iface.VerifyHash = EUVerifyHash;

	s_Iface.EnumKeyMediaTypes = EUEnumKeyMediaTypes;
	s_Iface.EnumKeyMediaDevices = EUEnumKeyMediaDevices;

	s_Iface.GetFileStoreSettings = EUGetFileStoreSettings;
	s_Iface.SetFileStoreSettings = EUSetFileStoreSettings;
	s_Iface.GetProxySettings = EUGetProxySettings;
	s_Iface.SetProxySettings = EUSetProxySettings;
	s_Iface.GetOCSPSettings = EUGetOCSPSettings;
	s_Iface.SetOCSPSettings = EUSetOCSPSettings;
	s_Iface.GetTSPSettings = EUGetTSPSettings;
	s_Iface.SetTSPSettings = EUSetTSPSettings;
	s_Iface.GetLDAPSettings = EUGetLDAPSettings;
	s_Iface.SetLDAPSettings = EUSetLDAPSettings;

	s_Iface.GetCertificatesCount = EUGetCertificatesCount;
	s_Iface.EnumCertificates = EUEnumCertificates;
	s_Iface.GetCRLsCount = EUGetCRLsCount;
	s_Iface.EnumCRLs = EUEnumCRLs;
	s_Iface.FreeCRLInfo = EUFreeCRLInfo;

	s_Iface.GetCertificateInfo = EUGetCertificateInfo;
	s_Iface.FreeCertificateInfo = EUFreeCertificateInfo;
	s_Iface.GetCRLDetailedInfo = EUGetCRLDetailedInfo;
	s_Iface.FreeCRLDetailedInfo = EUFreeCRLDetailedInfo;

	s_Iface.GetCMPSettings = EUGetCMPSettings;
	s_Iface.SetCMPSettings = EUSetCMPSettings;
	s_Iface.DoesNeedSetSettings = EUDoesNeedSetSettings;

	s_Iface.GetPrivateKeyMediaSettings =
		EUGetPrivateKeyMediaSettings;
	s_Iface.SetPrivateKeyMediaSettings =
		EUSetPrivateKeyMediaSettings;

	s_Iface.SelectCMPServer = EUSelectCMPServer;

	s_Iface.RawSignData = EURawSignData;
	s_Iface.RawVerifyData = EURawVerifyData;
	s_Iface.RawSignHash = EURawSignHash;
	s_Iface.RawVerifyHash = EURawVerifyHash;
	s_Iface.RawSignFile = EURawSignFile;
	s_Iface.RawVerifyFile = EURawVerifyFile;

	s_Iface.BASE64Encode = EUBASE64Encode;
	s_Iface.BASE64Decode = EUBASE64Decode;

	s_Iface.EnvelopData = EUEnvelopData;
	s_Iface.DevelopData = EUDevelopData;
	s_Iface.ShowSenderInfo = EUShowSenderInfo;
	s_Iface.FreeSenderInfo = EUFreeSenderInfo;

	s_Iface.ParseCertificate = EUParseCertificate;

	s_Iface.ReadPrivateKeyBinary = EUReadPrivateKeyBinary;
	s_Iface.ReadPrivateKeyFile = EUReadPrivateKeyFile;

	s_Iface.SessionDestroy = EUSessionDestroy;
	s_Iface.ClientSessionCreateStep1 =
		EUClientSessionCreateStep1;
	s_Iface.ServerSessionCreateStep1 =
		EUServerSessionCreateStep1;
	s_Iface.ClientSessionCreateStep2 =
		EUClientSessionCreateStep2;
	s_Iface.ServerSessionCreateStep2 =
		EUServerSessionCreateStep2;
	s_Iface.SessionIsInitialized = EUSessionIsInitialized;
	s_Iface.SessionSave = EUSessionSave;
	s_Iface.SessionLoad = EUSessionLoad;
	s_Iface.SessionCheckCertificates =
		EUSessionCheckCertificates;
	s_Iface.SessionEncrypt = EUSessionEncrypt;
	s_Iface.SessionEncryptContinue = EUSessionEncryptContinue;
	s_Iface.SessionDecrypt = EUSessionDecrypt;
	s_Iface.SessionDecryptContinue = EUSessionDecryptContinue;

	s_Iface.IsSignedData = EUIsSignedData;
	s_Iface.IsEnvelopedData = EUIsEnvelopedData;

	s_Iface.SessionGetPeerCertificateInfo =
		EUSessionGetPeerCertificateInfo;

	s_Iface.SaveCertificate = EUSaveCertificate;
	s_Iface.RefreshFileStore = EURefreshFileStore;

	s_Iface.GetModeSettings = EUGetModeSettings;
	s_Iface.SetModeSettings = EUSetModeSettings;

	s_Iface.CheckCertificate = EUCheckCertificate;

	s_Iface.EnvelopFile = EUEnvelopFile;
	s_Iface.DevelopFile = EUDevelopFile;
	s_Iface.IsSignedFile = EUIsSignedFile;
	s_Iface.IsEnvelopedFile = EUIsEnvelopedFile;

	s_Iface.GetCertificate = EUGetCertificate;
	s_Iface.GetOwnCertificate = EUGetOwnCertificate;

	s_Iface.EnumOwnCertificates = EUEnumOwnCertificates;
	s_Iface.GetCertificateInfoEx = EUGetCertificateInfoEx;
	s_Iface.FreeCertificateInfoEx = EUFreeCertificateInfoEx;

	s_Iface.GetReceiversCertificates = EUGetReceiversCertificates;
	s_Iface.FreeReceiversCertificates = EUFreeReceiversCertificates;

	s_Iface.GeneratePrivateKey = EUGeneratePrivateKey;
	s_Iface.ChangePrivateKeyPassword = EUChangePrivateKeyPassword;
	s_Iface.BackupPrivateKey = EUBackupPrivateKey;
	s_Iface.DestroyPrivateKey = EUDestroyPrivateKey;
	s_Iface.IsHardwareKeyMedia = EUIsHardwareKeyMedia;
	s_Iface.IsPrivateKeyExists = EUIsPrivateKeyExists;

	s_Iface.GetCRInfo = EUGetCRInfo;
	s_Iface.FreeCRInfo = EUFreeCRInfo;

	s_Iface.SaveCertificates = EUSaveCertificates;
	s_Iface.SaveCRL = EUSaveCRL;

	s_Iface.GetCertificateByEMail = EUGetCertificateByEMail;
	s_Iface.GetCertificateByNBUCode =
		EUGetCertificateByNBUCode;

	s_Iface.AppendSign = EUAppendSign;
	s_Iface.AppendSignInternal = EUAppendSignInternal;
	s_Iface.VerifyDataSpecific = EUVerifyDataSpecific;
	s_Iface.VerifyDataInternalSpecific =
		EUVerifyDataInternalSpecific;
	s_Iface.AppendSignBegin = EUAppendSignBegin;
	s_Iface.VerifyDataSpecificBegin =
		EUVerifyDataSpecificBegin;
	s_Iface.AppendSignFile = EUAppendSignFile;
	s_Iface.VerifyFileSpecific = EUVerifyFileSpecific;
	s_Iface.AppendSignHash = EUAppendSignHash;
	s_Iface.VerifyHashSpecific = EUVerifyHashSpecific;
	s_Iface.GetSignsCount = EUGetSignsCount;
	s_Iface.GetSignerInfo = EUGetSignerInfo;
	s_Iface.GetFileSignsCount = EUGetFileSignsCount;
	s_Iface.GetFileSignerInfo = EUGetFileSignerInfo;

	s_Iface.IsAlreadySigned = EUIsAlreadySigned;
	s_Iface.IsFileAlreadySigned = EUIsFileAlreadySigned;

	s_Iface.HashDataWithParams = EUHashDataWithParams;
	s_Iface.HashDataBeginWithParams = EUHashDataBeginWithParams;
	s_Iface.HashFileWithParams = EUHashFileWithParams;

	s_Iface.EnvelopDataEx = EUEnvelopDataEx;

	s_Iface.SetSettingsFilePath = EUSetSettingsFilePath;

	s_Iface.SetKeyMediaPassword = EUSetKeyMediaPassword;
	s_Iface.GeneratePrivateKeyEx = EUGeneratePrivateKeyEx;

	s_Iface.GetErrorLangDesc = EUGetErrorLangDesc;

	s_Iface.EnvelopFileEx = EUEnvelopFileEx;

	s_Iface.IsCertificates = EUIsCertificates;
	s_Iface.IsCertificatesFile = EUIsCertificatesFile;

	s_Iface.EnumCertificatesByOCode = EUEnumCertificatesByOCode;
	s_Iface.GetCertificatesByOCode = EUGetCertificatesByOCode;

	s_Iface.SetPrivateKeyMediaSettingsProtected =
		EUSetPrivateKeyMediaSettingsProtected;

	s_Iface.EnvelopDataToRecipients = EUEnvelopDataToRecipients;
	s_Iface.EnvelopFileToRecipients = EUEnvelopFileToRecipients;
	
	s_Iface.EnvelopDataExWithDynamicKey =
		EUEnvelopDataExWithDynamicKey;
	s_Iface.EnvelopDataToRecipientsWithDynamicKey =
		EUEnvelopDataToRecipientsWithDynamicKey;
	s_Iface.EnvelopFileExWithDynamicKey =
		EUEnvelopFileExWithDynamicKey;
	s_Iface.EnvelopFileToRecipientsWithDynamicKey =
		EUEnvelopFileToRecipientsWithDynamicKey;

	s_Iface.SavePrivateKey = EUSavePrivateKey;
	s_Iface.LoadPrivateKey = EULoadPrivateKey;
	s_Iface.ChangeSoftwarePrivateKeyPassword =
		EUChangeSoftwarePrivateKeyPassword;

	s_Iface.HashDataBeginWithParamsCtx =
		EUHashDataBeginWithParamsCtx;
	s_Iface.HashDataContinueCtx = EUHashDataContinueCtx;
	s_Iface.HashDataEndCtx = EUHashDataEndCtx;

	s_Iface.GetCertificateByKeyInfo = EUGetCertificateByKeyInfo;

	s_Iface.SavePrivateKeyEx = EUSavePrivateKeyEx;
	s_Iface.LoadPrivateKeyEx = EULoadPrivateKeyEx;

	s_Iface.CreateEmptySign = EUCreateEmptySign;
	s_Iface.CreateSigner = EUCreateSigner;
	s_Iface.AppendSigner = EUAppendSigner;

	s_Iface.SetRuntimeParameter = EUSetRuntimeParameter;

	s_Iface.EnvelopDataToRecipientsEx =
		EUEnvelopDataToRecipientsEx;
	s_Iface.EnvelopFileToRecipientsEx =
		EUEnvelopFileToRecipientsEx;
	s_Iface.EnvelopDataToRecipientsWithOCode =
		EUEnvelopDataToRecipientsWithOCode;

	s_Iface.SignDataContinueCtx = EUSignDataContinueCtx;
	s_Iface.SignDataEndCtx = EUSignDataEndCtx;
	s_Iface.VerifyDataBeginCtx = EUVerifyDataBeginCtx;
	s_Iface.VerifyDataContinueCtx = EUVerifyDataContinueCtx;
	s_Iface.VerifyDataEndCtx = EUVerifyDataEndCtx;
	s_Iface.ResetOperationCtx = EUResetOperationCtx;

	s_Iface.SignDataRSA = EUSignDataRSA;
	s_Iface.SignDataRSAContinue = EUSignDataRSAContinue;
	s_Iface.SignDataRSAEnd = EUSignDataRSAEnd;
	s_Iface.SignFileRSA = EUSignFileRSA;
	s_Iface.SignDataRSAContinueCtx = EUSignDataRSAContinueCtx;
	s_Iface.SignDataRSAEndCtx = EUSignDataRSAEndCtx;

	s_Iface.DownloadFileViaHTTP = EUDownloadFileViaHTTP;

	s_Iface.ParseCRL = EUParseCRL;

	s_Iface.IsOldFormatSign = EUIsOldFormatSign;
	s_Iface.IsOldFormatSignFile = EUIsOldFormatSignFile;

	s_Iface.GetPrivateKeyMediaEx = EUGetPrivateKeyMediaEx;

	s_Iface.GetKeyInfo = EUGetKeyInfo;
	s_Iface.GetKeyInfoBinary = EUGetKeyInfoBinary;
	s_Iface.GetKeyInfoFile = EUGetKeyInfoFile;
	s_Iface.GetCertificatesByKeyInfo = EUGetCertificatesByKeyInfo;

	s_Iface.EnvelopAppendData = EUEnvelopAppendData;
	s_Iface.EnvelopAppendFile = EUEnvelopAppendFile;
	s_Iface.EnvelopAppendDataEx = EUEnvelopAppendDataEx;
	s_Iface.EnvelopAppendFileEx = EUEnvelopAppendFileEx;

	s_Iface.GetStorageParameter = EUGetStorageParameter;
	s_Iface.SetStorageParameter = EUSetStorageParameter;

	s_Iface.DevelopDataEx = EUDevelopDataEx;
	s_Iface.DevelopFileEx = EUDevelopFileEx;

	s_Iface.GetOCSPAccessInfoModeSettings =
		EUGetOCSPAccessInfoModeSettings;
	s_Iface.SetOCSPAccessInfoModeSettings =
		EUSetOCSPAccessInfoModeSettings;

	s_Iface.EnumOCSPAccessInfoSettings = 
		EUEnumOCSPAccessInfoSettings;
	s_Iface.GetOCSPAccessInfoSettings = 
		EUGetOCSPAccessInfoSettings;
	s_Iface.SetOCSPAccessInfoSettings = 
		EUSetOCSPAccessInfoSettings;
	s_Iface.DeleteOCSPAccessInfoSettings = 
		EUDeleteOCSPAccessInfoSettings;

	s_Iface.CheckCertificateByIssuerAndSerial =
		EUCheckCertificateByIssuerAndSerial;

	s_Iface.ParseCertificateEx = EUParseCertificateEx;

	s_Iface.CheckCertificateByIssuerAndSerialEx =
		EUCheckCertificateByIssuerAndSerialEx;

	s_Iface.ClientDynamicKeySessionCreate =
		EUClientDynamicKeySessionCreate;
	s_Iface.ServerDynamicKeySessionCreate =
		EUServerDynamicKeySessionCreate;

	s_Iface.GetSenderInfo = EUGetSenderInfo;
	s_Iface.GetFileSenderInfo = EUGetFileSenderInfo;

	s_Iface.SCClientIsRunning =
		EUSCClientIsRunning;
	s_Iface.SCClientStart =
		EUSCClientStart;
	s_Iface.SCClientStop =
		EUSCClientStop;
	s_Iface.SCClientAddGate =
		EUSCClientAddGate;
	s_Iface.SCClientRemoveGate =
		EUSCClientRemoveGate;
	s_Iface.SCClientGetStatistic =
		EUSCClientGetStatistic;
	s_Iface.SCClientFreeStatistic =
		EUSCClientFreeStatistic;

	s_Iface.GetRecipientsCount =
		EUGetRecipientsCount;
	s_Iface.GetFileRecipientsCount =
		EUGetFileRecipientsCount;
	s_Iface.GetRecipientInfo =
		EUGetRecipientInfo;
	s_Iface.GetFileRecipientInfo =
		EUGetFileRecipientInfo;

	s_Iface.CtxCreate =
		EUCtxCreate;
	s_Iface.CtxFree =
		EUCtxFree;
	s_Iface.CtxSetParameter =
		EUCtxSetParameter;
	s_Iface.CtxReadPrivateKey =
		EUCtxReadPrivateKey;
	s_Iface.CtxReadPrivateKeyBinary =
		EUCtxReadPrivateKeyBinary;
	s_Iface.CtxReadPrivateKeyFile =
		EUCtxReadPrivateKeyFile;
	s_Iface.CtxFreePrivateKey =
		EUCtxFreePrivateKey;

	s_Iface.CtxDevelopData = EUCtxDevelopData;
	s_Iface.CtxDevelopFile = EUCtxDevelopFile;

	s_Iface.CtxFreeMemory = EUCtxFreeMemory;
	s_Iface.CtxFreeCertOwnerInfo = EUCtxFreeCertOwnerInfo;
	s_Iface.CtxFreeCertificateInfoEx = 
		EUCtxFreeCertificateInfoEx;
	s_Iface.CtxFreeSignInfo = EUCtxFreeSignInfo;
	s_Iface.CtxFreeSenderInfo = EUCtxFreeSenderInfo;

	s_Iface.CtxGetOwnCertificate = EUCtxGetOwnCertificate;
	s_Iface.CtxEnumOwnCertificates = EUCtxEnumOwnCertificates;

	s_Iface.CtxHashData = EUCtxHashData;
	s_Iface.CtxHashFile = EUCtxHashFile;
	s_Iface.CtxHashDataBegin = EUCtxHashDataBegin;
	s_Iface.CtxHashDataContinue = EUCtxHashDataContinue;
	s_Iface.CtxHashDataEnd = EUCtxHashDataEnd;
	s_Iface.CtxFreeHash = EUCtxFreeHash;

	s_Iface.CtxSignHash = EUCtxSignHash;
	s_Iface.CtxSignHashValue = EUCtxSignHashValue;
	s_Iface.CtxSignData = EUCtxSignData;
	s_Iface.CtxSignFile = EUCtxSignFile;
	s_Iface.CtxIsAlreadySigned = EUCtxIsAlreadySigned;
	s_Iface.CtxIsFileAlreadySigned = 
		EUCtxIsFileAlreadySigned;
	s_Iface.CtxAppendSignHash = EUCtxAppendSignHash;
	s_Iface.CtxAppendSignHashValue = 
		EUCtxAppendSignHashValue;
	s_Iface.CtxAppendSign = EUCtxAppendSign;
	s_Iface.CtxAppendSignFile = EUCtxAppendSignFile;
	s_Iface.CtxCreateEmptySign = EUCtxCreateEmptySign;
	s_Iface.CtxCreateSigner = EUCtxCreateSigner;
	s_Iface.CtxAppendSigner = EUCtxAppendSigner;
	s_Iface.CtxGetSignsCount = EUCtxGetSignsCount;
	s_Iface.CtxGetFileSignsCount = EUCtxGetFileSignsCount;
	s_Iface.CtxGetSignerInfo = EUCtxGetSignerInfo;
	s_Iface.CtxGetFileSignerInfo = EUCtxGetFileSignerInfo;
	s_Iface.CtxVerifyHash = EUCtxVerifyHash;
	s_Iface.CtxVerifyHashValue = EUCtxVerifyHashValue;
	s_Iface.CtxVerifyData = EUCtxVerifyData;
	s_Iface.CtxVerifyDataInternal = EUCtxVerifyDataInternal;
	s_Iface.CtxVerifyFile = EUCtxVerifyFile;

	s_Iface.CtxEnvelopData = EUCtxEnvelopData;
	s_Iface.CtxEnvelopFile = EUCtxEnvelopFile;
	s_Iface.CtxGetSenderInfo = EUCtxGetSenderInfo;
	s_Iface.CtxGetFileSenderInfo = EUCtxGetFileSenderInfo;
	s_Iface.CtxGetRecipientsCount = EUCtxGetRecipientsCount;
	s_Iface.CtxGetFileRecipientsCount = 
		EUCtxGetFileRecipientsCount;
	s_Iface.CtxGetRecipientInfo = EUCtxGetRecipientInfo;
	s_Iface.CtxGetFileRecipientInfo = 
		EUCtxGetFileRecipientInfo;
	s_Iface.CtxEnvelopAppendData = EUCtxEnvelopAppendData;
	s_Iface.CtxEnvelopAppendFile = EUCtxEnvelopAppendFile;

	s_Iface.EnumJKSPrivateKeys = EUEnumJKSPrivateKeys;
	s_Iface.EnumJKSPrivateKeysFile = EUEnumJKSPrivateKeysFile;
	s_Iface.FreeCertificatesArray = EUFreeCertificatesArray;
	s_Iface.GetJKSPrivateKey = EUGetJKSPrivateKey;
	s_Iface.GetJKSPrivateKeyFile = EUGetJKSPrivateKeyFile;

	s_Iface.CtxGetDataFromSignedData = EUCtxGetDataFromSignedData;
	s_Iface.CtxGetDataFromSignedFile = EUCtxGetDataFromSignedFile;

	s_Iface.SetSettingsRegPath = EUSetSettingsRegPath;

	s_Iface.CtxIsDataInSignedDataAvailable = 
		EUCtxIsDataInSignedDataAvailable;
	s_Iface.CtxIsDataInSignedFileAvailable =
		EUCtxIsDataInSignedFileAvailable;

	s_Iface.GetCertificateFromSignedData = 
		EUGetCertificateFromSignedData;
	s_Iface.GetCertificateFromSignedFile = 
		EUGetCertificateFromSignedFile;

	s_Iface.IsDataInSignedDataAvailable = 
		EUIsDataInSignedDataAvailable;
	s_Iface.IsDataInSignedFileAvailable = 
		EUIsDataInSignedFileAvailable;
	s_Iface.GetDataFromSignedData = EUGetDataFromSignedData;
	s_Iface.GetDataFromSignedFile = EUGetDataFromSignedFile;

	s_Iface.GetCertificatesFromLDAPByEDRPOUCode = 
		EUGetCertificatesFromLDAPByEDRPOUCode;

	s_Iface.ProtectDataByPassword = EUProtectDataByPassword;
	s_Iface.UnprotectDataByPassword = EUUnprotectDataByPassword;

	s_Iface.FreeTimeInfo = EUFreeTimeInfo;
	s_Iface.GetSignTimeInfo = EUGetSignTimeInfo;
	s_Iface.GetFileSignTimeInfo = EUGetFileSignTimeInfo;

	s_Iface.VerifyHashOnTime = EUVerifyHashOnTime;
	s_Iface.VerifyDataOnTime = EUVerifyDataOnTime;
	s_Iface.VerifyDataInternalOnTime = EUVerifyDataInternalOnTime;
	s_Iface.VerifyDataOnTimeBegin = EUVerifyDataOnTimeBegin;
	s_Iface.VerifyFileOnTime = EUVerifyFileOnTime;

	s_Iface.VerifyHashOnTimeEx = EUVerifyHashOnTimeEx;
	s_Iface.VerifyDataOnTimeEx = EUVerifyDataOnTimeEx;
	s_Iface.VerifyDataInternalOnTimeEx = 
		EUVerifyDataInternalOnTimeEx;
	s_Iface.VerifyDataOnTimeBeginEx = EUVerifyDataOnTimeBeginEx;
	s_Iface.VerifyFileOnTimeEx = EUVerifyFileOnTimeEx;

	s_Iface.CtxEnumPrivateKeyInfo = EUCtxEnumPrivateKeyInfo;
	s_Iface.CtxExportPrivateKeyContainer = 
		EUCtxExportPrivateKeyContainer;
	s_Iface.CtxExportPrivateKeyPFXContainer = 
		EUCtxExportPrivateKeyPFXContainer;
	s_Iface.CtxExportPrivateKeyContainerFile = 
		EUCtxExportPrivateKeyContainerFile;
	s_Iface.CtxExportPrivateKeyPFXContainerFile = 
		EUCtxExportPrivateKeyPFXContainerFile;
	s_Iface.CtxGetCertificateFromPrivateKey = 
		EUCtxGetCertificateFromPrivateKey;

	s_Iface.RawEnvelopData = EURawEnvelopData;
	s_Iface.RawDevelopData = EURawDevelopData;

	s_Iface.RawVerifyDataEx = EURawVerifyDataEx;

	s_Iface.EnvelopDataRSAEx = EUEnvelopDataRSAEx;
	s_Iface.EnvelopDataRSA = EUEnvelopDataRSA;
	s_Iface.EnvelopFileRSAEx = EUEnvelopFileRSAEx;
	s_Iface.EnvelopFileRSA = EUEnvelopFileRSA;
	s_Iface.GetReceiversCertificatesRSA = 
		EUGetReceiversCertificatesRSA;
	s_Iface.EnvelopDataToRecipientsRSA = 
		EUEnvelopDataToRecipientsRSA;
	s_Iface.EnvelopFileToRecipientsRSA = 
		EUEnvelopFileToRecipientsRSA;

	s_Iface.RemoveSign = EURemoveSign;
	s_Iface.RemoveSignFile = EURemoveSignFile;

	s_Iface.DevCtxEnum = EUDevCtxEnum;
	s_Iface.DevCtxOpen = EUDevCtxOpen;
	s_Iface.DevCtxEnumVirtual =
		EUDevCtxEnumVirtual;
	s_Iface.DevCtxOpenVirtual =
		EUDevCtxOpenVirtual;
	s_Iface.DevCtxClose = EUDevCtxClose;
	s_Iface.DevCtxBeginPersonalization =
		EUDevCtxBeginPersonalization;
	s_Iface.DevCtxContinuePersonalization =
		EUDevCtxContinuePersonalization;
	s_Iface.DevCtxEndPersonalization =
		EUDevCtxEndPersonalization;
	s_Iface.DevCtxGetData = EUDevCtxGetData;
	s_Iface.DevCtxUpdateData = EUDevCtxUpdateData;
	s_Iface.DevCtxSignData = EUDevCtxSignData;
	s_Iface.DevCtxChangePassword = EUDevCtxChangePassword;
	s_Iface.DevCtxUpdateSystemPublicKey =
		EUDevCtxUpdateSystemPublicKey;
	s_Iface.DevCtxSignSystemPublicKey =
		EUDevCtxSignSystemPublicKey;

	s_Iface.GetReceiversCertificatesEx = 
		EUGetReceiversCertificatesEx;

	s_Iface.AppendTransportHeader = EUAppendTransportHeader;
	s_Iface.ParseTransportHeader = EUParseTransportHeader;
	s_Iface.AppendCryptoHeader = EUAppendCryptoHeader;
	s_Iface.ParseCryptoHeader = EUParseCryptoHeader;

	s_Iface.EnvelopDataToRecipientsOffline = 
		EUEnvelopDataToRecipientsOffline;

	s_Iface.DevCtxGeneratePrivateKey =
		EUDevCtxGeneratePrivateKey;

	s_Iface.GeneratePRNGSequence = EUGeneratePRNGSequence;

	s_Iface.SetSettingsFilePathEx = EUSetSettingsFilePathEx;

	s_Iface.ChangeOwnCertificatesStatus = EUChangeOwnCertificatesStatus;
	s_Iface.CtxChangeOwnCertificatesStatus = EUCtxChangeOwnCertificatesStatus;

	s_Iface.GetCertificatesByNBUCodeAndCMP = 
		EUGetCertificatesByNBUCodeAndCMP;

	s_Iface.EnumCertificatesEx = EUEnumCertificatesEx;

	s_Iface.MakeNewCertificate = EUMakeNewCertificate;

	s_Iface.CreateSignerBegin = EUCreateSignerBegin;
	s_Iface.CreateSignerEnd = EUCreateSignerEnd;

	s_Iface.ClientDynamicKeySessionLoad = EUClientDynamicKeySessionLoad;

	s_Iface.DevCtxOpenIDCard = EUDevCtxOpenIDCard;
	s_Iface.DevCtxChangeIDCardPasswords = EUDevCtxChangeIDCardPasswords;
	s_Iface.DevCtxAuthenticateIDCard = EUDevCtxAuthenticateIDCard;
	s_Iface.DevCtxVerifyIDCardData = EUDevCtxVerifyIDCardData;
	s_Iface.DevCtxUpdateIDCardData = EUDevCtxUpdateIDCardData;
	s_Iface.DevCtxEnumIDCardData = EUDevCtxEnumIDCardData;

	s_Iface.EnvelopDataWithSettings = EUEnvelopDataWithSettings;
	s_Iface.EnvelopDataToRecipientsWithSettings = 
		EUEnvelopDataToRecipientsWithSettings;

	s_Iface.ShowSecureConfirmDialog = EUShowSecureConfirmDialog;

	s_Iface.CtxClientSessionCreateStep1 = EUCtxClientSessionCreateStep1;
	s_Iface.CtxServerSessionCreateStep1 = EUCtxServerSessionCreateStep1;
	s_Iface.CtxSessionLoad = EUCtxSessionLoad;
	s_Iface.CtxServerDynamicKeySessionCreate =
		EUCtxServerDynamicKeySessionCreate;

	s_Iface.CtxGetSignValue = EUCtxGetSignValue;
	s_Iface.AppendSignerUnsignedAttribute =
		EUAppendSignerUnsignedAttribute;
	s_Iface.CheckCertificateByOCSP = EUCheckCertificateByOCSP;
	s_Iface.GetOCSPResponse = EUGetOCSPResponse;
	s_Iface.CheckOCSPResponse = EUCheckOCSPResponse;
	s_Iface.CheckCertificateByOCSPResponse =
		EUCheckCertificateByOCSPResponse;
	s_Iface.CreateRevocationInfoAttributes =
		EUCreateRevocationInfoAttributes;
	s_Iface.GetCertificateChain = EUGetCertificateChain;
	s_Iface.CreateCACertificateInfoAttributes =
		EUCreateCACertificateInfoAttributes;
	s_Iface.GetTSP = EUGetTSP;
	s_Iface.CheckTSP = EUCheckTSP;
	s_Iface.CtxClientSessionCreate = EUCtxClientSessionCreate;
	s_Iface.CtxServerSessionCreate = EUCtxServerSessionCreate;

	s_Iface.CtxIsNamedPrivateKeyExists = EUCtxIsNamedPrivateKeyExists;
	s_Iface.CtxGenerateNamedPrivateKey = EUCtxGenerateNamedPrivateKey;
	s_Iface.CtxReadNamedPrivateKey = EUCtxReadNamedPrivateKey;
	s_Iface.CtxDestroyNamedPrivateKey = EUCtxDestroyNamedPrivateKey;

	s_Iface.CtxChangeNamedPrivateKeyPassword =
		EUCtxChangeNamedPrivateKeyPassword;
	s_Iface.GetTSPByAccessInfo = EUGetTSPByAccessInfo;

	s_Iface.GetCertificateByFingerprint =
		EUGetCertificateByFingerprint;
	s_Iface.FreeCertificates = EUFreeCertificates;
	s_Iface.GetCertificatesByEDRPOUAndDRFOCode =
		EUGetCertificatesByEDRPOUAndDRFOCode;

	s_Iface.SetOCSPResponseExpireTime =
		EUSetOCSPResponseExpireTime;
	s_Iface.GetOCSPResponseByAccessInfo =
		EUGetOCSPResponseByAccessInfo;

	s_Iface.DeleteCertificate = EUDeleteCertificate;

	s_Iface.SetKeyMediaUserPassword = EUSetKeyMediaUserPassword;

	s_Iface.CheckDataStruct = EUCheckDataStruct;
	s_Iface.CheckFileStruct = EUCheckFileStruct;

	s_Iface.DevCtxEnumIDCardDataChangeDate = EUDevCtxEnumIDCardDataChangeDate;

	s_Iface.GetDataHashFromSignedData = EUGetDataHashFromSignedData;
	s_Iface.GetDataHashFromSignedFile = EUGetDataHashFromSignedFile;

	s_Iface.DevCtxVerifyIDCardSecurityObjectDocument =
		EUDevCtxVerifyIDCardSecurityObjectDocument;

	s_Iface.VerifyDataWithParams = EUVerifyDataWithParams;
	s_Iface.VerifyDataInternalWithParams = EUVerifyDataInternalWithParams;

	s_Iface.CtxGetNamedPrivateKeyInfo = EUCtxGetNamedPrivateKeyInfo;

	s_Iface.GetCertificateByKeyInfoEx = EUGetCertificateByKeyInfoEx;

	s_Iface.ShowCertificate = EUShowCertificate;

	s_Iface.AppendFileTransportHeader = EUAppendFileTransportHeader;
	s_Iface.ParseFileTransportHeader = EUParseFileTransportHeader;
	s_Iface.AppendFileCryptoHeader = EUAppendFileCryptoHeader;
	s_Iface.ParseFileCryptoHeader = EUParseFileCryptoHeader;

	s_Iface.FreeKeyMediaDeviceInfo = EUFreeKeyMediaDeviceInfo;
	s_Iface.GetKeyMediaDeviceInfo = EUGetKeyMediaDeviceInfo;
	s_Iface.CtxEnumNamedPrivateKeys = EUCtxEnumNamedPrivateKeys;

	s_Iface.DevCtxInternalAuthenticateIDCard = EUDevCtxInternalAuthenticateIDCard;
#endif // PC_STATIC_LIBS

	for (dwI = 0; dwI < sizeof(EU_INTERFACE) /
		sizeof(void*); dwI++)
	{
		if (((void* *) &s_Iface)[dwI] == NULL)
		{
#ifndef PC_STATIC_LIBS
			FreeLibrary(s_hLibrary);
			s_hLibrary = NULL;
#endif // PC_STATIC_LIBS

			return 0;
		}
	}

	return 1;
}

//-----------------------------------------------------------------------------

PEU_INTERFACE EUGetInterface()
{
#ifndef PC_STATIC_LIBS
	if (s_hLibrary == NULL)
		return NULL;
#endif // PC_STATIC_LIBS

	return &s_Iface;
}

//-----------------------------------------------------------------------------

void EUUnload()
{
#ifndef PC_STATIC_LIBS
	if (s_hLibrary != NULL)
	{
		FreeLibrary(s_hLibrary);
		s_hLibrary = NULL;
	}
#endif // PC_STATIC_LIBS
}

//=============================================================================
