use crate::*;

pub const DLL_PROCESS_ATTACH: u32 = 1;
pub const DLL_PROCESS_DETACH: u32 = 0;
pub const DLL_THREAD_ATTACH: u32 = 2;
pub const DLL_THREAD_DETACH: u32 = 3;


#[allow(non_upper_case_globals)]
#[no_mangle]
pub static mut s_Iface: EU_INTERFACE = EU_INTERFACE {
    Initialize:          Some(EUInitialize),
    IsInitialized:       Some(EUIsInitialized),
    Finalize:            Some(EUFinalize),

    SetSettings:         Some(EUSetSettings),

    ShowCertificates:    Some(EUShowCertificates),
    ShowCRLs:            Some(EUShowCRLs),

    GetPrivateKeyMedia:  Some(EUGetPrivateKeyMedia),
    ReadPrivateKey:      Some(EUReadPrivateKey),
    IsPrivateKeyReaded:  Some(EUIsPrivateKeyReaded),
    ResetPrivateKey:     Some(EUResetPrivateKey),
    FreeCertOwnerInfo:   Some(EUFreeCertOwnerInfo),

    ShowOwnCertificate:  Some(EUShowOwnCertificate),
    ShowSignInfo:        Some(EUShowSignInfo),
    FreeSignInfo:        Some(EUFreeSignInfo),

    FreeMemory:          Some(EUFreeMemory),

    GetErrorDesc:        Some(EUGetErrorDesc),

    SignData:            Some(EUSignData),
    VerifyData:          Some(EUVerifyData),

    SignDataContinue:    Some(EUSignDataContinue),
    SignDataEnd:         Some(EUSignDataEnd),
    VerifyDataBegin:     Some(EUVerifyDataBegin),
    VerifyDataContinue:  Some(EUVerifyDataContinue),
    VerifyDataEnd:       Some(EUVerifyDataEnd),
    ResetOperation:      Some(EUResetOperation),

    SignFile:            Some(EUSignFile),
    VerifyFile:          Some(EUVerifyFile),

    SignDataInternal:    Some(EUSignDataInternal),
    VerifyDataInternal:  Some(EUVerifyDataInternal),

    SelectCertInfo:      Some(EUSelectCertificateInfo),

    SetUIMode:           Some(EUSetUIMode),

    HashData:            Some(EUHashData),
    HashDataContinue:    Some(EUHashDataContinue),
    HashDataEnd:         Some(EUHashDataEnd),
    HashFile:            Some(EUHashFile),
    SignHash:            Some(EUSignHash),
    VerifyHash:          Some(EUVerifyHash),

    EnumKeyMediaTypes:   Some(EUEnumKeyMediaTypes),
    EnumKeyMediaDevices: Some(EUEnumKeyMediaDevices),

    GetFileStoreSettings: Some(EUGetFileStoreSettings),
    SetFileStoreSettings: Some(EUSetFileStoreSettings),
    GetProxySettings:     Some(EUGetProxySettings),
    SetProxySettings:     Some(EUSetProxySettings),
    GetOCSPSettings:      Some(EUGetOCSPSettings),
    SetOCSPSettings:      Some(EUSetOCSPSettings),
    GetTSPSettings:       Some(EUGetTSPSettings),
    SetTSPSettings:       Some(EUSetTSPSettings),
    GetLDAPSettings:      Some(EUGetLDAPSettings),
    SetLDAPSettings:      Some(EUSetLDAPSettings),

    GetCertificatesCount: Some(EUGetCertificatesCount),
    EnumCertificates:     Some(EUEnumCertificates),
    GetCRLsCount:         Some(EUGetCRLsCount),
    EnumCRLs:             Some(EUEnumCRLs),
    FreeCRLInfo:          Some(EUFreeCRLInfo),

    GetCertificateInfo:   Some(EUGetCertificateInfo),
    FreeCertificateInfo:  Some(EUFreeCertificateInfo),
    GetCRLDetailedInfo:   Some(EUGetCRLDetailedInfo),
    FreeCRLDetailedInfo:  Some(EUFreeCRLDetailedInfo),

    GetCMPSettings:       Some(EUGetCMPSettings),
    SetCMPSettings:       Some(EUSetCMPSettings),
    DoesNeedSetSettings:  Some(EUDoesNeedSetSettings),

    GetPrivateKeyMediaSettings: Some(EUGetPrivateKeyMediaSettings),
    SetPrivateKeyMediaSettings: Some(EUSetPrivateKeyMediaSettings),

    SelectCMPServer:      Some(EUSelectCMPServer),

    RawSignData:          Some(EURawSignData),
    RawVerifyData:        Some(EURawVerifyData),
    RawSignHash:          Some(EURawSignHash),
    RawVerifyHash:        Some(EURawVerifyHash),
    RawSignFile:          Some(EURawSignFile),
    RawVerifyFile:        Some(EURawVerifyFile),

    BASE64Encode:         Some(EUBASE64Encode),
    BASE64Decode:         Some(EUBASE64Decode),

    EnvelopData:          Some(EUEnvelopData),
    DevelopData:          Some(EUDevelopData),
    ShowSenderInfo:       Some(EUShowSenderInfo),
    FreeSenderInfo:       Some(EUFreeSenderInfo),

    ParseCertificate:     Some(EUParseCertificate),

    ReadPrivateKeyBinary: Some(EUReadPrivateKeyBinary),
    ReadPrivateKeyFile:   Some(EUReadPrivateKeyFile),

    SessionDestroy:       Some(EUSessionDestroy),
    ClientSessionCreateStep1:  Some(EUClientSessionCreateStep1),
    ServerSessionCreateStep1:  Some(EUServerSessionCreateStep1),
    ClientSessionCreateStep2:  Some(EUClientSessionCreateStep2),
    ServerSessionCreateStep2:  Some(EUServerSessionCreateStep2),
    SessionIsInitialized:      Some(EUSessionIsInitialized),
    SessionSave:               Some(EUSessionSave),
    SessionLoad:               Some(EUSessionLoad),
    SessionCheckCertificates:  Some(EUSessionCheckCertificates),
    SessionEncrypt:            Some(EUSessionEncrypt),
    SessionEncryptContinue:    Some(EUSessionEncryptContinue),
    SessionDecrypt:            Some(EUSessionDecrypt),
    SessionDecryptContinue:    Some(EUSessionDecryptContinue),

    IsSignedData:              Some(EUIsSignedData),
    IsEnvelopedData:           Some(EUIsEnvelopedData),

    SessionGetPeerCertificateInfo: Some(EUSessionGetPeerCertificateInfo),

    SaveCertificate:               Some(EUSaveCertificate),
    RefreshFileStore:              Some(EURefreshFileStore),

    GetModeSettings:               Some(EUGetModeSettings),
    SetModeSettings:               Some(EUSetModeSettings),

    CheckCertificate:              Some(EUCheckCertificate),

    EnvelopFile:                   Some(EUEnvelopFile),
    DevelopFile:                   Some(EUDevelopFile),
    IsSignedFile:                  Some(EUIsSignedFile),
    IsEnvelopedFile:               Some(EUIsEnvelopedFile),

    GetCertificate:                Some(EUGetCertificate),
    GetOwnCertificate:             Some(EUGetOwnCertificate),

    EnumOwnCertificates:           Some(EUEnumOwnCertificates),
    GetCertificateInfoEx:          Some(EUGetCertificateInfoEx),
    FreeCertificateInfoEx:         Some(EUFreeCertificateInfoEx),

    GetReceiversCertificates:      Some(EUGetReceiversCertificates),
    FreeReceiversCertificates:     Some(EUFreeReceiversCertificates),

    GeneratePrivateKey:            Some(EUGeneratePrivateKey),
    ChangePrivateKeyPassword:      Some(EUChangePrivateKeyPassword),
    BackupPrivateKey:              Some(EUBackupPrivateKey),
    DestroyPrivateKey:             Some(EUDestroyPrivateKey),
    IsHardwareKeyMedia:            Some(EUIsHardwareKeyMedia),
    IsPrivateKeyExists:            Some(EUIsPrivateKeyExists),

    GetCRInfo:                     Some(EUGetCRInfo),
    FreeCRInfo:                    Some(EUFreeCRInfo),

    SaveCertificates:              Some(EUSaveCertificates),
    SaveCRL:                       Some(EUSaveCRL),

    GetCertificateByEMail:         Some(EUGetCertificateByEMail),
    GetCertificateByNBUCode:       Some(EUGetCertificateByNBUCode),

    AppendSign:                    Some(EUAppendSign),
    AppendSignInternal:            Some(EUAppendSignInternal),
    VerifyDataSpecific:            Some(EUVerifyDataSpecific),
    VerifyDataInternalSpecific:    Some(EUVerifyDataInternalSpecific),
    AppendSignBegin:               Some(EUAppendSignBegin),
    VerifyDataSpecificBegin:       Some(EUVerifyDataSpecificBegin),
    AppendSignFile:                Some(EUAppendSignFile),
    VerifyFileSpecific:            Some(EUVerifyFileSpecific),
    AppendSignHash:                Some(EUAppendSignHash),
    VerifyHashSpecific:            Some(EUVerifyHashSpecific),
    GetSignsCount:                 Some(EUGetSignsCount),
    GetSignerInfo:                 Some(EUGetSignerInfo),
    GetFileSignsCount:             Some(EUGetFileSignsCount),
    GetFileSignerInfo:             Some(EUGetFileSignerInfo),

    IsAlreadySigned:               Some(EUIsAlreadySigned),
    IsFileAlreadySigned:           Some(EUIsFileAlreadySigned),

    HashDataWithParams:            Some(EUHashDataWithParams),
    HashDataBeginWithParams:       Some(EUHashDataBeginWithParams),
    HashFileWithParams:            Some(EUHashFileWithParams),

    EnvelopDataEx:                 Some(EUEnvelopDataEx),

    SetSettingsFilePath:           Some(EUSetSettingsFilePath),

    SetKeyMediaPassword:           Some(EUSetKeyMediaPassword),
    GeneratePrivateKeyEx:          Some(EUGeneratePrivateKeyEx),

    GetErrorLangDesc:              Some(EUGetErrorLangDesc),

    EnvelopFileEx:                 Some(EUEnvelopFileEx),

    IsCertificates:                Some(EUIsCertificates),
    IsCertificatesFile:            Some(EUIsCertificatesFile),

    EnumCertificatesByOCode:       Some(EUEnumCertificatesByOCode),
    GetCertificatesByOCode:        Some(EUGetCertificatesByOCode),

    SetPrivateKeyMediaSettingsProtected:
        Some(EUSetPrivateKeyMediaSettingsProtected),

    EnvelopDataToRecipients:       Some(EUEnvelopDataToRecipients),
    EnvelopFileToRecipients:       Some(EUEnvelopFileToRecipients),

    EnvelopDataExWithDynamicKey:   Some(EUEnvelopDataExWithDynamicKey),
    EnvelopDataToRecipientsWithDynamicKey:
        Some(EUEnvelopDataToRecipientsWithDynamicKey),
    EnvelopFileExWithDynamicKey:   Some(EUEnvelopFileExWithDynamicKey),
    EnvelopFileToRecipientsWithDynamicKey:
        Some(EUEnvelopFileToRecipientsWithDynamicKey),

    SavePrivateKey:                Some(EUSavePrivateKey),
    LoadPrivateKey:                Some(EULoadPrivateKey),
    ChangeSoftwarePrivateKeyPassword:
        Some(EUChangeSoftwarePrivateKeyPassword),

    HashDataBeginWithParamsCtx:
        Some(EUHashDataBeginWithParamsCtx),
    HashDataContinueCtx: Some(EUHashDataContinueCtx),
    HashDataEndCtx:      Some(EUHashDataEndCtx),

    GetCertificateByKeyInfo: Some(EUGetCertificateByKeyInfo),

    SavePrivateKeyEx:     Some(EUSavePrivateKeyEx),
    LoadPrivateKeyEx:     Some(EULoadPrivateKeyEx),

    CreateEmptySign:      Some(EUCreateEmptySign),
    CreateSigner:         Some(EUCreateSigner),
    AppendSigner:         Some(EUAppendSigner),

    SetRuntimeParameter:   Some(EUSetRuntimeParameter),

    EnvelopDataToRecipientsEx: Some(EUEnvelopDataToRecipientsEx),
    EnvelopFileToRecipientsEx: Some(EUEnvelopFileToRecipientsEx),
    EnvelopDataToRecipientsWithOCode:
        Some(EUEnvelopDataToRecipientsWithOCode),

    SignDataContinueCtx:   Some(EUSignDataContinueCtx),
    SignDataEndCtx:        Some(EUSignDataEndCtx),
    VerifyDataBeginCtx:    Some(EUVerifyDataBeginCtx),
    VerifyDataContinueCtx: Some(EUVerifyDataContinueCtx),
    VerifyDataEndCtx:      Some(EUVerifyDataEndCtx),
    ResetOperationCtx:     Some(EUResetOperationCtx),

    SignDataRSA:            Some(EUSignDataRSA),
    SignDataRSAContinue:    Some(EUSignDataRSAContinue),
    SignDataRSAEnd:         Some(EUSignDataRSAEnd),
    SignFileRSA:            Some(EUSignFileRSA),
    SignDataRSAContinueCtx: Some(EUSignDataRSAContinueCtx),
    SignDataRSAEndCtx:      Some(EUSignDataRSAEndCtx),

    DownloadFileViaHTTP:    Some(EUDownloadFileViaHTTP),

    ParseCRL:               Some(EUParseCRL),

    IsOldFormatSign:        Some(EUIsOldFormatSign),
    IsOldFormatSignFile:    Some(EUIsOldFormatSignFile),

    GetPrivateKeyMediaEx:   Some(EUGetPrivateKeyMediaEx),

    GetKeyInfo:             Some(EUGetKeyInfo),
    GetKeyInfoBinary:       Some(EUGetKeyInfoBinary),
    GetKeyInfoFile:         Some(EUGetKeyInfoFile),
    GetCertificatesByKeyInfo: Some(EUGetCertificatesByKeyInfo),

    EnvelopAppendData:      Some(EUEnvelopAppendData),
    EnvelopAppendFile:      Some(EUEnvelopAppendFile),
    EnvelopAppendDataEx:    Some(EUEnvelopAppendDataEx),
    EnvelopAppendFileEx:    Some(EUEnvelopAppendFileEx),

    GetStorageParameter:    Some(EUGetStorageParameter),
    SetStorageParameter:    Some(EUSetStorageParameter),

    DevelopDataEx:          Some(EUDevelopDataEx),
    DevelopFileEx:          Some(EUDevelopFileEx),

    GetOCSPAccessInfoModeSettings: Some(EUGetOCSPAccessInfoModeSettings),
    SetOCSPAccessInfoModeSettings: Some(EUSetOCSPAccessInfoModeSettings),

    EnumOCSPAccessInfoSettings:    Some(EUEnumOCSPAccessInfoSettings),
    GetOCSPAccessInfoSettings:     Some(EUGetOCSPAccessInfoSettings),
    SetOCSPAccessInfoSettings:     Some(EUSetOCSPAccessInfoSettings),
    DeleteOCSPAccessInfoSettings:  Some(EUDeleteOCSPAccessInfoSettings),

    CheckCertificateByIssuerAndSerial:
        Some(EUCheckCertificateByIssuerAndSerial),

    ParseCertificateEx: Some(EUParseCertificateEx),

    CheckCertificateByIssuerAndSerialEx:
        Some(EUCheckCertificateByIssuerAndSerialEx),

    ClientDynamicKeySessionCreate: Some(EUClientDynamicKeySessionCreate),
    ServerDynamicKeySessionCreate: Some(EUServerDynamicKeySessionCreate),

    GetSenderInfo:        Some(EUGetSenderInfo),
    GetFileSenderInfo:    Some(EUGetFileSenderInfo),

    SCClientIsRunning:    Some(EUSCClientIsRunning),
    SCClientStart:        Some(EUSCClientStart),
    SCClientStop:         Some(EUSCClientStop),
    SCClientAddGate:      Some(EUSCClientAddGate),
    SCClientRemoveGate:   Some(EUSCClientRemoveGate),
    SCClientGetStatistic: Some(EUSCClientGetStatistic),
    SCClientFreeStatistic:Some(EUSCClientFreeStatistic),

    GetRecipientsCount:    Some(EUGetRecipientsCount),
    GetFileRecipientsCount:Some(EUGetFileRecipientsCount),
    GetRecipientInfo:      Some(EUGetRecipientInfo),
    GetFileRecipientInfo:  Some(EUGetFileRecipientInfo),

    CtxCreate:            Some(EUCtxCreate),
    CtxFree:              Some(EUCtxFree),
    CtxSetParameter:      Some(EUCtxSetParameter),
    CtxReadPrivateKey:    Some(EUCtxReadPrivateKey),
    CtxReadPrivateKeyBinary: Some(EUCtxReadPrivateKeyBinary),
    CtxReadPrivateKeyFile:   Some(EUCtxReadPrivateKeyFile),
    CtxFreePrivateKey:    Some(EUCtxFreePrivateKey),

    CtxDevelopData:       Some(EUCtxDevelopData),
    CtxDevelopFile:       Some(EUCtxDevelopFile),

    CtxFreeMemory:        Some(EUCtxFreeMemory),
    CtxFreeCertOwnerInfo: Some(EUCtxFreeCertOwnerInfo),
    CtxFreeCertificateInfoEx: Some(EUCtxFreeCertificateInfoEx),
    CtxFreeSignInfo:      Some(EUCtxFreeSignInfo),
    CtxFreeSenderInfo:    Some(EUCtxFreeSenderInfo),

    CtxGetOwnCertificate: Some(EUCtxGetOwnCertificate),
    CtxEnumOwnCertificates: Some(EUCtxEnumOwnCertificates),

    CtxHashData:          Some(EUCtxHashData),
    CtxHashFile:          Some(EUCtxHashFile),
    CtxHashDataBegin:     Some(EUCtxHashDataBegin),
    CtxHashDataContinue:  Some(EUCtxHashDataContinue),
    CtxHashDataEnd:       Some(EUCtxHashDataEnd),
    CtxFreeHash:          Some(EUCtxFreeHash),

    CtxSignHash:          Some(EUCtxSignHash),
    CtxSignHashValue:     Some(EUCtxSignHashValue),
    CtxSignData:          Some(EUCtxSignData),
    CtxSignFile:          Some(EUCtxSignFile),
    CtxIsAlreadySigned:   Some(EUCtxIsAlreadySigned),
    CtxIsFileAlreadySigned: Some(EUCtxIsFileAlreadySigned),
    CtxAppendSignHash:    Some(EUCtxAppendSignHash),
    CtxAppendSignHashValue: Some(EUCtxAppendSignHashValue),
    CtxAppendSign:        Some(EUCtxAppendSign),
    CtxAppendSignFile:    Some(EUCtxAppendSignFile),
    CtxCreateEmptySign:   Some(EUCtxCreateEmptySign),
    CtxCreateSigner:      Some(EUCtxCreateSigner),
    CtxAppendSigner:      Some(EUCtxAppendSigner),
    CtxGetSignsCount:     Some(EUCtxGetSignsCount),
    CtxGetFileSignsCount: Some(EUCtxGetFileSignsCount),
    CtxGetSignerInfo:     Some(EUCtxGetSignerInfo),
    CtxGetFileSignerInfo: Some(EUCtxGetFileSignerInfo),
    CtxVerifyHash:        Some(EUCtxVerifyHash),
    CtxVerifyHashValue:   Some(EUCtxVerifyHashValue),
    CtxVerifyData:        Some(EUCtxVerifyData),
    CtxVerifyDataInternal: Some(EUCtxVerifyDataInternal),
    CtxVerifyFile:        Some(EUCtxVerifyFile),

    CtxEnvelopData:       Some(EUCtxEnvelopData),
    CtxEnvelopFile:       Some(EUCtxEnvelopFile),
    CtxGetSenderInfo:     Some(EUCtxGetSenderInfo),
    CtxGetFileSenderInfo: Some(EUCtxGetFileSenderInfo),
    CtxGetRecipientsCount: Some(EUCtxGetRecipientsCount),
    CtxGetFileRecipientsCount: Some(EUCtxGetFileRecipientsCount),
    CtxGetRecipientInfo:  Some(EUCtxGetRecipientInfo),
    CtxGetFileRecipientInfo: Some(EUCtxGetFileRecipientInfo),
    CtxEnvelopAppendData: Some(EUCtxEnvelopAppendData),
    CtxEnvelopAppendFile: Some(EUCtxEnvelopAppendFile),

    EnumJKSPrivateKeys:     Some(EUEnumJKSPrivateKeys),
    EnumJKSPrivateKeysFile: Some(EUEnumJKSPrivateKeysFile),
    FreeCertificatesArray:  Some(EUFreeCertificatesArray),
    GetJKSPrivateKey:       Some(EUGetJKSPrivateKey),
    GetJKSPrivateKeyFile:   Some(EUGetJKSPrivateKeyFile),

    CtxGetDataFromSignedData: Some(EUCtxGetDataFromSignedData),
    CtxGetDataFromSignedFile: Some(EUCtxGetDataFromSignedFile),

    SetSettingsRegPath: Some(EUSetSettingsRegPath),

    CtxIsDataInSignedDataAvailable:
        Some(EUCtxIsDataInSignedDataAvailable),
    CtxIsDataInSignedFileAvailable:
        Some(EUCtxIsDataInSignedFileAvailable),

    GetCertificateFromSignedData:
        Some(EUGetCertificateFromSignedData),
    GetCertificateFromSignedFile:
        Some(EUGetCertificateFromSignedFile),

    IsDataInSignedDataAvailable:
        Some(EUIsDataInSignedDataAvailable),
    IsDataInSignedFileAvailable:
        Some(EUIsDataInSignedFileAvailable),
    GetDataFromSignedData:
        Some(EUGetDataFromSignedData),
    GetDataFromSignedFile:
        Some(EUGetDataFromSignedFile),

    GetCertificatesFromLDAPByEDRPOUCode:
        Some(EUGetCertificatesFromLDAPByEDRPOUCode),

    ProtectDataByPassword:   Some(EUProtectDataByPassword),
    UnprotectDataByPassword: Some(EUUnprotectDataByPassword),

    FreeTimeInfo:           Some(EUFreeTimeInfo),
    GetSignTimeInfo:        Some(EUGetSignTimeInfo),
    GetFileSignTimeInfo:    Some(EUGetFileSignTimeInfo),

    VerifyHashOnTime:       Some(EUVerifyHashOnTime),
    VerifyDataOnTime:       Some(EUVerifyDataOnTime),
    VerifyDataInternalOnTime:
        Some(EUVerifyDataInternalOnTime),
    VerifyDataOnTimeBegin:  Some(EUVerifyDataOnTimeBegin),
    VerifyFileOnTime:       Some(EUVerifyFileOnTime),

    VerifyHashOnTimeEx:       Some(EUVerifyHashOnTimeEx),
    VerifyDataOnTimeEx:       Some(EUVerifyDataOnTimeEx),
    VerifyDataInternalOnTimeEx:
        Some(EUVerifyDataInternalOnTimeEx),
    VerifyDataOnTimeBeginEx:  Some(EUVerifyDataOnTimeBeginEx),
    VerifyFileOnTimeEx:       Some(EUVerifyFileOnTimeEx),

    CtxEnumPrivateKeyInfo: Some(EUCtxEnumPrivateKeyInfo),
    CtxExportPrivateKeyContainer:
        Some(EUCtxExportPrivateKeyContainer),
    CtxExportPrivateKeyPFXContainer:
        Some(EUCtxExportPrivateKeyPFXContainer),
    CtxExportPrivateKeyContainerFile:
        Some(EUCtxExportPrivateKeyContainerFile),
    CtxExportPrivateKeyPFXContainerFile:
        Some(EUCtxExportPrivateKeyPFXContainerFile),
    CtxGetCertificateFromPrivateKey:
        Some(EUCtxGetCertificateFromPrivateKey),

    RawEnvelopData:    Some(EURawEnvelopData),
    RawDevelopData:    Some(EURawDevelopData),

    RawVerifyDataEx:   Some(EURawVerifyDataEx),

    EnvelopDataRSAEx:  Some(EUEnvelopDataRSAEx),
    EnvelopDataRSA:    Some(EUEnvelopDataRSA),
    EnvelopFileRSAEx:  Some(EUEnvelopFileRSAEx),
    EnvelopFileRSA:    Some(EUEnvelopFileRSA),
    GetReceiversCertificatesRSA:
        Some(EUGetReceiversCertificatesRSA),
    EnvelopDataToRecipientsRSA:
        Some(EUEnvelopDataToRecipientsRSA),
    EnvelopFileToRecipientsRSA:
        Some(EUEnvelopFileToRecipientsRSA),

    RemoveSign:        Some(EURemoveSign),
    RemoveSignFile:    Some(EURemoveSignFile),

    DevCtxEnum:        Some(EUDevCtxEnum),
    DevCtxOpen:        Some(EUDevCtxOpen),
    DevCtxEnumVirtual: Some(EUDevCtxEnumVirtual),
    DevCtxOpenVirtual: Some(EUDevCtxOpenVirtual),
    DevCtxClose:       Some(EUDevCtxClose),
    DevCtxBeginPersonalization:
        Some(EUDevCtxBeginPersonalization),
    DevCtxContinuePersonalization:
        Some(EUDevCtxContinuePersonalization),
    DevCtxEndPersonalization:
        Some(EUDevCtxEndPersonalization),
    DevCtxGetData:     Some(EUDevCtxGetData),
    DevCtxUpdateData:  Some(EUDevCtxUpdateData),
    DevCtxSignData:    Some(EUDevCtxSignData),
    DevCtxChangePassword:
        Some(EUDevCtxChangePassword),
    DevCtxUpdateSystemPublicKey:
        Some(EUDevCtxUpdateSystemPublicKey),
    DevCtxSignSystemPublicKey:
        Some(EUDevCtxSignSystemPublicKey),

    GetReceiversCertificatesEx:
        Some(EUGetReceiversCertificatesEx),

    AppendTransportHeader: Some(EUAppendTransportHeader),
    ParseTransportHeader:  Some(EUParseTransportHeader),
    AppendCryptoHeader:    Some(EUAppendCryptoHeader),
    ParseCryptoHeader:     Some(EUParseCryptoHeader),

    EnvelopDataToRecipientsOffline:
        Some(EUEnvelopDataToRecipientsOffline),

    DevCtxGeneratePrivateKey: Some(EUDevCtxGeneratePrivateKey),

    GeneratePRNGSequence:   Some(EUGeneratePRNGSequence),

    SetSettingsFilePathEx:  Some(EUSetSettingsFilePathEx),

    ChangeOwnCertificatesStatus:
        Some(EUChangeOwnCertificatesStatus),
    CtxChangeOwnCertificatesStatus:
        Some(EUCtxChangeOwnCertificatesStatus),

    GetCertificatesByNBUCodeAndCMP:
        Some(EUGetCertificatesByNBUCodeAndCMP),

    EnumCertificatesEx:  Some(EUEnumCertificatesEx),

    MakeNewCertificate:  Some(EUMakeNewCertificate),

    CreateSignerBegin:   Some(EUCreateSignerBegin),
    CreateSignerEnd:     Some(EUCreateSignerEnd),

    ClientDynamicKeySessionLoad: Some(EUClientDynamicKeySessionLoad),

    DevCtxOpenIDCard:            Some(EUDevCtxOpenIDCard),
    DevCtxChangeIDCardPasswords: Some(EUDevCtxChangeIDCardPasswords),
    DevCtxAuthenticateIDCard:    Some(EUDevCtxAuthenticateIDCard),
    DevCtxVerifyIDCardData:      Some(EUDevCtxVerifyIDCardData),
    DevCtxUpdateIDCardData:      Some(EUDevCtxUpdateIDCardData),
    DevCtxEnumIDCardData:        Some(EUDevCtxEnumIDCardData),

    EnvelopDataWithSettings: Some(EUEnvelopDataWithSettings),
    EnvelopDataToRecipientsWithSettings:
        Some(EUEnvelopDataToRecipientsWithSettings),

    ShowSecureConfirmDialog: Some(EUShowSecureConfirmDialog),

    CtxClientSessionCreateStep1: Some(EUCtxClientSessionCreateStep1),
    CtxServerSessionCreateStep1: Some(EUCtxServerSessionCreateStep1),
    CtxSessionLoad:             Some(EUCtxSessionLoad),
    CtxServerDynamicKeySessionCreate:
        Some(EUCtxServerDynamicKeySessionCreate),

    CtxGetSignValue:    Some(EUCtxGetSignValue),
    AppendSignerUnsignedAttribute:
        Some(EUAppendSignerUnsignedAttribute),
    CheckCertificateByOCSP: Some(EUCheckCertificateByOCSP),
    GetOCSPResponse:        Some(EUGetOCSPResponse),
    CheckOCSPResponse:      Some(EUCheckOCSPResponse),
    CheckCertificateByOCSPResponse:
        Some(EUCheckCertificateByOCSPResponse),
    CreateRevocationInfoAttributes:
        Some(EUCreateRevocationInfoAttributes),
    GetCertificateChain: Some(EUGetCertificateChain),
    CreateCACertificateInfoAttributes:
        Some(EUCreateCACertificateInfoAttributes),
    GetTSP:    Some(EUGetTSP),
    CheckTSP:  Some(EUCheckTSP),
    CtxClientSessionCreate:
        Some(EUCtxClientSessionCreate),
    CtxServerSessionCreate:
        Some(EUCtxServerSessionCreate),

    CtxIsNamedPrivateKeyExists:
        Some(EUCtxIsNamedPrivateKeyExists),
    CtxGenerateNamedPrivateKey:
        Some(EUCtxGenerateNamedPrivateKey),
    CtxReadNamedPrivateKey:
        Some(EUCtxReadNamedPrivateKey),
    CtxDestroyNamedPrivateKey:
        Some(EUCtxDestroyNamedPrivateKey),

    CtxChangeNamedPrivateKeyPassword:
        Some(EUCtxChangeNamedPrivateKeyPassword),
    GetTSPByAccessInfo:
        Some(EUGetTSPByAccessInfo),

    GetCertificateByFingerprint:
        Some(EUGetCertificateByFingerprint),
    FreeCertificates: Some(EUFreeCertificates),
    GetCertificatesByEDRPOUAndDRFOCode:
        Some(EUGetCertificatesByEDRPOUAndDRFOCode),

    SetOCSPResponseExpireTime:
        Some(EUSetOCSPResponseExpireTime),
    GetOCSPResponseByAccessInfo:
        Some(EUGetOCSPResponseByAccessInfo),

    DeleteCertificate:
        Some(EUDeleteCertificate),

    SetKeyMediaUserPassword:
        Some(EUSetKeyMediaUserPassword),

    CheckDataStruct: Some(EUCheckDataStruct),
    CheckFileStruct: Some(EUCheckFileStruct),

    DevCtxEnumIDCardDataChangeDate:
        Some(EUDevCtxEnumIDCardDataChangeDate),

    GetDataHashFromSignedData:
        Some(EUGetDataHashFromSignedData),
    GetDataHashFromSignedFile:
        Some(EUGetDataHashFromSignedFile),

    DevCtxVerifyIDCardSecurityObjectDocument:
        Some(EUDevCtxVerifyIDCardSecurityObjectDocument),

    VerifyDataWithParams:
        Some(EUVerifyDataWithParams),
    VerifyDataInternalWithParams:
        Some(EUVerifyDataInternalWithParams),

    CtxGetNamedPrivateKeyInfo:
        Some(EUCtxGetNamedPrivateKeyInfo),

    GetCertificateByKeyInfoEx:
        Some(EUGetCertificateByKeyInfoEx),

    ShowCertificate: Some(EUShowCertificate),

    AppendFileTransportHeader:
        Some(EUAppendFileTransportHeader),
    ParseFileTransportHeader:
        Some(EUParseFileTransportHeader),
    AppendFileCryptoHeader:
        Some(EUAppendFileCryptoHeader),
    ParseFileCryptoHeader:
        Some(EUParseFileCryptoHeader),

    FreeKeyMediaDeviceInfo:
        Some(EUFreeKeyMediaDeviceInfo),
    GetKeyMediaDeviceInfo:
        Some(EUGetKeyMediaDeviceInfo),
    CtxEnumNamedPrivateKeys:
        Some(EUCtxEnumNamedPrivateKeys),

    DevCtxInternalAuthenticateIDCard:
        Some(EUDevCtxInternalAuthenticateIDCard),
};

/// # Safety
pub unsafe fn EULoad() -> c_int {
    let ret = EUInitialize();
    // In the C code, success was "1" if loaded, "0" if not.
    // EUInitialize returns 0 if success, or an error code if not. 
    if ret == 0 {
        1
    } else {
        0
    }
}

/// # Safety
pub unsafe fn EUGetInterface() -> *const EU_INTERFACE {
    // Return pointer to our static s_Iface
    &raw const s_Iface
}

/// # Safety
pub unsafe fn EUUnload() {
    EUFinalize();
}