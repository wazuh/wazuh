#include "kerberos_sspi.h"
#include <stdlib.h>
#include <stdio.h>

static HINSTANCE _sspi_security_dll = NULL; 
static HINSTANCE _sspi_secur32_dll = NULL;

/**
 * Encrypt A Message
 */
SECURITY_STATUS SEC_ENTRY _sspi_EncryptMessage(PCtxtHandle phContext, unsigned long fQOP, PSecBufferDesc pMessage, unsigned long MessageSeqNo) {
  // Create function pointer instance
  encryptMessage_fn pfn_encryptMessage = NULL;

  // Return error if library not loaded
  if(_sspi_security_dll == NULL) return -1;

  // Map function to library method
  pfn_encryptMessage = (encryptMessage_fn)GetProcAddress(_sspi_security_dll, "EncryptMessage");
  // Check if the we managed to map function pointer
  if(!pfn_encryptMessage) {
    printf("GetProcAddress failed.\n");
    return -2;
  }

  // Call the function
  return (*pfn_encryptMessage)(phContext, fQOP, pMessage, MessageSeqNo);
}

/**
 * Acquire Credentials
 */
SECURITY_STATUS SEC_ENTRY _sspi_AcquireCredentialsHandle(
  LPSTR pszPrincipal, LPSTR pszPackage, unsigned long fCredentialUse,
  void * pvLogonId, void * pAuthData, SEC_GET_KEY_FN pGetKeyFn, void * pvGetKeyArgument,
  PCredHandle phCredential, PTimeStamp ptsExpiry
) {
  SECURITY_STATUS     status;
  // Create function pointer instance
  acquireCredentialsHandle_fn pfn_acquireCredentialsHandle = NULL;

  // Return error if library not loaded
  if(_sspi_security_dll == NULL) return -1;

  // Map function
  #ifdef _UNICODE
      pfn_acquireCredentialsHandle = (acquireCredentialsHandle_fn)GetProcAddress(_sspi_security_dll, "AcquireCredentialsHandleW");
  #else
      pfn_acquireCredentialsHandle = (acquireCredentialsHandle_fn)GetProcAddress(_sspi_security_dll, "AcquireCredentialsHandleA");
  #endif

  // Check if the we managed to map function pointer
  if(!pfn_acquireCredentialsHandle) {
    printf("GetProcAddress failed.\n");
    return -2;
  }

  // Status
  status = (*pfn_acquireCredentialsHandle)(pszPrincipal, pszPackage, fCredentialUse,
      pvLogonId, pAuthData, pGetKeyFn, pvGetKeyArgument, phCredential, ptsExpiry
    );

  // Call the function
  return status;
}

/**
 * Delete Security Context
 */
SECURITY_STATUS SEC_ENTRY _sspi_DeleteSecurityContext(PCtxtHandle phContext) {
  // Create function pointer instance
  deleteSecurityContext_fn pfn_deleteSecurityContext = NULL;

  // Return error if library not loaded
  if(_sspi_security_dll == NULL) return -1;
  // Map function
  pfn_deleteSecurityContext = (deleteSecurityContext_fn)GetProcAddress(_sspi_security_dll, "DeleteSecurityContext");

  // Check if the we managed to map function pointer
  if(!pfn_deleteSecurityContext) {
    printf("GetProcAddress failed.\n");
    return -2;
  }

  // Call the function
  return (*pfn_deleteSecurityContext)(phContext);
}

/**
 * Decrypt Message
 */
SECURITY_STATUS SEC_ENTRY _sspi_DecryptMessage(PCtxtHandle phContext, PSecBufferDesc pMessage, unsigned long MessageSeqNo, unsigned long pfQOP) {
  // Create function pointer instance
  decryptMessage_fn pfn_decryptMessage = NULL;

  // Return error if library not loaded
  if(_sspi_security_dll == NULL) return -1;
  // Map function
  pfn_decryptMessage = (decryptMessage_fn)GetProcAddress(_sspi_security_dll, "DecryptMessage");

  // Check if the we managed to map function pointer
  if(!pfn_decryptMessage) {
    printf("GetProcAddress failed.\n");
    return -2;
  }

  // Call the function
  return (*pfn_decryptMessage)(phContext, pMessage, MessageSeqNo, pfQOP);
}

/**
 * Initialize Security Context
 */
SECURITY_STATUS SEC_ENTRY _sspi_initializeSecurityContext(
  PCredHandle phCredential, PCtxtHandle phContext,
  LPSTR pszTargetName, unsigned long fContextReq, 
  unsigned long Reserved1, unsigned long TargetDataRep, 
  PSecBufferDesc pInput, unsigned long Reserved2,
  PCtxtHandle phNewContext, PSecBufferDesc pOutput,
  unsigned long * pfContextAttr, PTimeStamp ptsExpiry
) {
  SECURITY_STATUS status;
  // Create function pointer instance
  initializeSecurityContext_fn pfn_initializeSecurityContext = NULL;

  // Return error if library not loaded
  if(_sspi_security_dll == NULL) return -1;
  
  // Map function
  #ifdef _UNICODE
    pfn_initializeSecurityContext = (initializeSecurityContext_fn)GetProcAddress(_sspi_security_dll, "InitializeSecurityContextW");
  #else
    pfn_initializeSecurityContext = (initializeSecurityContext_fn)GetProcAddress(_sspi_security_dll, "InitializeSecurityContextA");
  #endif

  // Check if the we managed to map function pointer
  if(!pfn_initializeSecurityContext) {
    printf("GetProcAddress failed.\n");
    return -2;
  }

  // Execute intialize context
  status = (*pfn_initializeSecurityContext)(
    phCredential, phContext, pszTargetName, fContextReq, 
    Reserved1, TargetDataRep, pInput, Reserved2,
    phNewContext, pOutput, pfContextAttr, ptsExpiry
  );

  // Call the function
  return status;
}
/**
 * Query Context Attributes
 */
SECURITY_STATUS SEC_ENTRY _sspi_QueryContextAttributes(
  PCtxtHandle phContext, unsigned long ulAttribute, void * pBuffer
) {
  // Create function pointer instance
  queryContextAttributes_fn pfn_queryContextAttributes = NULL;

  // Return error if library not loaded
  if(_sspi_security_dll == NULL) return -1;

  #ifdef _UNICODE
    pfn_queryContextAttributes = (queryContextAttributes_fn)GetProcAddress(_sspi_security_dll, "QueryContextAttributesW");
  #else
    pfn_queryContextAttributes = (queryContextAttributes_fn)GetProcAddress(_sspi_security_dll, "QueryContextAttributesA");
  #endif

  // Check if the we managed to map function pointer
  if(!pfn_queryContextAttributes) {
    printf("GetProcAddress failed.\n");
    return -2;
  }

  // Call the function
  return (*pfn_queryContextAttributes)(
    phContext, ulAttribute, pBuffer
  );
}

/**
 * InitSecurityInterface
 */
PSecurityFunctionTable _ssip_InitSecurityInterface() {
  INIT_SECURITY_INTERFACE InitSecurityInterface;
  PSecurityFunctionTable pSecurityInterface = NULL;

  // Return error if library not loaded
  if(_sspi_security_dll == NULL) return NULL;

  #ifdef _UNICODE
    // Get the address of the InitSecurityInterface function.
    InitSecurityInterface = (INIT_SECURITY_INTERFACE) GetProcAddress (
                                          _sspi_secur32_dll, 
                                          TEXT("InitSecurityInterfaceW"));
  #else
    // Get the address of the InitSecurityInterface function.
    InitSecurityInterface = (INIT_SECURITY_INTERFACE) GetProcAddress (
                                          _sspi_secur32_dll, 
                                          TEXT("InitSecurityInterfaceA"));
  #endif

  if(!InitSecurityInterface) {
    printf (TEXT("Failed in getting the function address, Error: %x"), GetLastError ());
    return NULL;
  }

  // Use InitSecurityInterface to get the function table.
  pSecurityInterface = (*InitSecurityInterface)();

  if(!pSecurityInterface) {
    printf (TEXT("Failed in getting the function table, Error: %x"), GetLastError ());
    return NULL;
  }

  return pSecurityInterface;
}

/**
 * Load security.dll dynamically
 */
int load_library() {
  DWORD err;
  // Load the library
  _sspi_security_dll = LoadLibrary("security.dll");

  // Check if the library loaded
  if(_sspi_security_dll == NULL) {
    err = GetLastError();
    return err;
  }

  // Load the library
  _sspi_secur32_dll = LoadLibrary("secur32.dll");

  // Check if the library loaded
  if(_sspi_secur32_dll == NULL) {
    err = GetLastError();
    return err;
  }

  return 0;
}