/*! \file cavium_ssl.h */
/*
 * Copyright (c) 2003-2005, Cavium Networks. All rights reserved.
 *
 * This Software is the property of Cavium Networks. The Software and all
 * accompanying documentation are copyrighted. The Software made available here
 * constitutes the proprietary information of Cavium Networks. You agree to take *
 * reasonable steps to prevent the disclosure, unauthorized use or unauthorized
 * distribution of the Software. You shall use this Software solely with Cavium
 * hardware.
 *
 * Except as expressly permitted in a separate Software License Agreement
 * between You and Cavium Networks, You shall not modify, decompile,
 * disassemble, extract, or otherwise reverse engineer this Software. You shall
 * not make any copy of the Software or its accompanying documentation, except
 * for copying incident to the ordinary and intended use of the Software and
 * the Underlying Program and except for the making of a single archival copy.
 *
 * This Software, including technical data, may be subject to U.S. export
 * control laws, including the U.S. Export Administration Act and its
 * associated regulations, and may be subject to export or import regulations
 * in other countries. You warrant that You will comply strictly in all
 * respects with all such regulations and acknowledge that you have the
 * responsibility to obtain licenses to export, re-export or import the
 * Software.
 *
 * TO THE MAXIMUM EXTENT PERMITTED BY LAW, THE SOFTWARE IS PROVIDED "AS IS" AND
 * WITH ALL FAULTS AND CAVIUM MAKES NO PROMISES, REPRESENTATIONS OR WARRANTIES,
 * EITHER EXPRESS,IMPLIED, STATUTORY,OR OTHERWISE, WITH RESPECT TO THE SOFTWARE,
 * INCLUDING ITS CONDITION,ITS CONFORMITY TO ANY REPRESENTATION OR DESCRIPTION,
 * OR THE EXISTENCE OF ANY LATENT OR PATENT DEFECTS, AND CAVIUM SPECIFICALLY
 * DISCLAIMS ALL IMPLIED (IF ANY) WARRANTIES OF TITLE, MERCHANTABILITY,
 * NONINFRINGEMENT, FITNESS FOR A PARTICULAR PURPOSE,LACK OF VIRUSES,ACCURACY OR
 * COMPLETENESS, QUIET ENJOYMENT, QUIET POSSESSION OR CORRESPONDENCE TO
 * DESCRIPTION. THE ENTIRE RISK ARISING OUT OF USE OR PERFORMANCE OF THE
 * SOFTWARE LIES WITH YOU.
 *
 */

#ifndef _CAVIUM_SSL_H_
#define _CAVIUM_SSL_H_


#ifndef CSP1_KERNEL


/*! \enum SslVersion SSL/TLS protocol version */
typedef enum {VER_TLS = 0, VER3_0 = 1, VER_DTLS = 0x400, VER_DTLS_POST_RFC = 0x800, VER_TLS1_1 = 0x401, VER_TLS1_2 = 0x801} SslVersion;

#ifdef MC2
/*! \enum Rc4Type RC4 cipher type */
typedef enum {UNSUPPORTED_RC4 = -1, RC4_128 = 8, RC4_EXPORT_40 = 9, RC4_EXPORT_56 = 11} Rc4Type;

/*! \enum DesType  (3)DES cipher type */
typedef enum {UNSUPPORTED_DES = -1, DES = 12, DES_EXPORT_40 = 13, DES3_192 = 14, DES_EXPORT_56 = 15} DesType;
#else
/*! \enum Rc4Type RC4 cipher type */
typedef enum {UNSUPPORTED_RC4 = -1, RC4_128 = 0, RC4_EXPORT_40 = 1, RC4_EXPORT_56 = 7} Rc4Type;

/*! \enum DesType  (3)DES cipher type */
typedef enum {UNSUPPORTED_DES = -1, DES = 0, DES_EXPORT_40 = 1, DES3_192 = 2} DesType;
#endif
/*! \enum MessageType  SSL/TLS Record Type */
typedef enum {CHANGE_CIPHER_SPEC = 0, ALERT = 1, HANDSHAKE = 2, APP_DATA = 3} MessageType;

/*! \enum MasterSecretReturn  SSL/TLS Record Type */
typedef enum {NOT_RETURNED = 0, RETURN_ENCRYPTED = 1} MasterSecretReturn;

#ifdef MAC_SECRET_RETURN_SUPPORT
/*! \enum MacSecretReturn  SSL/TLS Record Type */
typedef enum {NO_MAC_SECRET_IN_RPTR = 0, RETURN_MAC_SECRET_IN_RPTR = 1} MacSecretReturn;
#endif

/*! \enum MasterSecretInput  Master secret location */
typedef enum {READ_FROM_CONTEXT = 0, INPUT_ENCRYPTED = 1} MasterSecretInput;

/*! \enum ClientFinishMessageOutput  predicted ClientFinished message format */
typedef enum {RETURN_CFM_ENCRYPTED = 0, RETURN_CFM_UNENCRYPTED = 1} ClientFinishMessageOutput;

/*! \enum ServerFinishMessageOutput  ServerFinished message format */
typedef enum {RETURN_SFM_ENCRYPTED = 0, RETURN_SFM_UNENCRYPTED = 1} ServerFinishMessageOutput;

#ifdef RFC_5746_SUPPORT
/*! \enum Encrypted and Unencrypted Cient and Server Finished message*/
typedef enum {NO_CFM_SFM_ENCRYTPED_UNENCRYPTED = 0, RETURN_CFM_SFM_ENCRYPTED_UNENCRYPTED = 1} ClientServerFinishMessageOutput;
#endif

/*! \enum SslPartyType server or client */
typedef enum {SSL_SERVER = 0, SSL_CLIENT = 1} SslPartyType;


/* SSLv2 specific Context Offsets */

#define OFFSET_SSL2_MASTER_SECRET            16

#define OFFSET_SSL2_3DES_SERVER_READ_SEQ     22
#define OFFSET_SSL2_3DES_SERVER_READ_KM      24
#define OFFSET_SSL2_3DES_SERVER_WRITE_SEQ    28
#define OFFSET_SSL2_3DES_SERVER_WRITE_KM     30

#define OFFSET_SSL2_RC4_SERVER_READ_SEQ      22
#define OFFSET_SSL2_RC4_SERVER_READ_KM       24
#define OFFSET_SSL2_RC4_SERVER_READ_STATE    26
#define OFFSET_SSL2_RC4_SERVER_WRITE_SEQ     60
#define OFFSET_SSL2_RC4_SERVER_WRITE_KM      62
#define OFFSET_SSL2_RC4_SERVER_WRITE_STATE   64


#ifdef USE_SSL_QUEUE1
#define SSL_QUEUE 1
#else
#define SSL_QUEUE 0
#endif

/*+****************************************************************************/
 /*! \ingroup MISC
 *
 * CspGetDmaMode
 *
 * Returns the current DMA mode
 *
 *
 * \retval CAVIUM_DIRECT, CAVIUM_SCATTER_GATHER #DmaMode
 */
 /*-***************************************************************************/
DmaMode
CspGetDmaMode(void);

DmaMode
Csp1GetDmaMode(void);


/*+****************************************************************************/
 /*! \ingroup MISC
 *
 * CspGetDriverState
 *
 * Function to check whether the driver handle is initialized or not.
 *
 * \param dev_id    Device ID
 *
 * \retval 0  driver handle is ready.
 * \retval -1 driver handle is not initialized
 */
 /*-***************************************************************************/
int
CspGetDriverState(Uint32 dev_id);
int
Csp1GetDriverState(void);

/*+****************************************************************************/
 /*! \ingroup SSL_OPS
 *
 * CspSetEncryptedMasterSecretKey
 *
 * Sets the key material for encryption of master secrets used by resume
 * operations.
 *
 * \param dev_id    Device ID
 *
 * \param     key pointer to 48 bytes of key material
 *
 * \retval SUCCESS 0
 * \retval FAILURE/PENDING #CspErrorCodes
 */
 /*-***************************************************************************/
Uint32 CspSetEncryptedMasterSecretKey(Uint8 *key,Uint32 dev_id);

Uint32 Csp1SetEncryptedMasterSecretKey(Uint8 *key);

#ifndef MC2

/*+****************************************************************************/
 /*! \ingroup SSL_OPS
 *
 * CspHandshake
 *
 * Calculates the hashes needed by the SSL handshake.
 *
 * \param request_type         CAVIUM_BLOCKING or CAVIUM_NON_BLOCKING #CspRequestType
 * \param context_handle    64-bit pointer to context (context_handle\%8=0)
 * \param message_length     size of input in bytes (0<=message_length<=2^16-1)
 * \param message         pointer to length bytes of input
 *
 * \param md5_final_hash     pointer to the 4-halfword handshake final result
 * \param sha1_final_hash     pointer to the 5-halfword handshake final result
 * \param request_id         Unique ID for this request
 *
 * \param dev_id    Device ID
 *
 * \retval SUCCESS 0
 * \retval FAILURE/PENDING #CspErrorCodes
 */
 /*-***************************************************************************/
Uint32
CspHandshake(CspRequestType request_type,
      Uint64 context_handle,
      Uint16 message_length,
      Uint8 *message,
      Uint8 *md5_final_hash,
      Uint8 *sha1_final_hash,
      Uint32 *request_id,Uint32 dev_id);

Uint32
Csp1Handshake(CspRequestType request_type,
      Uint64 context_handle,
      Uint16 message_length,
      Uint8 *message,
      Uint8 *md5_final_hash,
      Uint8 *sha1_final_hash,
      Uint32 *request_id);


/*+****************************************************************************/
 /*! \ingroup SSL_OPS
 *
 * CspHandshakeStart
 *
 * Calculates the partial hashes needed by the SSL handshake.
 *
 * \param request_type        CAVIUM_BLOCKING or CAVIUM_NON_BLOCKING #CspRequestType
 * \param context_handle    64-bit pointer to context (context_handle\%8=0)
 * \param message_length    size of input in bytes (0<=message_length<=2^16-1)
 * \param message        pointer to length bytes of input
 * \param request_id        Unique ID for this request
 *
 * \param dev_id    Device ID
 *
 * \retval SUCCESS 0
 * \retval FAILURE/PENDING #CspErrorCodes
 */
 /*-***************************************************************************/
Uint32
CspHandshakeStart(CspRequestType request_type,
           Uint64 context_handle,
           Uint16 message_length,
           Uint8 *message,
           Uint32 *request_id,Uint32 dev_id);

Uint32
Csp1HandshakeStart(CspRequestType request_type,
           Uint64 context_handle,
           Uint16 message_length,
           Uint8 *message,
           Uint32 *request_id);



/*+****************************************************************************/
 /*! \ingroup SSL_OPS
 *
 * CspHandshakeUpdate
 *
 * Calculates the partial hashes needed by the SSL handshake.
 *
 * \param request_type        CAVIUM_BLOCKING or CAVIUM_NON_BLOCKING
 * \param context_handle    64-bit pointer to context (context_handle\%8=0)
 * \param message_length    size of input in bytes (0<=message_length<=2^16-1)
 * \param message        pointer to length bytes of input
 * \param request_id        Unique ID for this request
 *
 * \param dev_id    Device ID
 *
 * \retval SUCCESS 0
 * \retval FAILURE/PENDING #CspErrorCodes
 */
 /*-***************************************************************************/
Uint32
CspHandshakeUpdate(n1_request_type request_type,
        Uint64 context_handle,
        Uint16 message_length,
        Uint8 *message,
        Uint32 *request_id,Uint32 dev_id);

Uint32
Csp1HandshakeUpdate(n1_request_type request_type,
        Uint64 context_handle,
        Uint16 message_length,
        Uint8 *message,
        Uint32 *request_id);


/*+****************************************************************************/
 /*! \ingroup SSL_OPS
 *
 * CspHandshakeFinish
 *
 * \param request_type        CAVIUM_BLOCKING or CAVIUM_NON_BLOCKING
 * \param context_handle    64-bit pointer to context (context_handle\%8=0)
 * \param message_length    size of input in bytes (0<=message_length<=2^16-1)
 * \param message        pointer to length bytes of input
 * \param md5_final_hash    pointer to the 4-word handshake final result
 * \param sha1_final_hash    pointer to the 5-word handshake final result
 * \param request_id        Unique ID for this request
 *
 * \param dev_id    Device ID
 *
 * \retval SUCCESS 0
 * \retval FAILURE/PENDING #CspErrorCodes
 */
 /*-***************************************************************************/
Uint32
CspHandshakeFinish(n1_request_type request_type,
        Uint64 context_handle,
        Uint16 message_length,
        Uint8 *message,
        Uint8 *md5_final_hash,
        Uint8 *sha1_final_hash,
                Uint32 *request_id,Uint32 dev_id);

Uint32
Csp1HandshakeFinish(n1_request_type request_type,
        Uint64 context_handle,
        Uint16 message_length,
        Uint8 *message,
        Uint8 *md5_final_hash,
        Uint8 *sha1_final_hash,
                Uint32 *request_id);


#endif /* MC2*/

/*+****************************************************************************/
 /*! \ingroup SSL_OPS
 *
 * CspRsaServerFullRc4
 *
 * Does a full handshake on the server with RSA <= 2048. This entry point
 * handles all the RC4 cases. The handshake message data for this request
 * should include all handshake message data after (and including) the client
 * hello message up until (but not including) the first finished message.
 *
 * \param request_type        CAVIUM_BLOCKING or CAVIUM_NON_BLOCKING
 * \param context_handle    64-bit byte-pointer to context (context_handle\%8=0)
 * \param key_handle        pointer to 64-bit key memory handle
 * \param hash_type        MD5_TYPE or SHA1_TYPE
 * \param ssl_version        VER3_0 or VER_TLS
 * \param rc4_type        RC4_128, RC4_EXPORT_40, or RC4_EXPORT_56
 * \param master_secret_ret    NOT_RETURNED or RETURN_ENCRYPTED
#ifdef MAC_SECRET_RETURN_SUPPORT
 * \param mac_secret_ret       NO_MAC_SECRET_IN_RPTR or RETURN_MAC_SECRET_IN_RPTR
#endif
 * \param modlength        size of RSA operation in bytes (64<=modlength<=256, modlength\%8=0)
 * \if MC2
 * \param encrypt_premaster_secret    pointer to modlength-byte value.
 * \else
 * \param encrypt_premaster_secret    pointer to modlength-byte value in integer format
 * \endif
 * \param client_random        pointer to 32 bytes of random data
 * \param server_random        pointer to 32 bytes of random data
 * \param handshake_length    size in bytes of the handshake message data
 * \param handshake        pointer to the handshake message data
 *
 * \param client_finished_message    pointer to encrypted part of client finished message
 * \param server_finished_message    pointer to encrypted part of server finished message
 * \param encrypt_master_secret    (master_secret_ret == RETURN_ENCRYPTED) ? pointer to
 *                        returned encrypted master secret : don't care
#ifdef MAC_SECRET_RETURN_SUPPORT
 * \param mac_secret    (mac_secret_ret == RETURN_MAC_SECRET_IN_RPTR) ? pointer to
 *                        return  mac secret : don't care
#endif
 * \param request_id    Unique ID for this request
 *
 * \param dev_id    Device ID
 *
 * \retval SUCCESS 0
 * \retval FAILURE/PENDING #CspErrorCodes
 */
 /*-***************************************************************************/
Uint32
CspRsaServerFullRc4(n1_request_type request_type,
         Uint64 context_handle,
         Uint64 *key_handle,
         HashType hash_type,
         SslVersion ssl_version,
         Rc4Type rc4_type,
         MasterSecretReturn master_secret_ret,
#ifdef MAC_SECRET_RETURN_SUPPORT
         MacSecretReturn mac_secret_ret,
#endif
#ifdef RC4_UNENC_FNSD_MSG_SUPPORT
         ClientFinishMessageOutput clnt_fin_msg_out,
         ServerFinishMessageOutput srvr_fin_msg_out,
#ifdef RFC_5746_SUPPORT
         ClientServerFinishMessageOutput clnt_srvr_fin_msg_out,
#endif
         Uint16 client_pad_length,
         Uint16 server_pad_length,
#endif
         Uint16 modlength,
         Uint8 *encrypt_premaster_secret,
         Uint8 *client_random,
         Uint8 *server_random,
#ifdef TLS12_SUPPORT
         Uint8 * write_seq_num,
         Uint8 * read_seq_num,
#endif
         Uint16 handshake_length,
         Uint8 *handshake,
         Uint8 *client_finished_message,
         Uint8 *server_finished_message,
#ifdef RFC_5746_SUPPORT
         Uint8 *unencrypted_client_finished_message,
         Uint8 *unencrypted_server_finished_message,
#endif
         Uint8 *encrypt_master_secret,
#ifdef MAC_SECRET_RETURN_SUPPORT
         Uint8 *mac_secret,
#endif
         Uint32 *request_id,Uint32 dev_id);

Uint32
Csp1RsaServerFullRc4(n1_request_type request_type,
         Uint64 context_handle,
         Uint64 *key_handle,
         HashType hash_type,
         SslVersion ssl_version,
         Rc4Type rc4_type,
         MasterSecretReturn master_secret_ret,
#ifdef MAC_SECRET_RETURN_SUPPORT
         MacSecretReturn mac_secret_ret,
#endif
#ifdef RC4_UNENC_FNSD_MSG_SUPPORT
         ClientFinishMessageOutput clnt_fin_msg_out,
         ServerFinishMessageOutput srvr_fin_msg_out,
#ifdef RFC_5746_SUPPORT
         ClientServerFinishMessageOutput clnt_srvr_fin_msg_out,
#endif
         Uint16 client_pad_length,
         Uint16 server_pad_length,
#endif
         Uint16 modlength,
         Uint8 *encrypt_premaster_secret,
         Uint8 *client_random,
         Uint8 *server_random,
#ifdef TLS12_SUPPORT
         Uint8 * write_seq_num,
         Uint8 * read_seq_num,
#endif
         Uint16 handshake_length,
         Uint8 *handshake,
         Uint8 *client_finished_message,
         Uint8 *server_finished_message,
#ifdef RFC_5746_SUPPORT
         Uint8 *unencrypted_client_finished_message,
         Uint8 *unencrypted_server_finished_message,
#endif
         Uint8 *encrypt_master_secret,
#ifdef MAC_SECRET_RETURN_SUPPORT
         Uint8 *mac_secret,
#endif
         Uint32 *request_id);


#ifndef MC2
/*+****************************************************************************/
 /*! \ingroup SSL_OPS
 *
 * CspRsaServerFullRc4Finish
 *
 * Does a full handshake on the server with RSA <= 2048. This entry point
 * handles all the RC4 cases. The handshake data is accumulated prior to this
 * request by calls to Handshake*, and this request appends the
 * included handshake message data to the pre-existing handshake hash state.
 * The handshake message data for this request (previously hashed plus included
 * messsage data) should include all handshake message data after (and
 * including) the client hello message up until (but not including) the first
 * finished message.
 *
 * \param request_type        CAVIUM_BLOCKING or CAVIUM_NON_BLOCKING
 * \param context_handle    64-bit byte-pointer to context (context_handle\%8=0)
 * \param key_handle        pointer to 64-bit key memory handle
 * \param hash_type        MD5_TYPE or SHA1_TYPE
 * \param ssl_version        VER3_0 or VER_TLS
 * \param rc4_type        RC4_128, RC4_EXPORT_40, or RC4_EXPORT_56
 * \param master_secret_ret    NOT_RETURNED or RETURN_ENCRYPTED
 * \param modlength        size of RSA operation in bytes (64<=modlength<=256, modlength\%8=0)
 * \param encrypt_premaster_secret    pointer to modlength-byte value in integer format
 * \param client_random        pointer to 32 bytes of random data
 * \param server_random        pointer to 32 bytes of random data
 * \param handshake_length    size in bytes of the handshake message data
 * \param handshake        pointer to the handshake message data
 *
 * \param client_finished_message    pointer to encrypted part of client finished message
 * \param server_finished_message    pointer to encrypted part of server finished message
 * \param encrypt_master_secret    (master_secret_ret == RETURN_ENCRYPTED) ? pointer to
 *                    returned encrypted master secret : don't care
 * \param request_id        Unique ID for this request
 *
 * \param dev_id    Device ID
 *
 * \retval SUCCESS 0
 * \retval FAILURE/PENDING #CspErrorCodes
 */
 /*-***************************************************************************/
Uint32
CspRsaServerFullRc4Finish(n1_request_type request_type,
               Uint64 context_handle,
               Uint64 *key_handle,
               HashType hash_type,
               SslVersion ssl_version,
               Rc4Type rc4_type,
               MasterSecretReturn master_secret_ret,
               Uint16 modlength,
               Uint8 *encrypt_premaster_secret,
               Uint8 *client_random,
               Uint8 *server_random,
               Uint16 handshake_length,
               Uint8 *handshake,
               Uint8 *client_finished_message,
               Uint8 *server_finished_message,
               Uint8 *encrypt_master_secret,
                           Uint32 *request_id,Uint32 dev_id);

Uint32
Csp1RsaServerFullRc4Finish(n1_request_type request_type,
               Uint64 context_handle,
               Uint64 *key_handle,
               HashType hash_type,
               SslVersion ssl_version,
               Rc4Type rc4_type,
               MasterSecretReturn master_secret_ret,
               Uint16 modlength,
               Uint8 *encrypt_premaster_secret,
               Uint8 *client_random,
               Uint8 *server_random,
               Uint16 handshake_length,
               Uint8 *handshake,
               Uint8 *client_finished_message,
               Uint8 *server_finished_message,
               Uint8 *encrypt_master_secret,
                           Uint32 *request_id);

#endif /* MC2*/

/*+****************************************************************************/
 /*! \ingroup SSL_OPS
 *
 * CspRsaServerVerifyRc4
 *
 * Do much of the full handshake - up to the point of the
 * verify - in the case when client authentication is required. This is used in
 * a full handshake on the server. This entry point handles all the RC4 cases.
 *
 * The handshake message data for this request should include all handshake
 * message data after (and including) the client hello message up until (but
 * not including) the client verify message.
 *
 * \param request_type        CAVIUM_BLOCKING or CAVIUM_NON_BLOCKING
 * \param context_handle    64-bit byte-pointer to context (context_handle\%8=0)
 * \param key_handle        pointer to 64-bit key memory handle
 * \param record_hash_type        MD5_TYPE or SHA1_TYPE
 * \param verify_hash_type      MD5_TYPE or SHA1_TYPE or SHA256_TYPE or SHA384_TYPE or SHA512_TYPE
 * \param ssl_version        VER3_0 or VER_TLS
 * \param rc4_type        RC4_128, RC4_EXPORT_40, or RC4_EXPORT_56
 * \param master_secret_ret    NOT_RETURNED or RETURN_ENCRYPTED
#ifdef MAC_SECRET_RETURN_SUPPORT
 * \param mac_secret_ret       NO_MAC_SECRET_IN_RPTR or RETURN_MAC_SECRET_IN_RPTR
#endif
 * \param modlength        size of RSA operation in bytes (64<=modlength<=256, modlength\%8=0)
 * \param encrypt_premaster_secret    pointer to modlength-byte value in integer format
 * \param client_random        pointer to 32 bytes of random data
 * \param server_random        pointer to 32 bytes of random data
 * \param handshake_length    size in bytes of the handshake message data
 * \param handshake        pointer to the handshake message data
 * \param verify_data        pointer to 36 bytes of verify data
 * \param encrypt_master_secret    (master_secret_ret == RETURN_ENCRYPTED) ? pointer to
 *                    returned encrypted master secret : don't care
#ifdef MAC_SECRET_RETURN_SUPPORT
 * \param mac_secret    (mac_secret_ret == RETURN_MAC_SECRET_IN_RPTR) ? pointer to
 *                        return  mac secret : don't care
#endif
 * \param request_id        Unique ID for this request
 *
 * \param dev_id    Device ID
 *
 * \retval SUCCESS 0
 * \retval FAILURE/PENDING #CspErrorCodes
 */
 /*-***************************************************************************/
Uint32
CspRsaServerVerifyRc4(n1_request_type request_type,
           Uint64 context_handle,
           Uint64 *key_handle,
           HashType record_hash_type,
#ifdef TLS12_SUPPORT
	   HashType verify_hash_type,
#endif
           SslVersion ssl_version,
           Rc4Type rc4_type,
           MasterSecretReturn master_secret_ret,
#ifdef MAC_SECRET_RETURN_SUPPORT
           MacSecretReturn mac_secret_ret,
#endif
           Uint16 modlength,
           Uint8 *encrypt_premaster_secret,
           Uint8 *client_random,
           Uint8 *server_random,
           Uint16 handshake_length,
           Uint8 *handshake,
           Uint8 *verify_data,
           Uint8 *encrypt_master_secret,
#ifdef MAC_SECRET_RETURN_SUPPORT
           Uint8 *mac_secret,
#endif
                   Uint32 *request_id,Uint32 dev_id);

Uint32
Csp1RsaServerVerifyRc4(n1_request_type request_type,
           Uint64 context_handle,
           Uint64 *key_handle,
           HashType record_hash_type,
#ifdef TLS12_SUPPORT
	   HashType verify_hash_type,
#endif
           SslVersion ssl_version,
           Rc4Type rc4_type,
           MasterSecretReturn master_secret_ret,
#ifdef MAC_SECRET_RETURN_SUPPORT
           MacSecretReturn mac_secret_ret,
#endif
           Uint16 modlength,
           Uint8 *encrypt_premaster_secret,
           Uint8 *client_random,
           Uint8 *server_random,
           Uint16 handshake_length,
           Uint8 *handshake,
           Uint8 *verify_data,
           Uint8 *encrypt_master_secret,
#ifdef MAC_SECRET_RETURN_SUPPORT
           Uint8 *mac_secret,
#endif
                   Uint32 *request_id);


#ifndef MC2
/*+****************************************************************************/
 /*! \ingroup SSL_OPS
 *
 * CspRsaServerVerifyRc4Finish
 *
 * Do much of the full handshake - up to the point of the
 * verify - in the case when client authentication is required. This is used in
 * a full handshake on the server. This entry point handles all the RC4 cases.
 *
 * Handshake data can be accumulated prior to this request by calls to
 * Handshake*, and this request will append the included handshake
 * message data to the pre-existing handshake hash state. The handshake message
 * data for this request (previously hashed plus included messsage data) should
 * include all handshake message data after (and including) the client hello
 * message up until (but not including) the client verify message.
 *
 * \param request_type        CAVIUM_BLOCKING or CAVIUM_NON_BLOCKING
 * \param context_handle    64-bit byte-pointer to context (context_handle\%8=0)
 * \param key_handle        pointer to 64-bit key memory handle
 * \param hash_type        MD5_TYPE or SHA1_TYPE
 * \param ssl_version        VER3_0 or VER_TLS
 * \param rc4_type        RC4_128, RC4_EXPORT_40, or RC4_EXPORT_56
 * \param master_secret_ret    NOT_RETURNED or RETURN_ENCRYPTED
 * \param modlength        size of RSA operation in bytes (64<=modlength<=256, modlength\%8=0)
 * \param encrypt_premaster_secret    pointer to modlength-byte value in integer format
 * \param client_random        pointer to 32 bytes of random data
 * \param server_random        pointer to 32 bytes of random data
 * \param handshake_length    size in bytes of the handshake message data
 * \param handshake        pointer to the handshake message data
 *
 * \param verify_data        pointer to 36 bytes of verify data
 * \param encrypt_master_secret    (master_secret_ret == RETURN_ENCRYPTED) ? pointer to
 *                    returned encrypted master secret : don't care
 * \param request_id        Unique ID for this request
 *
 * \param dev_id    Device ID
 *
 * \retval SUCCESS 0
 * \retval FAILURE/PENDING #CspErrorCodes
 */
 /*-***************************************************************************/
Uint32
CspRsaServerVerifyRc4Finish(n1_request_type request_type,
             Uint64 context_handle,
             Uint64 *key_handle,
             HashType hash_type,
             SslVersion ssl_version,
             Rc4Type rc4_type,
             MasterSecretReturn master_secret_ret,
             Uint16 modlength,
             Uint8 *encrypt_premaster_secret,
             Uint8 *client_random,
             Uint8 *server_random,
             Uint16 handshake_length,
             Uint8 *handshake,
             Uint8 *verify_data,
             Uint8 *encrypt_master_secret,
                         Uint32 *request_id,Uint32 dev_id);

Uint32
Csp1RsaServerVerifyRc4Finish(n1_request_type request_type,
             Uint64 context_handle,
             Uint64 *key_handle,
             HashType hash_type,
             SslVersion ssl_version,
             Rc4Type rc4_type,
             MasterSecretReturn master_secret_ret,
             Uint16 modlength,
             Uint8 *encrypt_premaster_secret,
             Uint8 *client_random,
             Uint8 *server_random,
             Uint16 handshake_length,
             Uint8 *handshake,
             Uint8 *verify_data,
             Uint8 *encrypt_master_secret,
                         Uint32 *request_id);


#endif

/*+****************************************************************************/
 /*! \ingroup SSL_OPS
 *
 * CspRsaServerFull3Des
 *
 * Does a full handshake on the server with RSA <= 2048. This entry point
 * handles all the DES cases. The handshake message data for this request
 * should include all handshake message data after (and including) the client
 * hello message up until (but not including) the first finished message.
 *
 * \param request_type        CAVIUM_BLOCKING or CAVIUM_NON_BLOCKING
 * \param context_handle    64-bit byte-pointer to context (context_handle\%8=0)
 * \param key_handle        pointer to 64-bit key memory handle
 * \param hash_type        MD5_TYPE or SHA1_TYPE
 * \param ssl_version        VER3_0 or VER_TLS
 * \param des_type        DES, DES_EXPORT_40 or DES3_192
 * \param master_secret_ret    NOT_RETURNED or RETURN_ENCRYPTED
#ifdef MAC_SECRET_RETURN_SUPPORT
 * \param mac_secret_ret       NO_MAC_SECRET_IN_RPTR or RETURN_MAC_SECRET_IN_RPTR
#endif
 * \param clnt_fin_msg_out    RETURN_CFM_ENCRYPTED or RETURN_CFM_UNENCRYPTED
 * \param srvr_fin_msg_out    RETURN_SFM_ENCRYPTED or RETURN_SFM_UNENCRYPTED
 * \param client_pad_length    number of 64-bit words to pad above min
 * \param server_pad_length    number of 64-bit words to pad above min
 * \param modlength        size of RSA operation in bytes (64<=modlength<=256, modlength\%8=0)
 * \if MC2
 * \param encrypt_premaster_secret    pointer to modlength-byte value.
 * \else
 * \param encrypt_premaster_secret    pointer to modlength-byte value in integer format
 * \endif
 * \param client_random        pointer to 32 bytes of random data
 * \param server_random        pointer to 32 bytes of random data
 * \param handshake_length    size in bytes of the handshake message data
 * \param handshake        pointer to the handshake message data
 *
 * \param client_finished_message    pointer to encrypted part of client finished message
 * \param server_finished_message    pointer to encrypted part of server finished message
 * \param encrypt_master_secret    (master_secret_ret == RETURN_ENCRYPTED) ? pointer to
 *                    returned encrypted master secret : don't care
#ifdef MAC_SECRET_RETURN_SUPPORT
 * \param mac_secret    (mac_secret_ret == RETURN_MAC_SECRET_IN_RPTR) ? pointer to
 *                        return  mac secret : don't care
#endif
 * \param request_id        Unique ID for this request
 *
 * \param dev_id    Device ID
 *
 * \retval SUCCESS 0
 * \retval FAILURE/PENDING #CspErrorCodes
 */
 /*-***************************************************************************/
Uint32
CspRsaServerFull3Des(n1_request_type request_type,
          Uint64 context_handle,
          Uint64 *key_handle,
          HashType hash_type,
          SslVersion ssl_version,
          DesType des_type,
          MasterSecretReturn master_secret_ret,
#ifdef MAC_SECRET_RETURN_SUPPORT
          MacSecretReturn mac_secret_ret,
#endif
          ClientFinishMessageOutput clnt_fin_msg_out,
          ServerFinishMessageOutput srvr_fin_msg_out,
#ifdef RFC_5746_SUPPORT
          ClientServerFinishMessageOutput clnt_srvr_fin_msg_out,
#endif
          Uint16 client_pad_length,
          Uint16 server_pad_length,
          Uint16 modlength,
          Uint8 *encrypt_premaster_secret,
          Uint8 *client_random,
          Uint8 *server_random,
#ifdef DTLS_SUPPORT
         Uint8 * handshake_write_seq_num,
         Uint8 * handshake_read_seq_num,
#endif
#if (defined(TLS12_SUPPORT) || (DTLS_SUPPORT))
          Uint8 * write_seq_num,
          Uint8 * write_iv,
          Uint8 * read_seq_num,
          Uint8 * read_iv,
#endif
          Uint16 handshake_length,
          Uint8 *handshake,
          Uint8 *client_finished_message,
          Uint8 *server_finished_message,
#ifdef RFC_5746_SUPPORT
         Uint8 *unencrypted_client_finished_message,
         Uint8 *unencrypted_server_finished_message,
#endif
          Uint8 *encrypt_master_secret,
#ifdef MAC_SECRET_RETURN_SUPPORT
          Uint8 *mac_secret,
#endif
          Uint32 *request_id,Uint32 dev_id);

Uint32
Csp1RsaServerFull3Des(n1_request_type request_type,
          Uint64 context_handle,
          Uint64 *key_handle,
          HashType hash_type,
          SslVersion ssl_version,
          DesType des_type,
          MasterSecretReturn master_secret_ret,
#ifdef MAC_SECRET_RETURN_SUPPORT
          MacSecretReturn mac_secret_ret,
#endif
          ClientFinishMessageOutput clnt_fin_msg_out,
          ServerFinishMessageOutput srvr_fin_msg_out,
#ifdef RFC_5746_SUPPORT
          ClientServerFinishMessageOutput clnt_srvr_fin_msg_out,
#endif
          Uint16 client_pad_length,
          Uint16 server_pad_length,
          Uint16 modlength,
          Uint8 *encrypt_premaster_secret,
          Uint8 *client_random,
          Uint8 *server_random,
#ifdef DTLS_SUPPORT
         Uint8 * handshake_write_seq_num,
         Uint8 * handshake_read_seq_num,
#endif
#if (defined(TLS12_SUPPORT) || (DTLS_SUPPORT))
          Uint8 * write_seq_num,
          Uint8 * write_iv,
          Uint8 * read_seq_num,
          Uint8 * read_iv,
#endif
          Uint16 handshake_length,
          Uint8 *handshake,
          Uint8 *client_finished_message,
          Uint8 *server_finished_message,
#ifdef RFC_5746_SUPPORT
         Uint8 *unencrypted_client_finished_message,
         Uint8 *unencrypted_server_finished_message,
#endif
          Uint8 *encrypt_master_secret,
#ifdef MAC_SECRET_RETURN_SUPPORT
          Uint8 *mac_secret,
#endif
                  Uint32 *request_id);


#ifndef MC2
/*+****************************************************************************/
 /*! \ingroup SSL_OPS
 *
 * CspRsaServerFull3DesFinish
 *
 * Does a full handshake on the server. This entry point
 * handles all the DES cases. The handshake data is accumulated prior to this
 * request by calls to Handshake*, and this request appends the
 * included handshake message data to the pre-existing handshake hash state.
 * The handshake message data for this request should include all handshake
 * message data after (and including) the client hello message up until
 * (but not including) the first finished message.
 *
 * \param request_type        CAVIUM_BLOCKING or CAVIUM_NON_BLOCKING
 * \param context_handle    64-bit byte-pointer to context (context_handle\%8=0)
 * \param key_handle        pointer to 64-bit key memory handle
 * \param hash_type        MD5_TYPE or SHA1_TYPE
 * \param ssl_version        VER3_0 or VER_TLS
 * \param des_type        DES, DES_EXPORT_40 or DES3_192
 * \param master_secret_ret    NOT_RETURNED or RETURN_ENCRYPTED
 * \param clnt_fin_msg_out    RETURN_CFM_ENCRYPTED or RETURN_CFM_UNENCRYPTED
 * \param srvr_fin_msg_out    RETURN_SFM_ENCRYPTED or RETURN_SFM_UNENCRYPTED
 * \param client_pad_length    number of 64-bit words to pad above min
 * \param server_pad_length    number of 64-bit words to pad above min
 * \param modlength        size of RSA operation in bytes (64<=modlength<=256, modlength\%8=0)
 * \if MC2
 * \param encrypt_premaster_secret    pointer to modlength-byte value.
 * \else
 * \param encrypt_premaster_secret    pointer to modlength-byte value in integer format
 * \endif
 * \param client_random        pointer to 32 bytes of random data
 * \param server_random        pointer to 32 bytes of random data
 * \param handshake_length    size in bytes of the handshake message data
 * \param handshake        pointer to the handshake message data
 *
 * \param client_finished_message    pointer to encrypted part of client finished message
 * \param server_finished_message    pointer to encrypted part of server finished message
 * \param encrypt_master_secret    (master_secret_ret == RETURN_ENCRYPTED) ? pointer to
 *                    returned encrypted master secret : don't care
 * \param request_id    Unique ID for this request
 *
 * \param dev_id    Device ID
 *
 * \retval SUCCESS 0
 * \retval FAILURE/PENDING #CspErrorCodes
 */
 /*-***************************************************************************/
Uint32
CspRsaServerFull3DesFinish(n1_request_type request_type,
            Uint64 context_handle,
                    Uint64 *key_handle,
            HashType hash_type,
            SslVersion ssl_version,
            DesType des_type,
            MasterSecretReturn master_secret_ret,
            ClientFinishMessageOutput clnt_fin_msg_out,
            ServerFinishMessageOutput srvr_fin_msg_out,
            Uint16 client_pad_length,
            Uint16 server_pad_length,
            Uint16 modlength,
            Uint8 *encrypt_premaster_secret,
            Uint8 *client_random,
            Uint8 *server_random,
            Uint16 handshake_length,
            Uint8 *handshake,
            Uint8 *client_finished_message,
            Uint8 *server_finished_message,
            Uint8 *encrypt_master_secret,
                        Uint32 *request_id,Uint32 dev_id);

Uint32
Csp1RsaServerFull3DesFinish(n1_request_type request_type,
            Uint64 context_handle,
                    Uint64 *key_handle,
            HashType hash_type,
            SslVersion ssl_version,
            DesType des_type,
            MasterSecretReturn master_secret_ret,
            ClientFinishMessageOutput clnt_fin_msg_out,
            ServerFinishMessageOutput srvr_fin_msg_out,
            Uint16 client_pad_length,
            Uint16 server_pad_length,
            Uint16 modlength,
            Uint8 *encrypt_premaster_secret,
            Uint8 *client_random,
            Uint8 *server_random,
            Uint16 handshake_length,
            Uint8 *handshake,
            Uint8 *client_finished_message,
            Uint8 *server_finished_message,
            Uint8 *encrypt_master_secret,
                        Uint32 *request_id);

#endif

/*+****************************************************************************/
 /*! \ingroup SSL_OPS
 *
 * CspRsaServerVerify3Des
 *
 * Do much of the full handshake - up to the point of the
 * verify - in the case when client authentication is required. This is used in
 * a full handshake on the server. This entry point handles all the DES/3DES
 * cases.
 *
 * The handshake message data for this request should include all handshake
 * message data after (and including) the client hello message up until (but
 * not including) the client verify message.
 *
 * \param request_type        CAVIUM_BLOCKING or CAVIUM_NON_BLOCKING
 * \param context_handle    64-bit byte-pointer to context (context_handle\%8=0)
 * \param key_handle        pointer to 64-bit key memory handle
 * \param record_hash_type        MD5_TYPE or SHA1_TYPE
 * \param verify_hash_type      MD5_TYPE or SHA1_TYPE or SHA256_TYPE or SHA384_TYPE or SHA512_TYPE
 * \param ssl_version        VER3_0 or VER_TLS
 * \param des_type        DES, DES_EXPORT_40, DES3_192
 * \param master_secret_ret    NOT_RETURNED or RETURN_ENCRYPTED
#ifdef MAC_SECRET_RETURN_SUPPORT
 * \param mac_secret_ret       NO_MAC_SECRET_IN_RPTR or RETURN_MAC_SECRET_IN_RPTR
#endif
 * \param modlength        size of RSA operation in bytes (64<=modlength<=256, modlength\%8=0)
 * \if MC2
 * \param encrypt_premaster_secret    pointer to modlength-byte value
 * \else
 * \param encrypt_premaster_secret    pointer to modlength-byte value in integer format
 * \endif
 * \param client_random        pointer to 32 bytes of random data
 * \param server_random        pointer to 32 bytes of random data
 * \param handshake_length    size in bytes of the handshake message data
 * \param handshake        pointer to the handshake message data
 *
 * \param verify_data        pointer to 36 bytes of verify data
 * \param encrypt_master_secret    (master_secret_ret == RETURN_ENCRYPTED) ? pointer to
 *                    returned encrypted master secret : don't care
#ifdef MAC_SECRET_RETURN_SUPPORT
 * \param mac_secret    (mac_secret_ret == RETURN_MAC_SECRET_IN_RPTR) ? pointer to
 *                        return  mac secret : don't care
#endif
 * \param request_id        Unique ID for this request
 *
 * \param dev_id    Device ID
 *
 * \retval SUCCESS 0
 * \retval FAILURE/PENDING #CspErrorCodes
 */
 /*-***************************************************************************/
Uint32
CspRsaServerVerify3Des(n1_request_type request_type,
            Uint64 context_handle,
            Uint64 *key_handle,
            HashType record_hash_type,
#ifdef TLS12_SUPPORT
	   HashType verify_hash_type,
#endif
            SslVersion ssl_version,
            DesType des_type,
            MasterSecretReturn master_secret_ret,
#ifdef MAC_SECRET_RETURN_SUPPORT
            MacSecretReturn mac_secret_ret,
#endif
            Uint16 modlength,
            Uint8 *encrypt_premaster_secret,
            Uint8 *client_random,
            Uint8 *server_random,
            Uint16 handshake_length,
            Uint8 *handshake,
            Uint8 *verify_data,
            Uint8 *encrypt_master_secret,
#ifdef MAC_SECRET_RETURN_SUPPORT
            Uint8 *mac_secret,
#endif
                        Uint32 *request_id,Uint32 dev_id);

Uint32
Csp1RsaServerVerify3Des(n1_request_type request_type,
            Uint64 context_handle,
            Uint64 *key_handle,
            HashType record_hash_type,
#ifdef TLS12_SUPPORT
	   HashType verify_hash_type,
#endif
            SslVersion ssl_version,
            DesType des_type,
            MasterSecretReturn master_secret_ret,
#ifdef MAC_SECRET_RETURN_SUPPORT
            MacSecretReturn mac_secret_ret,
#endif
            Uint16 modlength,
            Uint8 *encrypt_premaster_secret,
            Uint8 *client_random,
            Uint8 *server_random,
            Uint16 handshake_length,
            Uint8 *handshake,
            Uint8 *verify_data,
            Uint8 *encrypt_master_secret,
#ifdef MAC_SECRET_RETURN_SUPPORT
            Uint8 *mac_secret,
#endif
                        Uint32 *request_id);


#ifndef MC2
/*+****************************************************************************/
 /*! \ingroup SSL_OPS
 *
 * CspRsaServerVerify3DesFinish
 *
 * Do much of the full handshake - up to the point of the
 * verify - in the case when client authentication is required. This is used in
 * a full handshake on the server. This entry point handles all the DES/3DES
 * cases.
 *
 * The handshake message data for this request should include all handshake
 * message data after (and including) the client hello message up until (but not
 * including) the client verify message. Handshake data can be accumulated prior
 * to this request by calls to Handshake*, and this request will append
 * the included handshake message data to the pre-existing handshake hash state.
 *
 * \param request_type        CAVIUM_BLOCKING or CAVIUM_NON_BLOCKING
 * \param context_handle    64-bit byte-pointer to context (context_handle\%8=0)
 * \param key_handle        pointer to 64-bit key memory handle
 * \param hash_type        MD5_TYPE or SHA1_TYPE
 * \param ssl_version        VER3_0 or VER_TLS
 * \param des_type        DES, DES_EXPORT_40 or DES3_192
 * \param master_secret_ret    NOT_RETURNED or RETURN_ENCRYPTED
 * \param modlength    size of RSA operation in bytes (64<=modlength<=256, modlength\%8=0)
 * \param encrypt_premaster_secret    pointer to modlength-byte value in integer format
 * \param client_random        pointer to 32 bytes of random data
 * \param server_random        pointer to 32 bytes of random data
 * \param handshake_length    size in bytes of the handshake message data
 * \param handshake        pointer to the handshake message data
 *
 * \param verify_data        pointer to 36 bytes of verify data
 * \param encrypt_master_secret    (master_secret_ret == RETURN_ENCRYPTED) ? pointer to
 *                    returned encrypted master secret : don't care
 * \param request_id        Unique ID for this request
 *
 * \param dev_id    Device ID
 *
 * \retval SUCCESS 0
 * \retval FAILURE/PENDING #CspErrorCodes
 */
 /*-***************************************************************************/
Uint32
CspRsaServerVerify3DesFinish(n1_request_type request_type,
              Uint64 context_handle,
              Uint64 *key_handle,
              HashType hash_type,
              SslVersion ssl_version,
              DesType des_type,
              MasterSecretReturn master_secret_ret,
              Uint16 modlength,
              Uint8 *encrypt_premaster_secret,
              Uint8 *client_random,
              Uint8 *server_random,
              Uint16 handshake_length,
              Uint8 *handshake,
              Uint8 *verify_data,
              Uint8 *encrypt_master_secret,
                          Uint32 *request_id,Uint32 dev_id);

Uint32
Csp1RsaServerVerify3DesFinish(n1_request_type request_type,
              Uint64 context_handle,
              Uint64 *key_handle,
              HashType hash_type,
              SslVersion ssl_version,
              DesType des_type,
              MasterSecretReturn master_secret_ret,
              Uint16 modlength,
              Uint8 *encrypt_premaster_secret,
              Uint8 *client_random,
              Uint8 *server_random,
              Uint16 handshake_length,
              Uint8 *handshake,
              Uint8 *verify_data,
              Uint8 *encrypt_master_secret,
                          Uint32 *request_id);


#endif

/*+****************************************************************************/
 /*! \ingroup SSL_OPS
 *
 * CspRsaServerFullAes
 *
 * Does a full handshake on the server. This entry point
 * handles all the AES cases. The handshake message data for this request
 * should include all handshake message data after (and including) the client
 * hello message up until (but not including) the first finished message.
 *
 * \param request_type        CAVIUM_BLOCKING or CAVIUM_NON_BLOCKING
 * \param context_handle    64-bit byte-pointer to context (context_handle\%8=0)
 * \param key_handle        pointer to 64-bit key memory handle
 * \param hash_type        MD5_TYPE or SHA1_TYPE
 * \param ssl_version        VER3_0 or VER_TLS
 * \param aes_type        AES_128 or AES_256
 * \param master_secret_ret    NOT_RETURNED or RETURN_ENCRYPTED
#ifdef MAC_SECRET_RETURN_SUPPORT
 * \param mac_secret_ret       NO_MAC_SECRET_IN_RPTR or RETURN_MAC_SECRET_IN_RPTR
#endif
 * \param clnt_fin_msg_out    RETURN_CFM_ENCRYPTED or RETURN_CFM_UNENCRYPTED
 * \param srvr_fin_msg_out    RETURN_SFM_ENCRYPTED or RETURN_SFM_UNENCRYPTED
 * \param client_pad_length    number of 128-bit words to pad above min
 * \param server_pad_length    number of 128-bit words to pad above min
 * \param modlength        size of RSA operation in bytes (64<=modlength<=256, modlength\%8=0)
 * \if MC2
 * \param encrypt_premaster_secret    pointer to modlength-byte value.
 * \else
 * \param encrypt_premaster_secret    pointer to modlength-byte value in integer format
 * \endif
 * \param client_random        pointer to 32 bytes of random data
 * \param server_random        pointer to 32 bytes of random data
 * \param handshake_length    size in bytes of the handshake message data
 * \param handshake        pointer to the handshake message data
 *
 * \param client_finished_message    pointer to encrypted part of client finished message
 * \param server_finished_message    pointer to encrypted part of server finished message
 * \param encrypt_master_secret    (master_secret_ret == RETURN_ENCRYPTED) ? pointer to
 *                    returned encrypted master secret : don't care
#ifdef MAC_SECRET_RETURN_SUPPORT
 * \param mac_secret    (mac_secret_ret == RETURN_MAC_SECRET_IN_RPTR) ? pointer to
 *                        return  mac secret : don't care
#endif
 * \param request_id    Unique ID for this request
 *
 * \param dev_id    Device ID
 *
 * \retval SUCCESS 0
 * \retval FAILURE/PENDING #CspErrorCodes
 */
 /*-***************************************************************************/
Uint32
CspRsaServerFullAes(n1_request_type request_type,
         Uint64 context_handle,
         Uint64 *key_handle,
         HashType hash_type,
         SslVersion ssl_version,
         AesType aes_type,
         MasterSecretReturn master_secret_ret,
#ifdef MAC_SECRET_RETURN_SUPPORT
         MacSecretReturn mac_secret_ret,
#endif
         ClientFinishMessageOutput clnt_fin_msg_out,
         ServerFinishMessageOutput srvr_fin_msg_out,
#ifdef RFC_5746_SUPPORT
         ClientServerFinishMessageOutput clnt_srvr_fin_msg_out,
#endif
         Uint16 client_pad_length,
         Uint16 server_pad_length,
         Uint16 modlength,
         Uint8 *encrypt_premaster_secret,
         Uint8 *client_random,
         Uint8 *server_random,
#ifdef DTLS_SUPPORT
         Uint8 * handshake_write_seq_num,
         Uint8 * handshake_read_seq_num,
#endif
#if (defined(TLS12_SUPPORT) || (DTLS_SUPPORT))
         Uint8 * write_seq_num,
         Uint8 * write_iv,
         Uint8 * read_seq_num,
         Uint8 * read_iv,
#endif
         Uint16 handshake_length,
         Uint8 *handshake,
         Uint8 *client_finished_message,
         Uint8 *server_finished_message,
#ifdef RFC_5746_SUPPORT
         Uint8 *unencrypted_client_finished_message,
         Uint8 *unencrypted_server_finished_message,
#endif
         Uint8 *encrypt_master_secret,
#ifdef MAC_SECRET_RETURN_SUPPORT
         Uint8 *mac_secret,
#endif
         Uint32 *request_id,Uint32 dev_id);

Uint32
Csp1RsaServerFullAes(n1_request_type request_type,
         Uint64 context_handle,
         Uint64 *key_handle,
         HashType hash_type,
         SslVersion ssl_version,
         AesType aes_type,
         MasterSecretReturn master_secret_ret,
#ifdef MAC_SECRET_RETURN_SUPPORT
         MacSecretReturn mac_secret_ret,
#endif
         ClientFinishMessageOutput clnt_fin_msg_out,
         ServerFinishMessageOutput srvr_fin_msg_out,
#ifdef RFC_5746_SUPPORT
         ClientServerFinishMessageOutput clnt_srvr_fin_msg_out,
#endif
         Uint16 client_pad_length,
         Uint16 server_pad_length,
         Uint16 modlength,
         Uint8 *encrypt_premaster_secret,
         Uint8 *client_random,
         Uint8 *server_random,
#ifdef DTLS_SUPPORT
         Uint8 * handshake_write_seq_num,
         Uint8 * handshake_read_seq_num,
#endif
#if (defined(TLS12_SUPPORT) || (DTLS_SUPPORT))
         Uint8 * write_seq_num,
         Uint8 * write_iv,
         Uint8 * read_seq_num,
         Uint8 * read_iv,
#endif
         Uint16 handshake_length,
         Uint8 *handshake,
         Uint8 *client_finished_message,
         Uint8 *server_finished_message,
#ifdef RFC_5746_SUPPORT
         Uint8 *unencrypted_client_finished_message,
         Uint8 *unencrypted_server_finished_message,
#endif
         Uint8 *encrypt_master_secret,
#ifdef MAC_SECRET_RETURN_SUPPORT
         Uint8 *mac_secret,
#endif
         Uint32 *request_id);



#ifndef MC2
/*+****************************************************************************/
 /*! \ingroup SSL_OPS
 *
 * CspRsaServerFullAesFinish
 *
 * Does a full handshake on the server. This entry point
 * handles all the aes cases. The handshake data is accumulated prior to this
 * request by calls to Handshake*, and this request appends the
 * included handshake message data to the pre-existing handshake hash state.
 * The handshake message data for this request should include all handshake
 * message data after (and including) the client hello message up until
 * (but not including) the first finished message.
 *
 * \param request_type        CAVIUM_BLOCKING or CAVIUM_NON_BLOCKING
 * \param context_handle    64-bit byte-pointer to context (context_handle\%8=0)
 * \param key_handle        pointer to 64-bit key memory handle
 * \param hash_type        MD5_TYPE or SHA1_TYPE
 * \param ssl_version        VER3_0 or VER_TLS
 * \param aes_type        AES_128 or AES_256
 * \param master_secret_ret    NOT_RETURNED or RETURN_ENCRYPTED
 * \param clnt_fin_msg_out    RETURN_CFM_ENCRYPTED or RETURN_CFM_UNENCRYPTED
 * \param srvr_fin_msg_out    RETURN_SFM_ENCRYPTED or RETURN_SFM_UNENCRYPTED
 * \param client_pad_length    number of 128-bit words to pad above min
 * \param server_pad_length    number of 128-bit words to pad above min
 * \param modlength        size of RSA operation in bytes (64<=modlength<=256, modlength\%8=0)
 * \param encrypt_premaster_secret    pointer to modlength-byte value in integer format
 * \param client_random        pointer to 32 bytes of random data
 * \param server_random        pointer to 32 bytes of random data
 * \param handshake_length    size in bytes of the handshake message data
 * \param handshake        pointer to the handshake message data
 *
 * \param client_finished_message    pointer to encrypted part of client finished message
 * \param server_finished_message    pointer to encrypted part of server finished message
 * \param encrypt_master_secret    (master_secret_ret == RETURN_ENCRYPTED) ? pointer to
 *                    returned encrypted master secret : don't care
 * \param request_id    Unique ID for this request
 *
 * \param dev_id    Device ID
 *
 * \retval SUCCESS 0
 * \retval FAILURE/PENDING #CspErrorCodes
 */
 /*-***************************************************************************/
Uint32
CspRsaServerFullAesFinish(n1_request_type request_type,
               Uint64 context_handle,
               Uint64 *key_handle,
               HashType hash_type,
               SslVersion ssl_version,
               AesType aes_type,
               MasterSecretReturn master_secret_ret,
               ClientFinishMessageOutput clnt_fin_msg_out,
               ServerFinishMessageOutput srvr_fin_msg_out,
               Uint16 client_pad_length,
               Uint16 server_pad_length,
               Uint16 modlength,
               Uint8 *encrypt_premaster_secret,
               Uint8 *client_random,
               Uint8 *server_random,
               Uint16 handshake_length,
               Uint8 *handshake,
               Uint8 *client_finished_message,
               Uint8 *server_finished_message,
               Uint8 *encrypt_master_secret,
                           Uint32 *request_id,Uint32 dev_id);

Uint32
Csp1RsaServerFullAesFinish(n1_request_type request_type,
               Uint64 context_handle,
               Uint64 *key_handle,
               HashType hash_type,
               SslVersion ssl_version,
               AesType aes_type,
               MasterSecretReturn master_secret_ret,
               ClientFinishMessageOutput clnt_fin_msg_out,
               ServerFinishMessageOutput srvr_fin_msg_out,
               Uint16 client_pad_length,
               Uint16 server_pad_length,
               Uint16 modlength,
               Uint8 *encrypt_premaster_secret,
               Uint8 *client_random,
               Uint8 *server_random,
               Uint16 handshake_length,
               Uint8 *handshake,
               Uint8 *client_finished_message,
               Uint8 *server_finished_message,
               Uint8 *encrypt_master_secret,
                           Uint32 *request_id,Uint32 dev_id);
#endif

/*+****************************************************************************/
 /*! \ingroup SSL_OPS
 *
 * CspRsaServerVerifyAes
 *
 * Do much of the full handshake - up to the point of the
 * verify - in the case when client authentication is required. This is used in
 * a full handshake on the server. This entry point handles all the AES cases.
 *
 * The handshake message data for this request should include all handshake
 * message data after (and including) the client hello message up until (but
 * not including) the client verify message.
 *
 * \param request_type        CAVIUM_BLOCKING or CAVIUM_NON_BLOCKING
 * \param context_handle    64-bit byte-pointer to context (context_handle\%8=0)
 * \param key_handle        pointer to 64-bit key memory handle
 * \param hash_type        MD5_TYPE or SHA1_TYPE
 * \param verify_hash_type  MD5_TYPE of SHA1_TYPE or SHA224_TYPE or SHA256_TYPE or SHA384_TYPE or SHA512_TYPE
 * \param ssl_version        VER3_0 or VER_TLS
 * \param aes_type        AES_128 or AES_256
 * \param master_secret_ret    NOT_RETURNED or RETURN_ENCRYPTED
#ifdef MAC_SECRET_RETURN_SUPPORT
 * \param mac_secret_ret       NO_MAC_SECRET_IN_RPTR or RETURN_MAC_SECRET_IN_RPTR
#endif
 * \param modlength        size of RSA operation in bytes (64<=modlength<=256, modlength\%8=0)
 * \if MC2
 * \param encrypt_premaster_secret    pointer to modlength-byte value.
 * \else
 * \param encrypt_premaster_secret    pointer to modlength-byte value in integer format
 * \endif
 * \param client_random        pointer to 32 bytes of random data
 * \param server_random        pointer to 32 bytes of random data
 * \param handshake_length    size in bytes of the handshake message data
 * \param handshake        pointer to the handshake message data
 *
 * \param verify_data        pointer to 36 bytes of verify data
 * \param encrypt_master_secret    (master_secret_ret == RETURN_ENCRYPTED) ? pointer to
 *                    returned encrypted master secret : don't care
#ifdef MAC_SECRET_RETURN_SUPPORT
 * \param mac_secret    (mac_secret_ret == RETURN_MAC_SECRET_IN_RPTR) ? pointer to
 *                        return  mac secret : don't care
#endif
 * \param request_id        Unique ID for this request
 *
 * \param dev_id    Device ID
 *
 * \retval SUCCESS 0
 * \retval FAILURE/PENDING #CspErrorCodes
 */
 /*-***************************************************************************/
Uint32
CspRsaServerVerifyAes(n1_request_type request_type,
           Uint64 context_handle,
           Uint64 *key_handle,
           HashType record_hash_type,
#ifdef TLS12_SUPPORT
	   HashType verify_hash_type,
#endif
           SslVersion ssl_version,
           AesType aes_type,
           MasterSecretReturn master_secret_ret,
#ifdef MAC_SECRET_RETURN_SUPPORT
           MacSecretReturn mac_secret_ret,
#endif
           Uint16 modlength,
           Uint8 *encrypt_premaster_secret,
           Uint8 *client_random,
           Uint8 *server_random,
           Uint16 handshake_length,
           Uint8 *handshake,
           Uint8 *verify_data,
           Uint8 *encrypt_master_secret,
#ifdef MAC_SECRET_RETURN_SUPPORT
           Uint8 *mac_secret,
#endif
                   Uint32 *request_id,Uint32 dev_id);

Uint32
Csp1RsaServerVerifyAes(n1_request_type request_type,
           Uint64 context_handle,
           Uint64 *key_handle,
           HashType record_hash_type,
#ifdef TLS12_SUPPORT
	   HashType verify_hash_type,
#endif
           SslVersion ssl_version,
           AesType aes_type,
           MasterSecretReturn master_secret_ret,
#ifdef MAC_SECRET_RETURN_SUPPORT
           MacSecretReturn mac_secret_ret,
#endif
           Uint16 modlength,
           Uint8 *encrypt_premaster_secret,
           Uint8 *client_random,
           Uint8 *server_random,
           Uint16 handshake_length,
           Uint8 *handshake,
           Uint8 *verify_data,
           Uint8 *encrypt_master_secret,
#ifdef MAC_SECRET_RETURN_SUPPORT
           Uint8 *mac_secret,
#endif
                   Uint32 *request_id);



#ifndef MC2
/*+****************************************************************************/
 /*! \ingroup SSL_OPS
 *
 * CspRsaServerVerifyAesFinish
 *
 * Do much of the full handshake - up to the point of the
 * verify - in the case when client authentication is required. This is used in
 * a full handshake on the server. This entry point handles all the AES cases.
 *
 * The handshake message data for this request should include all handshake
 * message data after (and including) the client hello message up until (but
 * not including) the client verify message. Handshake data can be accumulated
 * prior to this request by calls to Handshake*, and this request will
 * append the included handshake message data to the pre-existing handshake
 * hash state.
 *
 * \param request_type        CAVIUM_BLOCKING or CAVIUM_NON_BLOCKING
 * \param context_handle    64-bit byte-pointer to context (context_handle\%8=0)
 * \param key_handle        pointer to 64-bit key memory handle
 * \param hash_type        MD5_TYPE or SHA1_TYPE
 * \param ssl_version        VER3_0 or VER_TLS
 * \param aes_type        AES_128 or AES_256
 * \param master_secret_ret    NOT_RETURNED or RETURN_ENCRYPTED
 * \param modlength        size of RSA operation in bytes (64<=modlength<=256, modlength\%8=0)
 * \param encrypt_premaster_secret    pointer to modlength-byte value in integer format
 * \param client_random        pointer to 32 bytes of random data
 * \param server_random        pointer to 32 bytes of random data
 * \param handshake_length    size in bytes of the handshake message data
 * \param handshake        pointer to the handshake message data
 *
 * \param verify_data        pointer to 36 bytes of verify data
 * \param encrypt_master_secret    (master_secret_ret == RETURN_ENCRYPTED) ? pointer to
 *                    returned encrypted master secret : don't care
 * \param request_id        Unique ID for this request
 *
 * \param dev_id    Device ID
 *
 * \retval SUCCESS 0
 * \retval FAILURE/PENDING #CspErrorCodes
 */
 /*-***************************************************************************/
Uint32
CspRsaServerVerifyAesFinish(n1_request_type request_type,
             Uint64 context_handle,
             Uint64 *key_handle,
             HashType hash_type,
             SslVersion ssl_version,
             AesType aes_type,
             MasterSecretReturn master_secret_ret,
             Uint16 modlength,
             Uint8 *encrypt_premaster_secret,
             Uint8 *client_random,
             Uint8 *server_random,
             Uint16 handshake_length,
             Uint8 *handshake,
             Uint8 *verify_data,
             Uint8 *encrypt_master_secret,
                         Uint32 *request_id,Uint32 dev_id);

Uint32
Csp1RsaServerVerifyAesFinish(n1_request_type request_type,
             Uint64 context_handle,
             Uint64 *key_handle,
             HashType hash_type,
             SslVersion ssl_version,
             AesType aes_type,
             MasterSecretReturn master_secret_ret,
             Uint16 modlength,
             Uint8 *encrypt_premaster_secret,
             Uint8 *client_random,
             Uint8 *server_random,
             Uint16 handshake_length,
             Uint8 *handshake,
             Uint8 *verify_data,
             Uint8 *encrypt_master_secret,
                         Uint32 *request_id);

#endif


/*+****************************************************************************/
 /*! \ingroup SSL_OPS
 *
 * CspOtherFullRc4
 *
 * Do a full handshake without RSA operation. The pre-master secret is read
 * from the context and the rest of the handshake is completed. This is used
 * by both the server and the client. This entry point handles all the RC4
 * cases.
 *
 * The handshake message data for this request should include all handshake
 * message data after (and including) the client hello message up until (but
 * not including) the first finished message.
 *
 * \param request_type        CAVIUM_BLOCKING or CAVIUM_NON_BLOCKING
 * \param context_handle    64-bit pointer to context (context_handle\%8=0)
 * \param hash_type        MD5_TYPE or SHA1_TYPE
 * \param ssl_version        VER3_0 or VER_TLS
 * \param rc4_type        RC4_128, RC4_EXPORT_40, or RC4_EXPORT_56
 * \param master_secret_ret    NOT_RETURNED or RETURN_ENCRYPTED
#ifdef MAC_SECRET_RETURN_SUPPORT
 * \param mac_secret_ret       NO_MAC_SECRET_IN_RPTR or RETURN_MAC_SECRET_IN_RPTR
#endif
 * \param pre_master_length    size of premaster secret in bytes
 *                (SSLv3: 4<=modlength<=256, modlength\%4=0;
 *                 TLS: 16<=modlength<=128, modlength\%16=0)
 * \param client_random        pointer to 32 bytes of random data
 * \param server_random        pointer to 32 bytes of random data
 * \param handshake_length    size in bytes of the handshake message data
 * \param handshake        pointer to the handshake message data
 *
 * \param client_finished_message    pointer to encrypted part of client finished message
 * \param server_finished_message    pointer to encrypted part of server finished message
 * \param encrypt_master_secret    (master_secret_ret == RETURN_ENCRYPTED) ? pointer to
 *                    returned encrypted master secret : don't care
#ifdef MAC_SECRET_RETURN_SUPPORT
 * \param mac_secret    (mac_secret_ret == RETURN_MAC_SECRET_IN_RPTR) ? pointer to
 *                        return  mac secret : don't care
#endif
 * \param request_id        Unique ID for this request
 *
 * \param dev_id    Device ID
 *
 * \retval SUCCESS 0
 * \retval FAILURE/PENDING #CspErrorCodes
 */
 /*-***************************************************************************/
Uint32
CspOtherFullRc4(n1_request_type request_type,
         Uint64 context_handle,
         HashType hash_type,
         SslVersion ssl_version,
         Rc4Type rc4_type,
         MasterSecretReturn master_secret_ret,
#ifdef MAC_SECRET_RETURN_SUPPORT
         MacSecretReturn mac_secret_ret,
#endif
#ifdef RC4_UNENC_FNSD_MSG_SUPPORT
         ClientFinishMessageOutput clnt_fin_msg_out,
         ServerFinishMessageOutput srvr_fin_msg_out,
#ifdef RFC_5746_SUPPORT
         ClientServerFinishMessageOutput clnt_srvr_fin_msg_out,
#endif
         Uint16 client_pad_length,
         Uint16 server_pad_length,
#endif
         Uint16 pre_master_length,
         Uint8 *client_random,
         Uint8 *server_random,
#ifdef TLS12_SUPPORT
         Uint8 * write_seq_num,
         Uint8 * read_seq_num,
#endif
         Uint16 handshake_length,
         Uint8 *handshake,
         Uint8 *client_finished_message,
         Uint8 *server_finished_message,
#ifdef RFC_5746_SUPPORT
         Uint8 *unencrypted_client_finished_message,
         Uint8 *unencrypted_server_finished_message,
#endif
         Uint8 *encrypt_master_secret,
#ifdef MAC_SECRET_RETURN_SUPPORT
         Uint8 *mac_secret,
#endif
                 Uint32 *request_id,Uint32 dev_id);

Uint32
Csp1OtherFullRc4(n1_request_type request_type,
         Uint64 context_handle,
         HashType hash_type,
         SslVersion ssl_version,
         Rc4Type rc4_type,
         MasterSecretReturn master_secret_ret,
#ifdef MAC_SECRET_RETURN_SUPPORT
         MacSecretReturn mac_secret_ret,
#endif
#ifdef RC4_UNENC_FNSD_MSG_SUPPORT
         ClientFinishMessageOutput clnt_fin_msg_out,
         ServerFinishMessageOutput srvr_fin_msg_out,
#ifdef RFC_5746_SUPPORT
         ClientServerFinishMessageOutput clnt_srvr_fin_msg_out,
#endif
         Uint16 client_pad_length,
         Uint16 server_pad_length,
#endif
         Uint16 pre_master_length,
         Uint8 *client_random,
         Uint8 *server_random,
#ifdef TLS12_SUPPORT
         Uint8 * write_seq_num,
         Uint8 * read_seq_num,
#endif
         Uint16 handshake_length,
         Uint8 *handshake,
         Uint8 *client_finished_message,
         Uint8 *server_finished_message,
#ifdef RFC_5746_SUPPORT
         Uint8 *unencrypted_client_finished_message,
         Uint8 *unencrypted_server_finished_message,
#endif
         Uint8 *encrypt_master_secret,
#ifdef MAC_SECRET_RETURN_SUPPORT
         Uint8 * mac_secret,
#endif
                 Uint32 *request_id);



#ifndef MC2
/*+****************************************************************************/
 /*! \ingroup SSL_OPS
 *
 * CspOtherFullRc4Finish
 *
 * Do a full handshake without RSA operation. The pre-master secret is read
 * from the context and the rest of the handshake is completed. This is used
 * by both the server and the client. This entry point handles all the rc4
 * cases.
 *
 * The handshake message data for this request should include all handshake
 * message data after (and including) the client hello message up until (but
 * not including) the first finished message. Handshake data can be accumulated
 * prior to this request by calls to Handshake*, and this request will
 * append the included handshake message data to the pre-existing handshake
 * hash state.
 *
 * \param request_type        CAVIUM_BLOCKING or CAVIUM_NON_BLOCKING
 * \param context_handle    64-bit pointer to context (context_handle\%8=0)
 * \param hash_type        MD5_TYPE or SHA1_TYPE
 * \param ssl_version        VER3_0 or VER_TLS
 * \param rc4_type        RC4_128, RC4_EXPORT_40, or RC4_EXPORT_56
 * \param master_secret_ret    NOT_RETURNED or RETURN_ENCRYPTED
 * \param pre_master_length    size of premaster secret in bytes
 *                (SSLv3: 4<=modlength<=256, modlength\%4=0;
 *                 TLS: 16<=modlength<=128, modlength\%16=0)
 * \param client_random        pointer to 32 bytes of random data
 * \param server_random        pointer to 32 bytes of random data
 * \param handshake_length    size in bytes of the handshake message data
 * \param handshake        pointer to the handshake message data
 *
 * \param client_finished_message    pointer to encrypted part of client finished message
 * \param server_finished_message    pointer to encrypted part of server finished message
 * \param encrypt_master_secret    (master_secret_ret == RETURN_ENCRYPTED) ? pointer to
 *                    returned encrypted master secret : don't care
 * \param request_id        Unique ID for this request
 *
 * \param dev_id    Device ID
 *
 * \retval SUCCESS 0
 * \retval FAILURE/PENDING #CspErrorCodes
 */
 /*-***************************************************************************/
Uint32
CspOtherFullRc4Finish(n1_request_type request_type,
           Uint64 context_handle,
           HashType hash_type,
           SslVersion ssl_version,
           Rc4Type rc4_type,
           MasterSecretReturn master_secret_ret,
           Uint16 pre_master_length,
           Uint8 *client_random,
           Uint8 *server_random,
           Uint16 handshake_length,
           Uint8 *handshake,
           Uint8 *client_finished_message,
           Uint8 *server_finished_message,
           Uint8 *encrypt_master_secret,
                   Uint32 *request_id,Uint32 dev_id);

Uint32
Csp1OtherFullRc4Finish(n1_request_type request_type,
           Uint64 context_handle,
           HashType hash_type,
           SslVersion ssl_version,
           Rc4Type rc4_type,
           MasterSecretReturn master_secret_ret,
           Uint16 pre_master_length,
           Uint8 *client_random,
           Uint8 *server_random,
           Uint16 handshake_length,
           Uint8 *handshake,
           Uint8 *client_finished_message,
           Uint8 *server_finished_message,
           Uint8 *encrypt_master_secret,
                   Uint32 *request_id);


#endif

/*+****************************************************************************/
 /*! \ingroup SSL_OPS
 *
 * CspOtherVerifyRc4
 *
 * Do a full handshake - up to the point of the
 * verify operation. The pre-master secret is read from the context.
 * This is used by both the server and the client. This entry point
 * handles all the RC4 cases.
 *
 * The handshake message data for this request should include all handshake
 * message data after (and including) the client hello message up until (but
 * not including) the client verify message.
 *
 * \param request_type        CAVIUM_BLOCKING or CAVIUM_NON_BLOCKING
 * \param context_handle    64-bit pointer to context (context_handle\%8=0)
 * \param record_hash_type        MD5_TYPE or SHA1_TYPE
 * \param verify_hash      MD5_TYPE or SHA1_TYPE or SHA256_TYPE or SHA384_TYPE or SHA512_TYPE
 * \param ssl_version        VER3_0 or VER_TLS
 * \param rc4_type        RC4_128, RC4_EXPORT_40, or RC4_EXPORT_56
 * \param master_secret_ret    NOT_RETURNED or RETURN_ENCRYPTED
#ifdef MAC_SECRET_RETURN_SUPPORT
 * \param mac_secret_ret       NO_MAC_SECRET_IN_RPTR or RETURN_MAC_SECRET_IN_RPTR
#endif
 * \param pre_master_length    size of premaster secret in bytes
 *                (SSLv3: 4<=modlength<=256, modlength\%4=0;
 *                 TLS: 16<=modlength<=128, modlength\%16=0)
 * \param client_random        pointer to 32 bytes of random data
 * \param server_random        pointer to 32 bytes of random data
 * \param handshake_length    size in bytes of the handshake message data
 * \param handshake        pointer to the handshake message data
 *
 * \param verify_data        pointer to 36 bytes of verify data
 * \param encrypt_master_secret    (master_secret_ret == RETURN_ENCRYPTED) ? pointer to
 *                    returned encrypted master secret : don't care
#ifdef MAC_SECRET_RETURN_SUPPORT
 * \param mac_secret    (mac_secret_ret == RETURN_MAC_SECRET_IN_RPTR) ? pointer to
 *                        return  mac secret : don't care
#endif
 * \param request_id        Unique ID for this request
 *
 * \param dev_id    Device ID
 *
 * \retval SUCCESS 0
 * \retval FAILURE/PENDING #CspErrorCodes
 */
 /*-***************************************************************************/
Uint32
CspOtherVerifyRc4(n1_request_type request_type,
          Uint64 context_handle,
          HashType record_hash_type,
#ifdef TLS12_SUPPORT
	  HashType verify_hash_type,
#endif
          SslVersion ssl_version,
          Rc4Type rc4_type,
          MasterSecretReturn master_secret_ret,
#ifdef MAC_SECRET_RETURN_SUPPORT
          MacSecretReturn mac_secret_ret,
#endif
          Uint16 pre_master_length,
          Uint8 *client_random,
          Uint8 *server_random,
          Uint16 handshake_length,
          Uint8 *handshake,
          Uint8 *verify_data,
          Uint8 *encrypt_master_secret,
#ifdef MAC_SECRET_RETURN_SUPPORT
          Uint8 *mac_secret,
#endif
                  Uint32 *request_id,Uint32 dev_id);

Uint32
Csp1OtherVerifyRc4(n1_request_type request_type,
          Uint64 context_handle,
          HashType record_hash_type,
#ifdef TLS12_SUPPORT
	  HashType verify_hash_type,
#endif
          SslVersion ssl_version,
          Rc4Type rc4_type,
          MasterSecretReturn master_secret_ret,
#ifdef MAC_SECRET_RETURN_SUPPORT
          MacSecretReturn mac_secret_ret,
#endif
          Uint16 pre_master_length,
          Uint8 *client_random,
          Uint8 *server_random,
          Uint16 handshake_length,
          Uint8 *handshake,
          Uint8 *verify_data,
          Uint8 *encrypt_master_secret,
#ifdef MAC_SECRET_RETURN_SUPPORT
          Uint8 *mac_secret,
#endif
                  Uint32 *request_id);



#ifndef MC2
/*+****************************************************************************/
 /*! \ingroup SSL_OPS
 *
 * CspOtherVerifyRc4Finish
 *
 * Do a full handshake - up to the point of the
 * verify operation. The pre-master secret is read from the context.
 * This is used by both the server and the client. This entry point
 * handles all the rc4 cases.
 *
 * The handshake message data for this request should include all handshake message
 * data after (and including) the client hello message up until (but not
 * including) the client verify message. Handshake data can be accumulated prior
 * to this request by calls to Handshake*, and this request will append
 * the included handshake message data to the pre-existing handshake hash state.
 *
 * \param request_type        CAVIUM_BLOCKING or CAVIUM_NON_BLOCKING
 * \param context_handle    64-bit pointer to context (context_handle\%8=0)
 * \param hash_type        MD5_TYPE or SHA1_TYPE
 * \param ssl_version        VER3_0 or VER_TLS
 * \param rc4_type        RC4_128, RC4_EXPORT_40, or RC4_EXPORT_56
 * \param master_secret_ret    NOT_RETURNED or RETURN_ENCRYPTED
 * \param pre_master_length    size of premaster secret in bytes
 *                (SSLv3: 4<=modlength<=256, modlength\%4=0;
 *                 TLS: 16<=modlength<=128, modlength\%16=0)
 * \param client_random        pointer to 32 bytes of random data
 * \param server_random        pointer to 32 bytes of random data
 * \param handshake_length    size in bytes of the handshake message data
 * \param handshake        pointer to the handshake message data
 *
 * \param verify_data        pointer to 36 bytes of verify data
 * \param encrypt_master_secret    (master_secret_ret == RETURN_ENCRYPTED) ? pointer to
 *                    returned encrypted master secret : don't care
 * \param request_id        Unique ID for this request
 *
 * \param dev_id    Device ID
 *
 * \retval SUCCESS 0
 * \retval FAILURE/PENDING #CspErrorCodes
 */
 /*-***************************************************************************/
Uint32
CspOtherVerifyRc4Finish(n1_request_type request_type,
             Uint64 context_handle,
             HashType hash_type,
             SslVersion ssl_version,
             Rc4Type rc4_type,
             MasterSecretReturn master_secret_ret,
             Uint16 pre_master_length,
             Uint8 *client_random,
             Uint8 *server_random,
             Uint16 handshake_length,
             Uint8 *handshake,
             Uint8 *verify_data,
             Uint8 *encrypt_master_secret,
                         Uint32 *request_id,Uint32 dev_id);

Uint32
Csp1OtherVerifyRc4Finish(n1_request_type request_type,
             Uint64 context_handle,
             HashType hash_type,
             SslVersion ssl_version,
             Rc4Type rc4_type,
             MasterSecretReturn master_secret_ret,
             Uint16 pre_master_length,
             Uint8 *client_random,
             Uint8 *server_random,
             Uint16 handshake_length,
             Uint8 *handshake,
             Uint8 *verify_data,
             Uint8 *encrypt_master_secret,
                         Uint32 *request_id);

#endif


/*+****************************************************************************/
 /*! \ingroup SSL_OPS
 *
 * CspOtherFull3Des
 *
 * Do a full handshake. The pre-master secret is read
 * from the context and the rest of the handshake is completed. This is used
 * by both the server and the client. This entry point handles all the DES/
 * 3DES cases.
 *
 * The handshake message data for this request should include all handshake
 * message data after (and including) the client hello message up until (but
 * not including) the first finished message.
 *
 * \param request_type        CAVIUM_BLOCKING or CAVIUM_NON_BLOCKING
 * \param context_handle    64-bit pointer to context (context_handle\%8=0)
 * \param hash_type        MD5_TYPE or SHA1_TYPE
 * \param ssl_version        VER3_0 or VER_TLS
 * \param des_type        DES, DES_EXPORT_40 or DES3_192
 * \param master_secret_ret    NOT_RETURNED or RETURN_ENCRYPTED
#ifdef MAC_SECRET_RETURN_SUPPORT
 * \param mac_secret_ret       NO_MAC_SECRET_IN_RPTR or RETURN_MAC_SECRET_IN_RPTR
#endif
 * \param clnt_fin_msg_out    RETURN_CFM_ENCRYPTED or RETURN_CFM_UNENCRYPTED
 * \param srvr_fin_msg_out    RETURN_SFM_ENCRYPTED or RETURN_SFM_UNENCRYPTED
 * \param client_pad_length    number of 64-bit words to pad above min
 * \param server_pad_length    number of 64-bit words to pad above min
 * \param pre_master_length    size of premaster secret in bytes
 *                 (SSLv3: 4<=modlength<=256, modlength\%4=0;
 *                  TLS: 16<=modlength<=128, modlength\%16=0)
 * \param client_random        pointer to 32 bytes of random data
 * \param server_random        pointer to 32 bytes of random data
 * \param handshake_length    size in bytes of the handshake message data
 * \param handshake        pointer to the handshake message data
 *
 * \param client_finished_message    pointer to encrypted part of client finished message
 * \param server_finished_message    pointer to encrypted part of server finished message
 * \param encrypt_master_secret    (master_secret_ret == RETURN_ENCRYPTED) ? pointer to
 *                    returned encrypted master secret : don't care
#ifdef MAC_SECRET_RETURN_SUPPORT
 * \param mac_secret    (mac_secret_ret == RETURN_MAC_SECRET_IN_RPTR) ? pointer to
 *                        return  mac secret : don't care
#endif
 * \param request_id        Unique ID for this request
 *
 * \param dev_id    Device ID
 *
 * \retval SUCCESS 0
 * \retval FAILURE/PENDING #CspErrorCodes
 */
 /*-***************************************************************************/
Uint32
CspOtherFull3Des(n1_request_type request_type,
          Uint64 context_handle,
          HashType hash_type,
          SslVersion ssl_version,
          DesType des_type,
          MasterSecretReturn master_secret_ret,
#ifdef MAC_SECRET_RETURN_SUPPORT
          MacSecretReturn mac_secret_ret,
#endif
          ClientFinishMessageOutput clnt_fin_msg_out,
          ServerFinishMessageOutput srvr_fin_msg_out,
#ifdef RFC_5746_SUPPORT
          ClientServerFinishMessageOutput clnt_srvr_fin_msg_out,
#endif
          Uint16 client_pad_length,
          Uint16 server_pad_length,
          Uint16 pre_master_length,
          Uint8 *client_random,
          Uint8 *server_random,
#ifdef DTLS_SUPPORT
          Uint8 * handshake_write_seq_num,
          Uint8 * handshake_read_seq_num,
#endif
#if (defined(TLS12_SUPPORT) || (DTLS_SUPPORT))
          Uint8 * write_seq_num,
          Uint8 * write_iv,
          Uint8 * read_seq_num,
          Uint8 * read_iv,
#endif
          Uint16 handshake_length,
          Uint8 *handshake,
          Uint8 *client_finished_message,
          Uint8 *server_finished_message,
#ifdef RFC_5746_SUPPORT
          Uint8 *unencrypted_client_finished_message,
          Uint8 *unencrypted_server_finished_message,
#endif
          Uint8 *encrypt_master_secret,
#ifdef MAC_SECRET_RETURN_SUPPORT
          Uint8 *mac_secret,
#endif
          Uint32 *request_id,Uint32 dev_id);

Uint32
Csp1OtherFull3Des(n1_request_type request_type,
          Uint64 context_handle,
          HashType hash_type,
          SslVersion ssl_version,
          DesType des_type,
          MasterSecretReturn master_secret_ret,
#ifdef MAC_SECRET_RETURN_SUPPORT
          MacSecretReturn mac_secret_ret,
#endif
          ClientFinishMessageOutput clnt_fin_msg_out,
          ServerFinishMessageOutput srvr_fin_msg_out,
#ifdef RFC_5746_SUPPORT
          ClientServerFinishMessageOutput clnt_srvr_fin_msg_out,
#endif
          Uint16 client_pad_length,
          Uint16 server_pad_length,
          Uint16 pre_master_length,
          Uint8 *client_random,
          Uint8 *server_random,
#ifdef DTLS_SUPPORT
          Uint8 * handshake_write_seq_num,
          Uint8 * handshake_read_seq_num,
#endif
#if (defined(TLS12_SUPPORT) || (DTLS_SUPPORT))
          Uint8 * write_seq_num,
          Uint8 * write_iv,
          Uint8 * read_seq_num,
          Uint8 * read_iv,
#endif
          Uint16 handshake_length,
          Uint8 *handshake,
          Uint8 *client_finished_message,
          Uint8 *server_finished_message,
#ifdef RFC_5746_SUPPORT
          Uint8 *unencrypted_client_finished_message,
          Uint8 *unencrypted_server_finished_message,
#endif
          Uint8 *encrypt_master_secret,
#ifdef MAC_SECRET_RETURN_SUPPORT
          Uint8 *mac_secret,
#endif
                  Uint32 *request_id);



#ifndef MC2
/*+****************************************************************************/
 /*! \ingroup SSL_OPS
 *
 * CspOtherFull3DesFinish
 *
 * Do a full handshake. The pre-master secret is read
 * from the context and the rest of the handshake is completed. This is used
 * by both the server and the client. This entry point handles all the DES/
 * 3DES cases.
 *
 * The handshake message data for this request should include all handshake
 * message data after (and including) the client hello message up until (but
 * not including) the first finished message. Handshake data can be accumulated
 * prior to this request by calls to Handshake*, and this request will
 * append the included handshake message data to the pre-existing handshake
 * hash state.
 *
 * \param request_type        CAVIUM_BLOCKING or CAVIUM_NON_BLOCKING
 * \param context_handle    64-bit pointer to context (context_handle\%8=0)
 * \param hash_type        MD5_TYPE or SHA1_TYPE
 * \param ssl_version        VER3_0 or VER_TLS
 * \param des_type        DES, DES_EXPORT_40 or DES3_192
 * \param master_secret_ret    NOT_RETURNED or RETURN_ENCRYPTED
 * \param clnt_fin_msg_out    RETURN_CFM_ENCRYPTED or RETURN_CFM_UNENCRYPTED
 * \param srvr_fin_msg_out    RETURN_SFM_ENCRYPTED or RETURN_SFM_UNENCRYPTED
 * \param client_pad_length    number of 64-bit words to pad above min
 * \param server_pad_length    number of 64-bit words to pad above min
 * \param pre_master_length    size of premaster secret in bytes
 *                (SSLv3: 4<=modlength<=256, modlength\%4=0;
 *                 TLS: 16<=modlength<=128, modlength\%16=0)
 * \param client_random        pointer to 32 bytes of random data
 * \param server_random        pointer to 32 bytes of random data
 * \param handshake_length    size in bytes of the handshake message data
 * \param handshake        pointer to the handshake message data
 *
 * \param client_finished_message    pointer to encrypted part of client finished message
 * \param server_finished_message    pointer to encrypted part of server finished message
 * \param encrypt_master_secret    (master_secret_ret == RETURN_ENCRYPTED) ? pointer to
 *                returned encrypted master secret : don't care
 * \param request_id        Unique ID for this request
 *
 * \param dev_id    Device ID
 *
 * \retval SUCCESS 0
 * \retval FAILURE/PENDING #CspErrorCodes
 */
 /*-***************************************************************************/
Uint32
CspOtherFull3DesFinish(n1_request_type request_type,
            Uint64 context_handle,
            HashType hash_type,
            SslVersion ssl_version,
            DesType des_type,
            MasterSecretReturn master_secret_ret,
            ClientFinishMessageOutput clnt_fin_msg_out,
            ServerFinishMessageOutput srvr_fin_msg_out,
            Uint16 client_pad_length,
            Uint16 server_pad_length,
            Uint16 pre_master_length,
            Uint8 *client_random,
            Uint8 *server_random,
            Uint16 handshake_length,
            Uint8 *handshake,
            Uint8 *client_finished_message,
            Uint8 *server_finished_message,
            Uint8 *encrypt_master_secret,
                        Uint32 *request_id,Uint32 dev_id);

Uint32
Csp1OtherFull3DesFinish(n1_request_type request_type,
            Uint64 context_handle,
            HashType hash_type,
            SslVersion ssl_version,
            DesType des_type,
            MasterSecretReturn master_secret_ret,
            ClientFinishMessageOutput clnt_fin_msg_out,
            ServerFinishMessageOutput srvr_fin_msg_out,
            Uint16 client_pad_length,
            Uint16 server_pad_length,
            Uint16 pre_master_length,
            Uint8 *client_random,
            Uint8 *server_random,
            Uint16 handshake_length,
            Uint8 *handshake,
            Uint8 *client_finished_message,
            Uint8 *server_finished_message,
            Uint8 *encrypt_master_secret,
                        Uint32 *request_id);

#endif


/*+****************************************************************************/
 /*! \ingroup SSL_OPS
 *
 * CspOtherVerify3Des
 *
 * do a full handshake - up to the point of the
 * verify operation. The pre-master secret is read from the context.
 * This is used by both the server and the client. This entry point handles all
 * the DES/3DES cases.
 *
 * The handshake message data for this request should include all handshake
 * message data after (and including) the client hello message up until (but
 * not including) the client verify message.
 *
 * \param request_type    CAVIUM_BLOCKING or CAVIUM_NON_BLOCKING
 * \param context_handle    64-bit pointer to context (context_handle\%8=0)
 * \param record_hash_type    MD5_TYPE or SHA1_TYPE
 * \param verify_hash_type      MD5_TYPE or SHA1_TYPE or SHA256_TYPE or SHA384_TYPE or SHA512_TYPE
 * \param ssl_version    VER3_0 or VER_TLS
 * \param des_type    DES, DES_EXPORT_40, DES3_192
 * \param master_secret_ret    NOT_RETURNED or RETURN_ENCRYPTED
#ifdef MAC_SECRET_RETURN_SUPPORT
 * \param mac_secret_ret       NO_MAC_SECRET_IN_RPTR or RETURN_MAC_SECRET_IN_RPTR
#endif
 * \param pre_master_length    size of premaster secret in bytes
 *            (SSLv3: 4<=modlength<=256, modlength\%4=0;
 *             TLS: 16<=modlength<=128, modlength\%16=0)
 * \param client_random    pointer to 32 bytes of random data
 * \param server_random    pointer to 32 bytes of random data
 * \param handshake_length    size in bytes of the handshake message data
 * \param handshake    pointer to the handshake message data
 *
 * \param verify_data    pointer to 36 bytes of verify data
 * \param encrypt_master_secret    (master_secret_ret == RETURN_ENCRYPTED) ? pointer to
 *        returned encrypted master secret : don't care
#ifdef MAC_SECRET_RETURN_SUPPORT
 * \param mac_secret    (mac_secret_ret == RETURN_MAC_SECRET_IN_RPTR) ? pointer to
 *                        return  mac secret : don't care
#endif
 * \param request_id    Unique ID for this request
 *
 * \param dev_id    Device ID
 *
 * \retval SUCCESS 0
 * \retval FAILURE/PENDING #CspErrorCodes
 */
 /*-***************************************************************************/
Uint32
CspOtherVerify3Des(n1_request_type request_type,
                Uint64 context_handle,
                    HashType record_hash_type,
#ifdef TLS12_SUPPORT
                    HashType verify_hash_type,
#endif
                    SslVersion ssl_version,
                    DesType des_type,
                    MasterSecretReturn master_secret_ret,
#ifdef MAC_SECRET_RETURN_SUPPORT
         	    MacSecretReturn mac_secret_ret,
#endif
                    Uint16 pre_master_length,
                    Uint8 *client_random,
                    Uint8 *server_random,
                    Uint16 handshake_length,
                    Uint8 *handshake,
                    Uint8 *verify_data,
                    Uint8 *encrypt_master_secret,
#ifdef MAC_SECRET_RETURN_SUPPORT
         	    Uint8 *mac_secret,
#endif
                    Uint32 *request_id,Uint32 dev_id);

Uint32
Csp1OtherVerify3Des(n1_request_type request_type,
                    Uint64 context_handle,
                    HashType record_hash_type,
#ifdef TLS12_SUPPORT
                    HashType verify_hash_type,
#endif
                    SslVersion ssl_version,
                    DesType des_type,
                    MasterSecretReturn master_secret_ret,
#ifdef MAC_SECRET_RETURN_SUPPORT
         	    MacSecretReturn mac_secret_ret,
#endif
                    Uint16 pre_master_length,
                    Uint8 *client_random,
                    Uint8 *server_random,
                    Uint16 handshake_length,
                    Uint8 *handshake,
                    Uint8 *verify_data,
                    Uint8 *encrypt_master_secret,
#ifdef MAC_SECRET_RETURN_SUPPORT
                    Uint8 *mac_secret,
#endif
                    Uint32 *request_id);



#ifndef MC2
/*+****************************************************************************/
 /*! \ingroup SSL_OPS
 *
 * CspOtherVerify3DesFinish
 *
 * do a full handshake - up to the point of the
 * verify operation. The pre-master secret is read from the context.
 * This is used by both the server and the client. This entry point handles all
 * the DES/3DES cases.
 *
 * The handshake message data for this request should include all handshake
 * message data after (and including) the client hello message up until (but
 * not including) the client verify message. Handshake data can be accumulated
 * prior to this request by calls to Handshake*, and this request will
 * append the included handshake message data to the pre-existing handshake
 * hash state.
 *
 * \param request_type    CAVIUM_BLOCKING or CAVIUM_NON_BLOCKING
 * \param context_handle 64-bit pointer to context (context_handle\%8=0)
 * \param hash_type    MD5_TYPE or SHA1_TYPE
 * \param ssl_version    VER3_0 or VER_TLS
 * \param des_type    DES, DES_EXPORT_40 or DES3_192
 * \param master_secret_ret    NOT_RETURNED or RETURN_ENCRYPTED
 * \param pre_master_length    size of premaster secret in bytes
 *            (SSLv3: 4<=modlength<=256, modlength\%4=0;
 *             TLS: 16<=modlength<=128, modlength\%16=0)
 * \param client_random        pointer to 32 bytes of random data
 * \param server_random        pointer to 32 bytes of random data
 * \param handshake_length    size in bytes of the handshake message data
 * \param handshake    pointer to the handshake message data
 *
 * \param verify_data    pointer to 36 bytes of verify data
 * \param encrypt_master_secret    (master_secret_ret == RETURN_ENCRYPTED) ? pointer to
 *        returned encrypted master secret : don't care
 * \param request_id    Unique ID for this request
 *
 * \param dev_id    Device ID
 *
 * \retval SUCCESS 0
 * \retval FAILURE/PENDING #CspErrorCodes
 */
 /*-***************************************************************************/
Uint32
CspOtherVerify3DesFinish(n1_request_type request_type,
                          Uint64 context_handle,
                          HashType hash_type,
                          SslVersion ssl_version,
                          DesType des_type,
                          MasterSecretReturn master_secret_ret,
                          Uint16 pre_master_length,
                          Uint8 *client_random,
                          Uint8 *server_random,
                          Uint16 handshake_length,
                          Uint8 *handshake,
                          Uint8 *verify_data,
                          Uint8 *encrypt_master_secret,
                          Uint32 *request_id,Uint32 dev_id);

Uint32
Csp1OtherVerify3DesFinish(n1_request_type request_type,
                          Uint64 context_handle,
                          HashType hash_type,
                          SslVersion ssl_version,
                          DesType des_type,
                          MasterSecretReturn master_secret_ret,
                          Uint16 pre_master_length,
                          Uint8 *client_random,
                          Uint8 *server_random,
                          Uint16 handshake_length,
                          Uint8 *handshake,
                          Uint8 *verify_data,
                          Uint8 *encrypt_master_secret,
                          Uint32 *request_id);

#endif


/*+****************************************************************************/
 /*! \ingroup SSL_OPS
 *
 * CspOtherFullAes
 *
 * Do a full handshake. The pre-master secret is read
 * from the context and the rest of the handshake is completed. This is used
 * by both the server and the client. This entry point handles all the
 * AES cases.
 *
 * The handshake message data for this request should include all handshake
 * message data after (and including) the client hello message up until (but
 * not including) the first finished message.
 *
 * \param request_type    CAVIUM_BLOCKING or CAVIUM_NON_BLOCKING
 * \param context_handle    64-bit pointer to context (context_handle\%8=0)
 * \param hash_type    MD5_TYPE or SHA1_TYPE
 * \param ssl_version    VER3_0 or VER_TLS
 * \param aes_type    AES_128 or AES_256
 * \param master_secret_ret    NOT_RETURNED or RETURN_ENCRYPTED
#ifdef MAC_SECRET_RETURN_SUPPORT
 * \param mac_secret_ret       NO_MAC_SECRET_IN_RPTR or RETURN_MAC_SECRET_IN_RPTR
#endif
 * \param clnt_fin_msg_out    RETURN_CFM_ENCRYPTED or RETURN_CFM_UNENCRYPTED
 * \param srvr_fin_msg_out    RETURN_SFM_ENCRYPTED or RETURN_SFM_UNENCRYPTED
 * \param client_pad_length    number of 128-bit words to pad above min
 * \param server_pad_length    number of 128-bit words to pad above min
 * \param pre_master_length    size of premaster secret in bytes
 *            (SSLv3: 4<=modlength<=256, modlength\%4=0;
 *             TLS: 16<=modlength<=128, modlength\%16=0)
 * \param client_random    pointer to 32 bytes of random data
 * \param server_random    pointer to 32 bytes of random data
 * \param handshake_length    size in bytes of the handshake message data
 * \param handshake    pointer to the handshake message data
 *
 * \param client_finished_message    pointer to encrypted part of client finished message
 * \param server_finished_message    pointer to encrypted part of server finished message
 * \param encrypt_master_secret    (master_secret_ret == RETURN_ENCRYPTED) ? pointer to
 *        returned encrypted master secret : don't care
#ifdef MAC_SECRET_RETURN_SUPPORT
 * \param mac_secret    (mac_secret_ret == RETURN_MAC_SECRET_IN_RPTR) ? pointer to
 *                        return  mac secret : don't care
#endif
 * \param request_id    Unique ID for this request
 *
 * \param dev_id    Device ID
 *
 * \retval SUCCESS 0
 * \retval FAILURE/PENDING #CspErrorCodes
 */
 /*-***************************************************************************/
Uint32
CspOtherFullAes(n1_request_type request_type,
                 Uint64 context_handle,
                 HashType hash_type,
                 SslVersion ssl_version,
                 AesType aes_type,
                 MasterSecretReturn master_secret_ret,
#ifdef MAC_SECRET_RETURN_SUPPORT
         	 MacSecretReturn mac_secret_ret,
#endif
                 ClientFinishMessageOutput clnt_fin_msg_out,
                 ServerFinishMessageOutput srvr_fin_msg_out,
#ifdef RFC_5746_SUPPORT
                 ClientServerFinishMessageOutput clnt_srvr_fin_msg_out,
#endif
                 Uint16 client_pad_length,
                 Uint16 server_pad_length,
                 Uint16 pre_master_length,
                 Uint8 *client_random,
                 Uint8 *server_random,
#ifdef DTLS_SUPPORT
                 Uint8 * handshake_write_seq_num,
                 Uint8 * handshake_read_seq_num,
#endif
#if (defined(TLS12_SUPPORT) || (DTLS_SUPPORT))
                 Uint8 * write_seq_num,
                 Uint8 * write_iv,
                 Uint8 * read_seq_num,
                 Uint8 * read_iv,
#endif
                 Uint16 handshake_length,
                 Uint8 *handshake,
                 Uint8 *client_finished_message,
                 Uint8 *server_finished_message,
#ifdef RFC_5746_SUPPORT
                 Uint8 *unencrypted_client_finished_message,
                 Uint8 *unencrypted_server_finished_message,
#endif
                 Uint8 *encrypt_master_secret,
#ifdef MAC_SECRET_RETURN_SUPPORT
                 Uint8 *mac_secret,
#endif
                 Uint32 *request_id,Uint32 dev_id);

Uint32
Csp1OtherFullAes(n1_request_type request_type,
                 Uint64 context_handle,
                 HashType hash_type,
                 SslVersion ssl_version,
                 AesType aes_type,
                 MasterSecretReturn master_secret_ret,
#ifdef MAC_SECRET_RETURN_SUPPORT
         	 MacSecretReturn mac_secret_ret,
#endif
                 ClientFinishMessageOutput clnt_fin_msg_out,
                 ServerFinishMessageOutput srvr_fin_msg_out,
#ifdef RFC_5746_SUPPORT
                 ClientServerFinishMessageOutput clnt_srvr_fin_msg_out,
#endif
                 Uint16 client_pad_length,
                 Uint16 server_pad_length,
                 Uint16 pre_master_length,
                 Uint8 *client_random,
                 Uint8 *server_random,
#ifdef DTLS_SUPPORT
                 Uint8 * handshake_write_seq_num,
                 Uint8 * handshake_read_seq_num,
#endif
#if (defined(TLS12_SUPPORT) || (DTLS_SUPPORT))
                 Uint8 * write_seq_num,
                 Uint8 * write_iv,
                 Uint8 * read_seq_num,
                 Uint8 * read_iv,
#endif
                 Uint16 handshake_length,
                 Uint8 *handshake,
                 Uint8 *client_finished_message,
                 Uint8 *server_finished_message,
#ifdef RFC_5746_SUPPORT
                 Uint8 *unencrypted_client_finished_message,
                 Uint8 *unencrypted_server_finished_message,
#endif
                 Uint8 *encrypt_master_secret,
#ifdef MAC_SECRET_RETURN_SUPPORT
                 Uint8 *mac_secret,
#endif
                 Uint32 *request_id);



#ifndef MC2
/*+****************************************************************************/
 /*! \ingroup SSL_OPS
 *
 * CspOtherFullAesFinish
 *
 * When not (RSA <= 2048), do a full handshake. The pre-master secret is read
 * from the context and the rest of the handshake is completed. This is used
 * by both the server and the client. This entry point handles all the
 * AES cases.
 *
 * The handshake message data for this request should include all handshake
 * message data after (and including) the client hello message up until (but
 * not including) the first finished message. Handshake data can be accumulated
 * prior to this request by calls to Handshake*, and this request will
 * append the included handshake message data to the pre-existing handshake
 * hash state.
 *
 * \param request_type    CAVIUM_BLOCKING or CAVIUM_NON_BLOCKING
 * \param context_handle    64-bit pointer to context (context_handle\%8=0)
 * \param hash_type    MD5_TYPE or SHA1_TYPE
 * \param ssl_version    VER3_0 or VER_TLS
 * \param aes_type    AES_128 or AES_256
 * \param master_secret_ret    NOT_RETURNED or RETURN_ENCRYPTED
 * \param clnt_fin_msg_out    RETURN_CFM_ENCRYPTED or RETURN_CFM_UNENCRYPTED
 * \param srvr_fin_msg_out    RETURN_SFM_ENCRYPTED or RETURN_SFM_UNENCRYPTED
 * \param client_pad_length    number of 128-bit words to pad above min
 * \param server_pad_length    number of 128-bit words to pad above min
 * \param pre_master_length    size of premaster secret in bytes
 *                 (SSLv3: 4<=modlength<=256, modlength\%4=0;
 *                 TLS: 16<=modlength<=128, modlength\%16=0)
 * \param client_random    pointer to 32 bytes of random data
 * \param server_random    pointer to 32 bytes of random data
 * \param handshake_length    size in bytes of the handshake message data
 * \param handshake    pointer to the handshake message dat
 *
 * \param client_finished_message    pointer to encrypted part of client finished message
 * \param server_finished_message    pointer to encrypted part of server finished message
 * \param encrypt_master_secret    (master_secret_ret == RETURN_ENCRYPTED) ? pointer to
 *        returned encrypted master secret : don't care
 * \param request_id    Unique ID for this request
 *
 * \param dev_id    Device ID
 *
 * \retval SUCCESS 0
 * \retval FAILURE/PENDING #CspErrorCodes
 */
 /*-***************************************************************************/
Uint32
CspOtherFullAesFinish(n1_request_type request_type,
                       Uint64 context_handle,
                       HashType hash_type,
                       SslVersion ssl_version,
                       AesType aes_type,
                       MasterSecretReturn master_secret_ret,
                       ClientFinishMessageOutput clnt_fin_msg_out,
                       ServerFinishMessageOutput srvr_fin_msg_out,
                       Uint16 client_pad_length,
                       Uint16 server_pad_length,
                       Uint16 pre_master_length,
                       Uint8 *client_random,
                       Uint8 *server_random,
                       Uint16 handshake_length,
                       Uint8 *handshake,
                       Uint8 *client_finished_message,
                       Uint8 *server_finished_message,
                       Uint8 *encrypt_master_secret,
                       Uint32 *request_id,Uint32 dev_id);

Uint32
Csp1OtherFullAesFinish(n1_request_type request_type,
                       Uint64 context_handle,
                       HashType hash_type,
                       SslVersion ssl_version,
                       AesType aes_type,
                       MasterSecretReturn master_secret_ret,
                       ClientFinishMessageOutput clnt_fin_msg_out,
                       ServerFinishMessageOutput srvr_fin_msg_out,
                       Uint16 client_pad_length,
                       Uint16 server_pad_length,
                       Uint16 pre_master_length,
                       Uint8 *client_random,
                       Uint8 *server_random,
                       Uint16 handshake_length,
                       Uint8 *handshake,
                       Uint8 *client_finished_message,
                       Uint8 *server_finished_message,
                       Uint8 *encrypt_master_secret,
                       Uint32 *request_id);

#endif


/*+****************************************************************************/
 /*! \ingroup SSL_OPS
 *
 * CspOtherVerifyAes
 *
 * Do a full handshake - up to the point of the
 * verify operation. The pre-master secret is read from the context.
 * This is used by both the server and the client. This entry point handles all
 * the AES cases.
 *
 * The handshake message data for this request should include all handshake
 * message data after (and including) the client hello message up until (but
 * not including) the client verify message.
 *
 * \param request_type    CAVIUM_BLOCKING or CAVIUM_NON_BLOCKING
 * \param context_handle    64-bit pointer to context (context_handle\%8=0)
 * \param record_hash_type    MD5_TYPE or SHA1_TYPE
 * \param verify_hash      MD5_TYPE or SHA1_TYPE or SHA256_TYPE or SHA384_TYPE or SHA512_TYPE
 * \param ssl_version    VER3_0 or VER_TLS
 * \param aes_type    AES_128 or AES_256
 * \param master_secret_ret    NOT_RETURNED or RETURN_ENCRYPTED
#ifdef MAC_SECRET_RETURN_SUPPORT
 * \param mac_secret_ret       NO_MAC_SECRET_IN_RPTR or RETURN_MAC_SECRET_IN_RPTR
#endif
 * \param pre_master_length    size of premaster secret in bytes
 *            (SSLv3: 4<=modlength<=256, modlength\%4=0;
 *             TLS: 16<=modlength<=128, modlength\%16=0)
 * \param client_random    pointer to 32 bytes of random data
 * \param server_random    pointer to 32 bytes of random data
 * \param handshake_length    size in bytes of the handshake message data
 * \param handshake    pointer to the handshake message data
 *
 * \param verify_data    pointer to 36 bytes of verify data
 * \param encrypt_master_secret    (master_secret_ret == RETURN_ENCRYPTED) ? pointer to
 *        returned encrypted master secret : don't care
#ifdef MAC_SECRET_RETURN_SUPPORT
 * \param mac_secret    (mac_secret_ret == RETURN_MAC_SECRET_IN_RPTR) ? pointer to
 *                        return  mac secret : don't care
#endif
 * \param request_id    Unique ID for this request
 *
 * \param dev_id    Device ID
 *
 * \retval SUCCESS 0
 * \retval FAILURE/PENDING #CspErrorCodes
 */
 /*-***************************************************************************/
Uint32
CspOtherVerifyAes(n1_request_type request_type,
                   Uint64 context_handle,
                   HashType record_hash_type,
#ifdef TLS12_SUPPORT
                   HashType verify_hash_type,
#endif
                   SslVersion ssl_version,
                   AesType aes_type,
                   MasterSecretReturn master_secret_ret,
#ifdef MAC_SECRET_RETURN_SUPPORT
         	   MacSecretReturn mac_secret_ret,
#endif
                   Uint16 pre_master_length,
                   Uint8 *client_random,
                   Uint8 *server_random,
                   Uint16 handshake_length,
                   Uint8 *handshake,
                   Uint8 *verify_data,
                   Uint8 *encrypt_master_secret,
#ifdef MAC_SECRET_RETURN_SUPPORT
                   Uint8 *mac_secret,
#endif
                   Uint32 *request_id,Uint32 dev_id);

Uint32
Csp1OtherVerifyAes(n1_request_type request_type,
                   Uint64 context_handle,
                   HashType record_hash_type,
#ifdef TLS12_SUPPORT
                   HashType verify_hash_type,
#endif
                   SslVersion ssl_version,
                   AesType aes_type,
                   MasterSecretReturn master_secret_ret,
#ifdef MAC_SECRET_RETURN_SUPPORT
         	   MacSecretReturn mac_secret_ret,
#endif
                   Uint16 pre_master_length,
                   Uint8 *client_random,
                   Uint8 *server_random,
                   Uint16 handshake_length,
                   Uint8 *handshake,
                   Uint8 *verify_data,
                   Uint8 *encrypt_master_secret,
#ifdef MAC_SECRET_RETURN_SUPPORT
                   Uint8 *mac_secret,
#endif
                   Uint32 *request_id);



#ifndef MC2
/*+****************************************************************************/
 /*! \ingroup SSL_OPS
 *
 * CspOtherVerifyAesFinish
 *
 * do a full handshake - up to the point of the
 * verify operation. The pre-master secret is read from the context.
 * This is used by both the server and the client. This entry point handles all
 * the AES cases.
 *
 * The handshake message data for this request should include all handshake
 * message data after (and including) the client hello message up until (but
 * not including) the client verify message. Handshake data can be accumulated
 * prior to this request by calls to Handshake*, and this request will
 * append the included handshake message data to the pre-existing handshake
 * hash state.
 *
 * \param request_type    CAVIUM_BLOCKING or CAVIUM_NON_BLOCKING
 * \param context_handle    64-bit pointer to context (context_handle\%8=0)
 * \param hash_type    MD5_TYPE or SHA1_TYPE
 * \param ssl_version    VER3_0 or VER_TLS
 * \param aes_type    AES_128 or AES_256
 * \param master_secret_ret    NOT_RETURNED or RETURN_ENCRYPTED
 * \param pre_master_length    size of premaster secret in bytes
 *            (SSLv3: 4<=modlength<=256, modlength\%4=0;
 *             TLS: 16<=modlength<=128, modlength\%16=0)
 * \param client_random    pointer to 32 bytes of random data
 * \param server_random    pointer to 32 bytes of random data
 * \param handshake_length    size in bytes of the handshake message data
 * \param handshake    pointer to the handshake message data
 *
 * \param verify_data    pointer to 36 bytes of verify data
 * \param encrypt_master_secret    (master_secret_ret == RETURN_ENCRYPTED) ? pointer to
 *        returned encrypted master secret : don't care
 * \param request_id    Unique ID for this request
 *
 * \param dev_id    Device ID
 *
 * \retval SUCCESS 0
 * \retval FAILURE/PENDING #CspErrorCodes
 */
 /*-***************************************************************************/
Uint32
CspOtherVerifyAesFinish(n1_request_type request_type,
                         Uint64 context_handle,
                         HashType hash_type,
                         SslVersion ssl_version,
                         AesType aes_type,
                         MasterSecretReturn master_secret_ret,
                         Uint16 pre_master_length,
                         Uint8 *client_random,
                         Uint8 *server_random,
                         Uint16 handshake_length,
                         Uint8 *handshake,
                         Uint8 *verify_data,
                         Uint8 *encrypt_master_secret,
                         Uint32 *request_id,Uint32 dev_id);

Uint32
Csp1OtherVerifyAesFinish(n1_request_type request_type,
                         Uint64 context_handle,
                         HashType hash_type,
                         SslVersion ssl_version,
                         AesType aes_type,
                         MasterSecretReturn master_secret_ret,
                         Uint16 pre_master_length,
                         Uint8 *client_random,
                         Uint8 *server_random,
                         Uint16 handshake_length,
                         Uint8 *handshake,
                         Uint8 *verify_data,
                         Uint8 *encrypt_master_secret,
                         Uint32 *request_id);


#endif

/*+****************************************************************************/
 /*! \ingroup SSL_OPS
 *
 * CspFinishedRc4Finish
 *
 * Finish off the handshake hash and generate the finished messages for a full
 * handshake. This is used in a full handshake with client authentication on
 * either the client or the server. This follows RsaserverVerify or
 * OtherVerify in that case. This entry point handles all the RC4 cases.
 *
 * The handshake hash context should include handshake messages from the
 * client hello message up until (but not including) the client verify message.
 * This state should have been set up by a prior RsaserverVerifyRc4* or
 * OtherVerifyRc4*. The handshake message data for this request should include
 * the certificate verify message.
 *
 * \param request_type    CAVIUM_BLOCKING or CAVIUM_NON_BLOCKING
 * \param context_handle    64-bit pointer to context (context_handle\%8=0)
 * \param hash_type    MD5_TYPE or SHA1_TYPE
 * \param ssl_version    VER3_0 or VER_TLS
 * \param handshake_length    size in bytes of the handshake message data
 * \param handshake    pointer to the handshake message data
 *
 * \param client_finished_message    pointer to encrypted part of client finished message
 * \param server_finished_message    pointer to encrypted part of server finished message
 * \param request_id    Unique ID for this request
 *
 * \param dev_id    Device ID
 *
 * \retval SUCCESS 0
 * \retval FAILURE/PENDING #CspErrorCodes
 */
 /*-***************************************************************************/
Uint32
CspFinishedRc4Finish(n1_request_type request_type,
                      Uint64 context_handle,
                      HashType hash_type,
                      SslVersion ssl_version,
#ifdef RC4_UNENC_FNSD_MSG_SUPPORT
                      ClientFinishMessageOutput clnt_fin_msg_out,
                      ServerFinishMessageOutput srvr_fin_msg_out,
#ifdef RFC_5746_SUPPORT
                      ClientServerFinishMessageOutput clnt_srvr_fin_msg_out,
#endif
                      Uint16 client_pad_length,
                      Uint16 server_pad_length,
#endif
#ifdef TLS12_SUPPORT
                      Uint8 * write_seq_num,
                      Uint8 * read_seq_num,
#endif
                      Uint16 handshake_length,
                      Uint8 *handshake,
                      Uint8 *client_finished_message,
                      Uint8 *server_finished_message,
#ifdef RFC_5746_SUPPORT
                      Uint8 *unencrypted_client_finished_message,
                      Uint8 *unencrypted_server_finished_message,
#endif
                      Uint32 *request_id,Uint32 dev_id);

Uint32
Csp1FinishedRc4Finish(n1_request_type request_type,
                      Uint64 context_handle,
                      HashType hash_type,
                      SslVersion ssl_version,
#ifdef RC4_UNENC_FNSD_MSG_SUPPORT
                      ClientFinishMessageOutput clnt_fin_msg_out,
                      ServerFinishMessageOutput srvr_fin_msg_out,
#ifdef RFC_5746_SUPPORT
                      ClientServerFinishMessageOutput clnt_srvr_fin_msg_out,
#endif
                      Uint16 client_pad_length,
                      Uint16 server_pad_length,
#endif
#ifdef TLS12_SUPPORT
               Uint8 * write_seq_num,
               Uint8 * read_seq_num,
#endif
                      Uint16 handshake_length,
                      Uint8 *handshake,
                      Uint8 *client_finished_message,
                      Uint8 *server_finished_message,
#ifdef RFC_5746_SUPPORT
                      Uint8 *unencrypted_client_finished_message,
                      Uint8 *unencrypted_server_finished_message,
#endif
                      Uint32 *request_id);



/*+****************************************************************************/
 /*! \ingroup SSL_OPS
 *
 * CspFinished3DesFinish
 *
 * Finish off the handshake hash and generate the finished messages for a full
 * handshake. This is used in a full handshake with client authentication on
 * either the client or the server. This follows RsaserverVerify or
 * OtherVerify in that case. This entry point handles all DES/3DES
 * cases.
 *
 * The handshake hash context should include handshake messages from the
 * client hello message up until (but not including) the client verify message.
 * This state should have been set up by a prior RsaserverVerify3Des* or
 * OtherVerify3Des*. The handshake message data for this request should include
 * the certificate verify message.
 *
 * \param request_type    CAVIUM_BLOCKING or CAVIUM_NON_BLOCKING
 * \param context_handle    64-bit pointer to context (context_handle\%8=0)
 * \param hash_type    MD5_TYPE or SHA1_TYPE
 * \param ssl_version    VER3_0 or VER_TLS
 * \param clnt_fin_msg_out    RETURN_CFM_ENCRYPTED or RETURN_CFM_UNENCRYPTED
 * \param srvr_fin_msg_out    RETURN_SFM_ENCRYPTED or RETURN_SFM_UNENCRYPTED
 * \param client_pad_length    number of 64-bit words to pad above min
 * \param server_pad_length    number of 64-bit words to pad above min
 * \param handshake_length    size in bytes of the handshake message data
 * \param handshake    pointer to the handshake message data
 *
 * \param client_finished_message    pointer to encrypted part of client finished message
 * \param server_finished_message    pointer to encrypted part of server finished message
 * \param request_id    Unique ID for this request
 *
 * \param dev_id    Device ID
 *
 * \retval SUCCESS 0
 * \retval FAILURE/PENDING #CspErrorCodes
 */
 /*-***************************************************************************/
Uint32
CspFinished3DesFinish(n1_request_type request_type,
                       Uint64 context_handle,
                       HashType hash_type,
                       SslVersion ssl_version,
                       ClientFinishMessageOutput clnt_fin_msg_out,
                       ServerFinishMessageOutput srvr_fin_msg_out,
#ifdef RFC_5746_SUPPORT
                       ClientServerFinishMessageOutput clnt_srvr_fin_msg_out,
#endif
                       Uint16 client_pad_length,
                       Uint16 server_pad_length,
#ifdef DTLS_SUPPORT
                      Uint8 * handshake_write_seq_num,
                      Uint8 * handshake_read_seq_num,
#endif
#if (defined(TLS12_SUPPORT) || (DTLS_SUPPORT))
                       Uint8 * write_seq_num,
                       Uint8 * write_iv,
                       Uint8 * read_seq_num,
                       Uint8 * read_iv,
#endif
                       Uint16 handshake_length,
                       Uint8 *handshake,
                       Uint8 *client_finished_message,
                       Uint8 *server_finished_message,
#ifdef RFC_5746_SUPPORT
                       Uint8 *unencrypted_client_finished_message,
                       Uint8 *unencrypted_server_finished_message,
#endif
                       Uint32 *request_id,Uint32 dev_id);

Uint32
Csp1Finished3DesFinish(n1_request_type request_type,
                       Uint64 context_handle,
                       HashType hash_type,
                       SslVersion ssl_version,
                       ClientFinishMessageOutput clnt_fin_msg_out,
                       ServerFinishMessageOutput srvr_fin_msg_out,
#ifdef RFC_5746_SUPPORT
                       ClientServerFinishMessageOutput clnt_srvr_fin_msg_out,
#endif
                       Uint16 client_pad_length,
                       Uint16 server_pad_length,
#ifdef DTLS_SUPPORT
                      Uint8 * handshake_write_seq_num,
                      Uint8 * handshake_read_seq_num,
#endif
#if (defined(TLS12_SUPPORT) || (DTLS_SUPPORT))
                       Uint8 * write_seq_num,
                       Uint8 * write_iv,
                       Uint8 * read_seq_num,
                       Uint8 * read_iv,
#endif
                       Uint16 handshake_length,
                       Uint8 *handshake,
                       Uint8 *client_finished_message,
                       Uint8 *server_finished_message,
#ifdef RFC_5746_SUPPORT
                       Uint8 *unencrypted_client_finished_message,
                       Uint8 *unencrypted_server_finished_message,
#endif
                       Uint32 *request_id);



/*+****************************************************************************/
 /*! \ingroup SSL_OPS
 *
 * CspFinishedAesFinish
 *
 * Finish off the handshake hash and generate the finished messages for a full
 * handshake. This is used in a full handshake with client authentication on
 * either the client or the server. This follows RsaserverVerify or
 * OtherVerify in that case. This entry point handles all the AES cases.
 *
 * The handshake hash context should include handshake messages from the
 * client hello message up until (but not including) the client verify message.
 * This state should have been set up by a prior RsaserverVerifyAes* or
 * OtherVerifyAes*. The handshake message data for this request should include
 * the certificate verify message.
 *
 * \param request_type    CAVIUM_BLOCKING or CAVIUM_NON_BLOCKING
 * \param context_handle    64-bit pointer to context (context_handle\%8=0)
 * \param hash_type    MD5_TYPE or SHA1_TYPE
 * \param ssl_version    VER3_0 or VER_TLS
 * \param aes_type    AES_128 or AES_256
 * \param clnt_fin_msg_out    RETURN_CFM_ENCRYPTED or RETURN_CFM_UNENCRYPTED
 * \param srvr_fin_msg_out    RETURN_SFM_ENCRYPTED or RETURN_SFM_UNENCRYPTED
 * \param client_pad_length    number of 128-bit words to pad above min
 * \param server_pad_length    number of 128-bit words to pad above min
 * \param handshake_length    size in bytes of the handshake message data
 * \param handshake    pointer to the handshake message data
 *
 * \param client_finished_message    pointer to encrypted part of client finished message
 * \param server_finished_message    pointer to encrypted part of server finished message
 * \param request_id    Unique ID for this request
 *
 * \param dev_id    Device ID
 *
 * \retval SUCCESS 0
 * \retval FAILURE/PENDING #CspErrorCodes
 */
 /*-***************************************************************************/
Uint32
CspFinishedAesFinish(n1_request_type request_type,
                      Uint64 context_handle,
                      HashType hash_type,
                      SslVersion ssl_version,
                      AesType aes_type,
                      ClientFinishMessageOutput clnt_fin_msg_out,
                      ServerFinishMessageOutput srvr_fin_msg_out,
#ifdef RFC_5746_SUPPORT
                      ClientServerFinishMessageOutput clnt_srvr_fin_msg_out,
#endif
                      Uint16 client_pad_length,
                      Uint16 server_pad_length,
#ifdef DTLS_SUPPORT
                      Uint8 * handshake_write_seq_num,
                      Uint8 * handshake_read_seq_num,
#endif
#if (defined(TLS12_SUPPORT) || (DTLS_SUPPORT))
                      Uint8 * write_seq_num,
                      Uint8 * write_iv,
                      Uint8 * read_seq_num,
                      Uint8 * read_iv,
#endif
                      Uint16 handshake_length,
                      Uint8 *handshake,
                      Uint8 *client_finished_message,
                      Uint8 *server_finished_message,
#ifdef RFC_5746_SUPPORT
                      Uint8 *unencrypted_client_finished_message,
                      Uint8 *unencrypted_server_finished_message,
#endif
                      Uint32 *request_id,Uint32 dev_id);

Uint32
Csp1FinishedAesFinish(n1_request_type request_type,
                      Uint64 context_handle,
                      HashType hash_type,
                      SslVersion ssl_version,
                      AesType aes_type,
                      ClientFinishMessageOutput clnt_fin_msg_out,
                      ServerFinishMessageOutput srvr_fin_msg_out,
#ifdef RFC_5746_SUPPORT
                      ClientServerFinishMessageOutput clnt_srvr_fin_msg_out,
#endif
                      Uint16 client_pad_length,
                      Uint16 server_pad_length,
#ifdef DTLS_SUPPORT
                      Uint8 * handshake_write_seq_num,
                      Uint8 * handshake_read_seq_num,
#endif
#if (defined(TLS12_SUPPORT) || (DTLS_SUPPORT))
                      Uint8 * write_seq_num,
                      Uint8 * write_iv,
                      Uint8 * read_seq_num,
                      Uint8 * read_iv,
#endif
                      Uint16 handshake_length,
                      Uint8 *handshake,
                      Uint8 *client_finished_message,
                      Uint8 *server_finished_message,
#ifdef RFC_5746_SUPPORT
                      Uint8 *unencrypted_client_finished_message,
                      Uint8 *unencrypted_server_finished_message,
#endif
                      Uint32 *request_id);



/*+****************************************************************************/
 /*! \ingroup SSL_OPS
 *
 * CspResumeRc4
 *
 * Completes a resume on either the client or the server. This entry point
 * handles all the RC4 cases.
 *
 * The handshake message data for this request should include all handshake
 * message data after (and including) the most-recent client hello message up
 * until (but not including) the first finished message.
 *
 * \param request_type    CAVIUM_BLOCKING or CAVIUM_NON_BLOCKING
 * \param context_handle    64-bit pointer to context (context_handle\%8=0)
 * \param hash_type    MD5_TYPE or SHA1_TYPE
 * \param ssl_version    VER3_0 or VER_TLS
 * \param rc4_type    RC4_128, RC4_EXPORT_40, or RC4_EXPORT_56
 * \param master_secret_inp    READ_FROM_CONTEXT or INPUT_ENCRYPTED
#ifdef MAC_SECRET_RETURN_SUPPORT
 * \param mac_secret_ret       NO_MAC_SECRET_IN_RPTR or RETURN_MAC_SECRET_IN_RPTR
#endif
 * \param client_random    pointer to 32 bytes of random data
 * \param server_random    pointer to 32 bytes of random data
 * \param encrypt_master_secret    pointer to 48-byte secret
#ifdef MAC_SECRET_RETURN_SUPPORT
 * \param mac_secret    (mac_secret_ret == RETURN_MAC_SECRET_IN_RPTR) ? pointer to
 *                        return  mac secret : don't care
#endif
 * \param handshake_length    size in bytes of the handshake message data
 * \param handshake    pointer to the handshake message data
 *
 * \param client_finished_message    pointer to encrypted part of client finished message
 * \param server_finished_message    pointer to encrypted part of server finished message
 * \param request_id    Unique ID for this request
 *
 * \param dev_id    Device ID
 *
 * \retval SUCCESS 0
 * \retval FAILURE/PENDING #CspErrorCodes
 */
 /*-***************************************************************************/
Uint32
CspResumeRc4(n1_request_type request_type,
              Uint64 context_handle,
              HashType hash_type,
              SslVersion ssl_version,
              Rc4Type rc4_type,
              MasterSecretInput master_secret_inp,
#ifdef MAC_SECRET_RETURN_SUPPORT
              MacSecretReturn mac_secret_ret,
#endif
#ifdef RC4_UNENC_FNSD_MSG_SUPPORT
              ClientFinishMessageOutput clnt_fin_msg_out,
              ServerFinishMessageOutput srvr_fin_msg_out,
#ifdef RFC_5746_SUPPORT
              ClientServerFinishMessageOutput clnt_srvr_fin_msg_out,
#endif
              Uint16 client_pad_length,
              Uint16 server_pad_length,
#endif
              Uint8 *client_random,
              Uint8 *server_random,
              Uint8 *encrypt_master_secret,
#ifdef MAC_SECRET_RETURN_SUPPORT
              Uint8 *mac_secret,
#endif
#ifdef TLS12_SUPPORT
              Uint8 * write_seq_num,
              Uint8 * read_seq_num,
#endif
              Uint16 handshake_length,
              Uint8 *handshake,
              Uint8 *client_finished_message,
              Uint8 *server_finished_message,
#ifdef RFC_5746_SUPPORT
              Uint8 *unencrypted_client_finished_message,
              Uint8 *unencrypted_server_finished_message,
#endif
              Uint32 *request_id,Uint32 dev_id);

Uint32
Csp1ResumeRc4(n1_request_type request_type,
              Uint64 context_handle,
              HashType hash_type,
              SslVersion ssl_version,
              Rc4Type rc4_type,
              MasterSecretInput master_secret_inp,
#ifdef MAC_SECRET_RETURN_SUPPORT
              MacSecretReturn mac_secret_ret,
#endif
#ifdef RC4_UNENC_FNSD_MSG_SUPPORT
              ClientFinishMessageOutput clnt_fin_msg_out,
              ServerFinishMessageOutput srvr_fin_msg_out,
#ifdef RFC_5746_SUPPORT
              ClientServerFinishMessageOutput clnt_srvr_fin_msg_out,
#endif
              Uint16 client_pad_length,
              Uint16 server_pad_length,
#endif
              Uint8 *client_random,
              Uint8 *server_random,
              Uint8 *encrypt_master_secret,
#ifdef MAC_SECRET_RETURN_SUPPORT
              Uint8 *mac_secret,
#endif
#ifdef TLS12_SUPPORT
              Uint8 * write_seq_num,
              Uint8 * read_seq_num,
#endif
              Uint16 handshake_length,
              Uint8 *handshake,
              Uint8 *client_finished_message,
              Uint8 *server_finished_message,
#ifdef RFC_5746_SUPPORT
              Uint8 *unencrypted_client_finished_message,
              Uint8 *unencrypted_server_finished_message,
#endif
              Uint32 *request_id);



#ifndef MC2
/*+****************************************************************************/
 /*! \ingroup SSL_OPS
 *
 * CspResumeRc4Finish
 *
 * Completes a resume on either the client or the server. This entry point
 * handles all the RC4 cases.
 *
 * The handshake message data for this request should include all handshake
 * message data after (and including) the most-recent client hello message up
 * until (but not including) the first finished message. Handshake data can be
 * accumulated prior to this request by calls to Handshake*, and this
 * request will append the included handshake message data to the pre-existing
 * handshake hash state.
 *
 * \param request_type    CAVIUM_BLOCKING or CAVIUM_NON_BLOCKING
 * \param context_handle    64-bit pointer to context (context_handle\%8=0)
 * \param hash_type    MD5_TYPE or SHA1_TYPE
 * \param ssl_version    VER3_0 or VER_TLS
 * \param rc4_type    RC4_128, RC4_EXPORT_40, or RC4_EXPORT_56
 * \param master_secret_inp    READ_FROM_CONTEXT or INPUT_ENCRYPTED
 * \param client_random    pointer to 32 bytes of random data
 * \param server_random    pointer to 32 bytes of random data
 * \param encrypt_master_secret    pointer to 48-byte secret
 * \param handshake_length    size in bytes of the handshake message data
 * \param handshake    pointer to the handshake message data
 *
 * \param client_finished_message    pointer to encrypted part of client finished message
 * \param server_finished_message    pointer to encrypted part of server finished message
 * \param request_id    Unique ID for this request
 *
 * \param dev_id    Device ID
 *
 * \retval SUCCESS 0
 * \retval FAILURE/PENDING #CspErrorCodes
 */
 /*-***************************************************************************/
Uint32
CspResumeRc4Finish(n1_request_type request_type,
                    Uint64 context_handle,
                    HashType hash_type,
                    SslVersion ssl_version,
                    Rc4Type rc4_type,
                    MasterSecretInput master_secret_inp,
                    Uint8 *client_random,
                    Uint8 *server_random,
                    Uint8 *encrypt_master_secret,
                    Uint16 handshake_length,
                    Uint8 *handshake,
                    Uint8 *client_finished_message,
                    Uint8 *server_finished_message,
                    Uint32 *request_id,Uint32 dev_id);

Uint32
Csp1ResumeRc4Finish(n1_request_type request_type,
                    Uint64 context_handle,
                    HashType hash_type,
                    SslVersion ssl_version,
                    Rc4Type rc4_type,
                    MasterSecretInput master_secret_inp,
                    Uint8 *client_random,
                    Uint8 *server_random,
                    Uint8 *encrypt_master_secret,
                    Uint16 handshake_length,
                    Uint8 *handshake,
                    Uint8 *client_finished_message,
                    Uint8 *server_finished_message,
                    Uint32 *request_id);

#endif



/*+****************************************************************************/
 /*! \ingroup SSL_OPS
 *
 * CspResume3Des
 *
 * Completes a resume on either the client or the server. This entry point
 * handles all the DES/3DES cases.
 *
 * The handshake message data for this request should include all handshake
 * message data after (and including) the most-recent client hello message up
 * until (but not including) the first finished message.
 *
 * \param request_type    CAVIUM_BLOCKING or CAVIUM_NON_BLOCKING
 * \param context_handle    64-bit pointer to context (context_handle\%8=0)
 * \param hash_type    MD5_TYPE or SHA1_TYPE
 * \param ssl_version    VER3_0 or VER_TLS
 * \param des_type    DES, DES_EXPORT_40 or DES3_192
 * \param master_secret_inp    READ_FROM_CONTEXT or INPUT_ENCRYPTED
#ifdef MAC_SECRET_RETURN_SUPPORT
 * \param mac_secret_ret       NO_MAC_SECRET_IN_RPTR or RETURN_MAC_SECRET_IN_RPTR
#endif
 * \param clnt_fin_msg_out    RETURN_CFM_ENCRYPTED or RETURN_CFM_UNENCRYPTED
 * \param srvr_fin_msg_out    RETURN_SFM_ENCRYPTED or RETURN_SFM_UNENCRYPTED
 * \param client_pad_length    number of 64-bit words to pad above min(not applicable to MC2)
 * \param server_pad_length    number of 64-bit words to pad above min(not applicable to MC2)
 * \param client_random    pointer to 32 bytes of random data
 * \param server_random    pointer to 32 bytes of random data
#ifdef MAC_SECRET_RETURN_SUPPORT
 * \param mac_secret    (mac_secret_ret == RETURN_MAC_SECRET_IN_RPTR) ? pointer to
 *                        return  mac secret : don't care
#endif
 * \param encrypt_master_secret    pointer to 48-byte secret
 * \param handshake_length    size in bytes of the handshake message data
 * \param handshake    pointer to the handshake message data
 *
 * \param client_finished_message    pointer to encrypted part of client finished message
 * \param server_finished_message    pointer to encrypted part of server finished message
 * \param request_id    Unique ID for this request
 *
 * \param dev_id    Device ID
 *
 * \retval SUCCESS 0
 * \retval FAILURE/PENDING #CspErrorCodes
 */
 /*-***************************************************************************/
Uint32
CspResume3Des(n1_request_type request_type,
               Uint64 context_handle,
               HashType hash_type,
               SslVersion ssl_version,
               DesType des_type,
               MasterSecretInput master_secret_inp,
#ifdef MAC_SECRET_RETURN_SUPPORT
               MacSecretReturn mac_secret_ret,
#endif
               ClientFinishMessageOutput clnt_fin_msg_out,
               ServerFinishMessageOutput srvr_fin_msg_out,
#ifdef RFC_5746_SUPPORT
               ClientServerFinishMessageOutput clnt_srvr_fin_msg_out,
#endif
               Uint16 client_pad_length,
               Uint16 server_pad_length,
               Uint8 *client_random,
               Uint8 *server_random,
               Uint8 *encrypt_master_secret,
#ifdef MAC_SECRET_RETURN_SUPPORT
               Uint8 *mac_secret,
#endif
#ifdef DTLS_SUPPORT
               Uint8 * handshake_write_seq_num,
               Uint8 * handshake_read_seq_num,
#endif
#if (defined(TLS12_SUPPORT) || (DTLS_SUPPORT))
               Uint8 * write_seq_num,
               Uint8 * write_iv,
               Uint8 * read_seq_num,
               Uint8 * read_iv,
#endif
               Uint16 handshake_length,
               Uint8 *handshake,
               Uint8 *client_finished_message,
               Uint8 *server_finished_message,
#ifdef RFC_5746_SUPPORT
               Uint8 *unencrypted_client_finished_message,
               Uint8 *unencrypted_server_finished_message,
#endif
               Uint32 *request_id,Uint32 dev_id);

Uint32
Csp1Resume3Des(n1_request_type request_type,
               Uint64 context_handle,
               HashType hash_type,
               SslVersion ssl_version,
               DesType des_type,
               MasterSecretInput master_secret_inp,
#ifdef MAC_SECRET_RETURN_SUPPORT
               MacSecretReturn mac_secret_ret,
#endif
               ClientFinishMessageOutput clnt_fin_msg_out,
               ServerFinishMessageOutput srvr_fin_msg_out,
#ifdef RFC_5746_SUPPORT
               ClientServerFinishMessageOutput clnt_srvr_fin_msg_out,
#endif
               Uint16 client_pad_length,
               Uint16 server_pad_length,
               Uint8 *client_random,
               Uint8 *server_random,
               Uint8 *encrypt_master_secret,
#ifdef MAC_SECRET_RETURN_SUPPORT
               Uint8 *mac_secret,
#endif
#ifdef DTLS_SUPPORT
               Uint8 * handshake_write_seq_num,
               Uint8 * handshake_read_seq_num,
#endif
#if (defined(TLS12_SUPPORT) || (DTLS_SUPPORT))
               Uint8 * write_seq_num,
               Uint8 * write_iv,
               Uint8 * read_seq_num,
               Uint8 * read_iv,
#endif
               Uint16 handshake_length,
               Uint8 *handshake,
               Uint8 *client_finished_message,
               Uint8 *server_finished_message,
#ifdef RFC_5746_SUPPORT
               Uint8 *unencrypted_client_finished_message,
               Uint8 *unencrypted_server_finished_message,
#endif
               Uint32 *request_id);



#ifndef MC2
/*+****************************************************************************/
 /*! \ingroup SSL_OPS
 *
 * CspResume3DesFinish
 *
 * Completes a resume on either the client or the server. This entry point
 * handles all the DES/3DES cases.
 *
 * The handshake message data for this request should include all handshake
 * message data after (and including) the most-recent client hello message up
 * until (but not including) the first finished message. Handshake data can be
 * accumulated prior to this request by calls to Handshake*, and this
 * request will append the included handshake message data to the pre-existing
 * handshake hash state.
 *
 * \param request_type    CAVIUM_BLOCKING or CAVIUM_NON_BLOCKING
 * \param context_handle    64-bit pointer to context (context_handle\%8=0)
 * \param hash_type    MD5_TYPE or SHA1_TYPE
 * \param ssl_version    VER3_0 or VER_TLS
 * \param des_type    DES, DES_EXPORT_40 or DES3_192
 * \param master_secret_inp    READ_FROM_CONTEXT or INPUT_ENCRYPTED
 * \param clnt_fin_msg_out    RETURN_CFM_ENCRYPTED or RETURN_CFM_UNENCRYPTED
 * \param srvr_fin_msg_out    RETURN_SFM_ENCRYPTED or RETURN_SFM_UNENCRYPTED
 * \param client_pad_length    number of 64-bit words to pad above min
 * \param server_pad_length    number of 64-bit words to pad above min
 * \param client_random    pointer to 32 bytes of random data
 * \param server_random    pointer to 32 bytes of random data
 * \param encrypt_master_secret    pointer to 48-byte secret
 * \param handshake_length    size in bytes of the handshake message data
 * \param handshake    pointer to the handshake message data
 *
 * \param client_finished_message    pointer to encrypted part of client finished message
 * \param server_finished_message    pointer to encrypted part of server finished message
 * \param request_id    Unique ID for this request
 *
 * \param dev_id    Device ID
 *
 * \retval SUCCESS 0
 * \retval FAILURE/PENDING #CspErrorCodes
 */
 /*-***************************************************************************/
Uint32
CspResume3DesFinish(n1_request_type request_type,
                     Uint64 context_handle,
                     HashType hash_type,
                     SslVersion ssl_version,
                     DesType des_type,
                     MasterSecretInput master_secret_inp,
                     ClientFinishMessageOutput clnt_fin_msg_out,
                     ServerFinishMessageOutput srvr_fin_msg_out,
                     Uint16 client_pad_length,
                     Uint16 server_pad_length,
                     Uint8 *client_random,
                     Uint8 *server_random,
                     Uint8 *encrypt_master_secret,
                     Uint16 handshake_length,
                     Uint8 *handshake,
                     Uint8 *client_finished_message,
                     Uint8 *server_finished_message,
                     Uint32 *request_id,Uint32 dev_id);

Uint32
Csp1Resume3DesFinish(n1_request_type request_type,
                     Uint64 context_handle,
                     HashType hash_type,
                     SslVersion ssl_version,
                     DesType des_type,
                     MasterSecretInput master_secret_inp,
                     ClientFinishMessageOutput clnt_fin_msg_out,
                     ServerFinishMessageOutput srvr_fin_msg_out,
                     Uint16 client_pad_length,
                     Uint16 server_pad_length,
                     Uint8 *client_random,
                     Uint8 *server_random,
                     Uint8 *encrypt_master_secret,
                     Uint16 handshake_length,
                     Uint8 *handshake,
                     Uint8 *client_finished_message,
                     Uint8 *server_finished_message,
                     Uint32 *request_id);

#endif


/*+****************************************************************************/
 /*! \ingroup SSL_OPS
 *
 * CspResumeAes
 *
 * Completes a resume on either the client or the server. This entry point
 * handles all the AES cases.
 *
 * The handshake message data for this request should include all handshake
 * message data after (and including) the most-recent client hello message up
 * until (but not including) the first finished message.
 *
 * \param request_type    CAVIUM_BLOCKING or CAVIUM_NON_BLOCKING
 * \param context_handle    64-bit pointer to context (context_handle\%8=0)
 * \param hash_type    MD5_TYPE or SHA1_TYPE
 * \param ssl_version    VER3_0 or VER_TLS
 * \param aes_type    AES_128 or AES_256
 * \param master_secret_inp    READ_FROM_CONTEXT or INPUT_ENCRYPTED
#ifdef MAC_SECRET_RETURN_SUPPORT
 * \param mac_secret_ret       NO_MAC_SECRET_IN_RPTR or RETURN_MAC_SECRET_IN_RPTR
#endif
 * \param clnt_fin_msg_out    RETURN_CFM_ENCRYPTED or RETURN_CFM_UNENCRYPTED
 * \param srvr_fin_msg_out    RETURN_SFM_ENCRYPTED or RETURN_SFM_UNENCRYPTED
 * \param client_pad_length    number of 128-bit words to pad above min(not applicable to MC2)
 * \param server_pad_length    number of 128-bit words to pad above min(not applicable to MC2)
 * \param client_random    pointer to 32 bytes of random data
 * \param server_random    pointer to 32 bytes of random data
 * \param encrypt_master_secret    pointer to 48-byte secret
#ifdef MAC_SECRET_RETURN_SUPPORT
 * \param mac_secret    (mac_secret_ret == RETURN_MAC_SECRET_IN_RPTR) ? pointer to
 *                        return  mac secret : don't care
#endif
 * \param handshake_length    size in bytes of the handshake message data
 * \param handshake    pointer to the handshake message data
 *
 * \param client_finished_message    pointer to encrypted part of client finished message
 * \param server_finished_message    pointer to encrypted part of server finished message
 * \param request_id    Unique ID for this request
 *
 * \param dev_id    Device ID
 *
 * \retval SUCCESS 0
 * \retval FAILURE/PENDING #CspErrorCodes
 */
 /*-***************************************************************************/
Uint32
CspResumeAes(n1_request_type request_type,
              Uint64 context_handle,
              HashType hash_type,
              SslVersion ssl_version,
              AesType aes_type,
              MasterSecretInput master_secret_inp,
#ifdef MAC_SECRET_RETURN_SUPPORT
              MacSecretReturn mac_secret_ret,
#endif
              ClientFinishMessageOutput clnt_fin_msg_out,
              ServerFinishMessageOutput srvr_fin_msg_out,
#ifdef RFC_5746_SUPPORT
              ClientServerFinishMessageOutput clnt_srvr_fin_msg_out,
#endif
              Uint16 client_pad_length,
              Uint16 server_pad_length,
              Uint8 *client_random,
              Uint8 *server_random,
              Uint8 *encrypt_master_secret,
#ifdef MAC_SECRET_RETURN_SUPPORT
              Uint8 *mac_secret,
#endif
#ifdef DTLS_SUPPORT
              Uint8 * handshake_write_seq_num,
              Uint8 * handshake_read_seq_num,
#endif
#if (defined(TLS12_SUPPORT) || (DTLS_SUPPORT))
              Uint8 * write_seq_num,
              Uint8 * write_iv,
              Uint8 * read_seq_num,
              Uint8 * read_iv,
#endif
              Uint16 handshake_length,
              Uint8 *handshake,
              Uint8 *client_finished_message,
              Uint8 *server_finished_message,
#ifdef RFC_5746_SUPPORT
              Uint8 *unencrypted_client_finished_message,
              Uint8 *unencrypted_server_finished_message,
#endif
              Uint32 *request_id,Uint32 dev_id);

Uint32
Csp1ResumeAes(n1_request_type request_type,
              Uint64 context_handle,
              HashType hash_type,
              SslVersion ssl_version,
              AesType aes_type,
              MasterSecretInput master_secret_inp,
#ifdef MAC_SECRET_RETURN_SUPPORT
              MacSecretReturn mac_secret_ret,
#endif
              ClientFinishMessageOutput clnt_fin_msg_out,
              ServerFinishMessageOutput srvr_fin_msg_out,
#ifdef RFC_5746_SUPPORT
              ClientServerFinishMessageOutput clnt_srvr_fin_msg_out,
#endif
              Uint16 client_pad_length,
              Uint16 server_pad_length,
              Uint8 *client_random,
              Uint8 *server_random,
              Uint8 *encrypt_master_secret,
#ifdef MAC_SECRET_RETURN_SUPPORT
              Uint8 *mac_secret,
#endif
#ifdef DTLS_SUPPORT
              Uint8 * handshake_write_seq_num,
              Uint8 * handshake_read_seq_num,
#endif
#if (defined(TLS12_SUPPORT) || (DTLS_SUPPORT))
              Uint8 * write_seq_num,
              Uint8 * write_iv,
              Uint8 * read_seq_num,
              Uint8 * read_iv,
#endif
              Uint16 handshake_length,
              Uint8 *handshake,
              Uint8 *client_finished_message,
              Uint8 *server_finished_message,
#ifdef RFC_5746_SUPPORT
              Uint8 *unencrypted_client_finished_message,
              Uint8 *unencrypted_server_finished_message,
#endif
              Uint32 *request_id);



#ifndef MC2
/*+****************************************************************************/
 /*! \ingroup SSL_OPS
 *
 * CspResumeAesFinish
 *
 * Completes a resume on either the client or the server. This entry point
 * handles all the AES cases.
 *
 * The handshake message data for this request should include all handshake
 * message data after (and including) the most-recent client hello message up
 * until (but not including) the first finished message. Handshake data can be
 * accumulated prior to this request by calls to Handshake*, and this
 * request will append the included handshake message data to the pre-existing
 * handshake hash state.
 *
 * \param request_type    CAVIUM_BLOCKING or CAVIUM_NON_BLOCKING
 * \param context_handle    64-bit pointer to context (context_handle\%8=0)
 * \param hash_type    MD5_TYPE or SHA1_TYPE
 * \param ssl_version    VER3_0 or VER_TLS
 * \param aes_type    AES_128 or AES_256
 * \param master_secret_inp    READ_FROM_CONTEXT or INPUT_ENCRYPTED
 * \param clnt_fin_msg_out    RETURN_CFM_ENCRYPTED or RETURN_CFM_UNENCRYPTED
 * \param srvr_fin_msg_out    RETURN_SFM_ENCRYPTED or RETURN_SFM_UNENCRYPTED
 * \param client_pad_length    number of 128-bit words to pad above min
 * \param server_pad_length    number of 128-bit words to pad above min
 * \param client_random    pointer to 32 bytes of random data
 * \param server_random    pointer to 32 bytes of random data
 * \param encrypt_master_secret    pointer to 48-byte secret
 * \param handshake_length    size in bytes of the handshake message data
 * \param handshake    pointer to the handshake message data
 *
 * \param client_finished_message    pointer to encrypted part of client finished message
 * \param server_finished_message    pointer to encrypted part of server finished message
 * \param request_id    Unique ID for this request
 *
 * \param dev_id    Device ID
 *
 * \retval SUCCESS 0
 * \retval FAILURE/PENDING #CspErrorCodes
 */
 /*-***************************************************************************/
Uint32
CspResumeAesFinish(n1_request_type request_type,
                    Uint64 context_handle,
                    HashType hash_type,
                    SslVersion ssl_version,
                    AesType aes_type,
                    MasterSecretInput master_secret_inp,
                    ClientFinishMessageOutput clnt_fin_msg_out,
                    ServerFinishMessageOutput srvr_fin_msg_out,
                    Uint16 client_pad_length,
                    Uint16 server_pad_length,
                    Uint8 *client_random,
                    Uint8 *server_random,
                    Uint8 *encrypt_master_secret,
                    Uint16 handshake_length,
                    Uint8 *handshake,
                    Uint8 *client_finished_message,
                    Uint8 *server_finished_message,
                    Uint32 *request_id,Uint32 dev_id);

Uint32
Csp1ResumeAesFinish(n1_request_type request_type,
                    Uint64 context_handle,
                    HashType hash_type,
                    SslVersion ssl_version,
                    AesType aes_type,
                    MasterSecretInput master_secret_inp,
                    ClientFinishMessageOutput clnt_fin_msg_out,
                    ServerFinishMessageOutput srvr_fin_msg_out,
                    Uint16 client_pad_length,
                    Uint16 server_pad_length,
                    Uint8 *client_random,
                    Uint8 *server_random,
                    Uint8 *encrypt_master_secret,
                    Uint16 handshake_length,
                    Uint8 *handshake,
                    Uint8 *client_finished_message,
                    Uint8 *server_finished_message,
                    Uint32 *request_id);

#endif



/*+****************************************************************************/
 /*! \ingroup SSL_OPS
 *
 * CspEncryptRecordRc4
 *
 *    Encrypts the SSL record for RC4 cipher.
 *
 * \param request_type    CAVIUM_BLOCKING or CAVIUM_NON_BLOCKING
 * \param context_handle    64-bit pointer to context (context_handle\%8=0)
 * \param hash_type    MD5_TYPE or SHA1_TYPE
 * \param ssl_version    VER3_0 or VER_TLS
 * \param ssl_party    SERVER or CLIENT
 * \param message_type    CHANGE_CIPHER_SPEC, ALERT, HANDSHAKE, or APP_DATA
 * \param message_length    size of message in bytes (0<=length<=2^14+1024)
 * \param message    pointer to length-byte message
 *
 * \param record    pointer to (length + hash_size) bytes of encrypted record
 * \param request_id    Unique ID for this request.
 *
 * \param dev_id    Device ID
 *
 * \retval SUCCESS 0
 * \retval FAILURE/PENDING #CspErrorCodes
 */
 /*-***************************************************************************/
Uint32
CspEncryptRecordRc4(n1_request_type request_type,
            Uint64 context_handle,
            HashType hash_type,
            SslVersion ssl_version,
            SslPartyType ssl_party,
            MessageType message_type,
#ifdef TLS12_SUPPORT
            Uint8 *record_seq_num,
#endif
            Uint16 message_length,
            Uint8 *message,
            Uint8 *record,
            Uint32 *request_id,Uint32 dev_id);

Uint32
Csp1EncryptRecordRc4(n1_request_type request_type,
            Uint64 context_handle,
            HashType hash_type,
            SslVersion ssl_version,
            SslPartyType ssl_party,
            MessageType message_type,
#ifdef TLS12_SUPPORT
            Uint8 *record_seq_num,
#endif
            Uint16 message_length,
            Uint8 *message,
            Uint8 *record,
            Uint32 *request_id);



/*+****************************************************************************/
 /*! \ingroup SSL_OPS
 *
 * CspDecryptRecordRc4
 *
 *    Decrypts the SSL record for RC4 cipher.
 *
 * \param request_type    CAVIUM_BLOCKING or CAVIUM_NON_BLOCKING
 * \param context_handle    64-bit pointer to context (context_handle\%8=0)
 * \param hash_type    MD5_TYPE or SHA1_TYPE
 * \param ssl_version    VER3_0 or VER_TLS
 * \param ssl_party    SERVER or CLIENT
 * \param message_type    CHANGE_CIPHER_SPEC, ALERT, HANDSHAKE, or APP_DATA
 * \param record_length    size of record in bytes (0<=length<=2^14+1024)
 * \param record    pointer to length-byte encrypted part of record
 *
 * \param message    pointer to (record length - hash size) bytes
 * \param request_id    Unique ID for this request
 *
 * \param dev_id    Device ID
 *
 * \retval SUCCESS 0
 * \retval FAILURE/PENDING #CspErrorCodes
 */
 /*-***************************************************************************/
Uint32
CspDecryptRecordRc4(n1_request_type request_type,
                     Uint64 context_handle,
                     HashType hash_type,
                     SslVersion ssl_version,
                      SslPartyType ssl_party,
                     MessageType message_type,
#ifdef TLS12_SUPPORT
                     Uint8 *record_seq_num,
#endif
                     Uint16 record_length,
                     Uint8 *record,
                     Uint8 *message,
                     Uint32 *request_id,Uint32 dev_id);

Uint32
Csp1DecryptRecordRc4(n1_request_type request_type,
                     Uint64 context_handle,
                     HashType hash_type,
                     SslVersion ssl_version,
                     SslPartyType ssl_party,
                     MessageType message_type,
#ifdef TLS12_SUPPORT
                     Uint8 *record_seq_num,
#endif
                     Uint16 record_length,
                     Uint8 *record,
                     Uint8 *message,
                     Uint32 *request_id);



/*+****************************************************************************/
 /*! \ingroup SSL_OPS
 *
 * CspEncryptRecord3Des
 *
 *    Encrypts the SSL record for 3Des cipher.
 *
 * \param request_type    CAVIUM_BLOCKING or CAVIUM_NON_BLOCKING
 * \param context_handle    64-bit pointer to context (context_handle\%8=0)
 * \param hash_type    MD5_TYPE or SHA1_TYPE
 * \param ssl_version    VER3_0 or VER_TLS
 * \param ssl_party    SERVER or CLIENT
 * \param message_type    CHANGE_CIPHER_SPEC, ALERT, HANDSHAKE, or APP_DATA
 * \param pad_length    size of extra padding in 8-byte blocks
 * \param message_length    size of param in bytes (0<=length<=2^14+1024)
 * \param message    pointer to length-byte input message
 *
 * \param record_length    pointer to length of the encrypted part of the record in bytes
 * \param record    pointer to *record_length-byte output
 * \param request_id    Unique ID for this request
 *
 * \param dev_id    Device ID
 *
 * \retval SUCCESS 0
 * \retval FAILURE/PENDING #CspErrorCodes
 */
 /*-***************************************************************************/
Uint32
CspEncryptRecord3Des(n1_request_type request_type,
                      Uint64 context_handle,
                      HashType hash_type,
                      SslVersion ssl_version,
                      SslPartyType ssl_party,
                      MessageType message_type,
                      Uint16 pad_length,
#if defined(DTLS_SUPPORT) || defined(TLS12_SUPPORT)
                      Uint8 *record_epoch_seq_num,
                      Uint8 *record_IV,
#endif
                      Uint16 message_length,
                      Uint8 *message,
                      Uint16 *record_length,
                      Uint8 *record,
                      Uint32 *request_id,Uint32 dev_id);

Uint32
Csp1EncryptRecord3Des(n1_request_type request_type,
                      Uint64 context_handle,
                      HashType hash_type,
                      SslVersion ssl_version,
                      SslPartyType ssl_party,
                      MessageType message_type,
                      Uint16 pad_length,
#if defined(DTLS_SUPPORT) || defined(TLS12_SUPPORT)
                      Uint8 *record_epoch_seq_num,
                      Uint8 *record_IV,
#endif
                      Uint16 message_length,
                      Uint8 *message,
                      Uint16 *record_length,
                      Uint8 *record,
                      Uint32 *request_id);



/*+****************************************************************************/
 /*! \ingroup SSL_OPS
 *
 * CspDecryptRecord3Des
 *
 *    Decrypts the SSL record for 3Des cipher.
 *
 * \param request_type    CAVIUM_BLOCKING or CAVIUM_NON_BLOCKING
 * \param context_handle    64-bit pointer to context (context_handle\%8=0)
 * \param hash_type    MD5_TYPE or SHA1_TYPE
 * \param ssl_version    VER3_0 or VER_TLS
 * \param ssl_party    SERVER or CLIENT
 * \param message_type    CHANGE_CIPHER_SPEC, ALERT, HANDSHAKE, or APP_DATA
 * \param record_length    size of the encrypted part of the input record in bytes
 *        (length\%8=0, 0<=length<=2^14+1024)
 * \param record    pointer to length-byte encrypted part of the input record
 *
 * \param message_length    pointer to length in bytes of the decrypted message
 * \param message    pointer to *message_length-byte output
 * \param request_id    Unique ID for this request
 *
 * \param dev_id    Device ID
 *
 * \retval SUCCESS 0
 * \retval FAILURE/PENDING #CspErrorCodes
 */
 /*-***************************************************************************/
Uint32
CspDecryptRecord3Des(n1_request_type request_type,
                      Uint64 context_handle,
                      HashType hash_type,
                      SslVersion ssl_version,
                      SslPartyType ssl_party,
                      MessageType message_type,
#if defined(DTLS_SUPPORT) || defined(TLS12_SUPPORT)
                      Uint8 *record_epoch_seq_num,
                      Uint8 *record_IV,
#endif
                      Uint16 record_length,
                      Uint8 *record,
                      Uint16 *message_length,
                      Uint8 *message,
                      Uint32 *request_id,Uint32 dev_id);

Uint32
Csp1DecryptRecord3Des(n1_request_type request_type,
                      Uint64 context_handle,
                      HashType hash_type,
                      SslVersion ssl_version,
                      SslPartyType ssl_party,
                      MessageType message_type,
#if defined(DTLS_SUPPORT) || defined(TLS12_SUPPORT)
                      Uint8 *record_epoch_seq_num,
                      Uint8 *record_IV,
#endif
                      Uint16 record_length,
                      Uint8 *record,
                      Uint16 *message_length,
                      Uint8 *message,
                      Uint32 *request_id);



#ifndef MC2
/*+****************************************************************************/
 /*! \ingroup SSL_OPS
 *
 * CspDecryptRecord3DesRecover
 *
 * \param request_type    CAVIUM_BLOCKING or CAVIUM_NON_BLOCKING
 * \param context_handle    64-bit pointer to context (context_handle\%8=0)
 * \param hash_type    MD5_TYPE or SHA1_TYPE
 * \param ssl_version    VER3_0 or VER_TLS
 * \param ssl_party    SERVER or CLIENT
 * \param message_type    CHANGE_CIPHER_SPEC, ALERT, HANDSHAKE, or APP_DATA
 * \param record_length    size of the encrypted part of the input record in bytes
 *        (length\%8=0, 0<=length<=2^14+1024)
 * \param record    pointer to length-byte encrypted part of the input record
 *
 * \param message_length    pointer to length in bytes of the decrypted message
 * \param message    pointer to *message_length-byte output,
 * \param request_id    Unique ID for this request
 *
 * \param dev_id    Device ID
 *
 * \retval SUCCESS 0
 * \retval FAILURE/PENDING #CspErrorCodes
 */
 /*-***************************************************************************/
Uint32
CspDecryptRecord3DesRecover(n1_request_type request_type,
                             Uint64 context_handle,
                             HashType hash_type,
                             SslVersion ssl_version,
                              SslPartyType ssl_party,
                             MessageType message_type,
                             Uint16 record_length,
                             Uint8 *record,
                             Uint16 *message_length,
                             Uint8 *message,
                             Uint32 *request_id,Uint32 dev_id);

Uint32
Csp1DecryptRecord3DesRecover(n1_request_type request_type,
                             Uint64 context_handle,
                             HashType hash_type,
                             SslVersion ssl_version,
                              SslPartyType ssl_party,
                             MessageType message_type,
                             Uint16 record_length,
                             Uint8 *record,
                             Uint16 *message_length,
                             Uint8 *message,
                             Uint32 *request_id);

#endif


/*+****************************************************************************/
 /*! \ingroup SSL_OPS
 *
 * CspEncryptRecordAes
 *
 *    Encrypts the SSL record for Aes cipher.
 *
 * \param request_type    CAVIUM_BLOCKING or CAVIUM_NON_BLOCKING
 * \param context_handle    64-bit pointer to context (context_handle\%8=0)
 * \param hash_type    MD5_TYPE or SHA1_TYPE (MD5 hash_size = 16, SHA1 hash_size = 20)
 * \param ssl_version    VER3_0 or VER_TLS
 * \param ssl_party    SERVER or CLIENT
 * \param aes_type    AES_128 or AES_256
 * \param message_type    CHANGE_CIPHER_SPEC, ALERT, HANDSHAKE, or APP_DATA
 * \param pad_length    size of extra padding in 8-byte blocks
 * \param message_length    size of input in bytes (0<=length<=2^14+1024)
 * \param message    pointer to length-byte input
 *
 * \param record_length    pointer to length of the encrypted part of the record in bytes
 * \param record    pointer to *record_length-byte output,
 * \param request_id    Unique ID for this request
 *
 * \param dev_id    Device ID
 *
 * \retval SUCCESS 0
 * \retval FAILURE/PENDING #CspErrorCodes
 */
 /*-***************************************************************************/
Uint32
CspEncryptRecordAes(n1_request_type request_type,
                     Uint64 context_handle,
                     HashType hash_type,
                     SslVersion ssl_version,
                     SslPartyType ssl_party,
                     AesType aes_type,
                     MessageType message_type,
                     Uint16 pad_length,
#if defined(DTLS_SUPPORT) || defined(TLS12_SUPPORT)
                     Uint8 *record_epoch_seq_num,
                     Uint8 *record_IV,
#endif
                     Uint16 message_length,
                     Uint8 *message,
                     Uint16 *record_length,
                     Uint8 *record,
                     Uint32 *request_id,Uint32 dev_id);

Uint32
Csp1EncryptRecordAes(n1_request_type request_type,
                     Uint64 context_handle,
                     HashType hash_type,
                     SslVersion ssl_version,
                     SslPartyType ssl_party,
                     AesType aes_type,
                     MessageType message_type,
                     Uint16 pad_length,
#if defined(DTLS_SUPPORT) || defined(TLS12_SUPPORT)
                     Uint8 *record_epoch_seq_num,
                     Uint8 *record_IV,
#endif
                     Uint16 message_length,
                     Uint8 *message,
                     Uint16 *record_length,
                     Uint8 *record,
                     Uint32 *request_id);




/*+****************************************************************************/
 /*! \ingroup SSL_OPS
 *
 * CspDecryptRecordAes
 *
 *    Decrypts the SSL record for Aes cipher.
 *
 * \param request_type    CAVIUM_BLOCKING or CAVIUM_NON_BLOCKING
 * \param context_handle    64-bit pointer to context (context_handle\%8=0)
 * \param hash_type    MD5_TYPE or SHA1_TYPE
 * \param ssl_version    VER3_0 or VER_TLS
 * \param ssl_party    SERVER or CLIENT
 * \param aes_type    AES_128 or AES_256
 * \param message_type    CHANGE_CIPHER_SPEC, ALERT, HANDSHAKE, or APP_DATA
 * \param record_length    size of input in bytes (length\%16=0, 0<=length<=2^14+1024)
 * \param record    pointer to length-byte input
 *
 * \param message_length    pointer to length in bytes of the decrypted message
 * \param message    pointer to *message_length-byte output
 * \param request_id    Unique ID for this request
 *
 * \param dev_id    Device ID
 *
 * \retval SUCCESS 0
 * \retval FAILURE/PENDING #CspErrorCodes
 */
 /*-***************************************************************************/
Uint32
CspDecryptRecordAes(n1_request_type request_type,
                     Uint64 context_handle,
                     HashType hash_type,
                     SslVersion ssl_version,
                     SslPartyType ssl_party,
                     AesType aes_type,
                     MessageType message_type,
#if defined(DTLS_SUPPORT) || defined(TLS12_SUPPORT)
                     Uint8 *record_epoch_seq_num,
                     Uint8 *record_IV,
#endif
                     Uint16 record_length,
                     Uint8 *record,
                     Uint16 *message_length,
                     Uint8 *message,
                     Uint32 *request_id,Uint32 dev_id);

Uint32
Csp1DecryptRecordAes(n1_request_type request_type,
                     Uint64 context_handle,
                     HashType hash_type,
                     SslVersion ssl_version,
                     SslPartyType ssl_party,
                     AesType aes_type,
                     MessageType message_type,
#if defined(DTLS_SUPPORT) || defined(TLS12_SUPPORT)
                     Uint8 *record_epoch_seq_num,
                     Uint8 *record_IV,
#endif
                     Uint16 record_length,
                     Uint8 *record,
                     Uint16 *message_length,
                     Uint8 *message,
                     Uint32 *request_id);



#ifndef MC2

/*+****************************************************************************/
 /*! \ingroup SSL_OPS
 *
 * CspDecryptRecordAesRecover
 *
 * \param request_type    CAVIUM_BLOCKING or CAVIUM_NON_BLOCKING
 * \param context_handle    64-bit pointer to context (context_handle\%8=0)
 * \param hash_type    MD5_TYPE or SHA1_TYPE (MD5 hash_size = 16, SHA1 hash_size = 20)
 * \param ssl_version    VER3_0 or VER_TLS
 * \param aes_type    AES_128 or AES_256
 * \param ssl_party    SERVER or CLIENT
 * \param message_type    CHANGE_CIPHER_SPEC, ALERT, HANDSHAKE, or APP_DATA
 * \param record_length    size of input in bytes (length\%16=0, 0<=length<=2^14+1024)
 * \param record    pointer to length-byte input
 *
 * \param message_length    pointer to length in bytes of the decrypted message
 * \param message    pointer to *message_length-byte output
 * \param request_id    Unique ID for this request
 *
 * \param dev_id    Device ID
 *
 * \retval SUCCESS 0
 * \retval FAILURE/PENDING #CspErrorCodes
 */
 /*-***************************************************************************/
Uint32
CspDecryptRecordAesRecover(n1_request_type request_type,
                Uint64 context_handle,
                HashType hash_type,
                SslVersion ssl_version,
                SslPartyType ssl_party,
                AesType aes_type,
                MessageType message_type,
                Uint16 record_length,
                Uint8 *record,
                Uint16 *message_length,
                Uint8 *message,
                Uint32 *request_id,Uint32 dev_id);

Uint32
Csp1DecryptRecordAesRecover(n1_request_type request_type,
                Uint64 context_handle,
                HashType hash_type,
                SslVersion ssl_version,
                SslPartyType ssl_party,
                AesType aes_type,
                MessageType message_type,
                Uint16 record_length,
                Uint8 *record,
                Uint16 *message_length,
                Uint8 *message,
                Uint32 *request_id);


#endif





/*+****************************************************************************/
 /*! \ingroup SSL_OPS
 *
 * CspRsaSsl20ServerFullRc4
 *
 * Does a full SSL2.0 handshake on the server with RSA <= 2048 bits.
 *
 *
 * Supported ciphers
 *    SSL_CK_RC4_128_WITH_MD5
 *    SSL_CK_RC4_128_EXPORT40_WITH_MD5
 *
 *
 * \param request_type    CAVIUM_BLOCKING or CAVIUM_NON_BLOCKING
 * \param context_handle    64-bit byte-pointer to context (context_handle\%8=0)
 * \param key_handle    pointer to 64-bit key memory handle
 * \param rc4_type    RC4_128 or RC4_EXPORT_40
 * \param client_master_secret    master key received in client-master-key handshake message.
 * \param clear_master_secret_length    length (in bytes) of clear portion of client_master_secret
 * \param encrypted_master_secret_length    length (in bytes) of encrypted portion of client_master_secret
 * \param modlength    size of RSA operation in bytes (64<=modlength<=256, modlength\%8=0)
 * \param challenge    pointer to challenge data.
 * \param challenge_length    length (in bytes) of challenge data.
 * \param connection_id    pointer to 16 bytes of connection ID.
 * \param session_id    pointer to 16 bytes of Session ID.
 *
 *
 * \param client_finished    pointer to encrypted part of client finished message
 * \param server_finished    pointer to encrypted part of server finished message
 * \param server_verify    pointer to encrypted part of server verify message
 * \param master_secret    master secret to used in session caching for reuse.
 * \param master_secret_length    size in bytes of master secret.
 * \param request_id    Unique ID for this request
 *
 * \param dev_id    Device ID
 *
 * \retval SUCCESS 0
 * \retval FAILURE/PENDING #CspErrorCodes
 *
 * \verbatim
 * Context format:
 *    Context is left in a state where it can be used for record processing:
 *    Word
 *    0-15    reserved for hashing
 *    16-21    master secret
 *    To server
 *    22        Sequence number
 *    23        Unused
 *    24-15    Rc4 Key
 *    26-59    Rc4 State
 *    To client
 *    60        Sequence number
 *    61        Unused
 *    62-63    Rc4 Key
 *    64-97    Rc4 State
 * \endverbatim
 */
 /*-***************************************************************************/
Uint32
CspRsaSsl20ServerFullRc4(n1_request_type request_type,
                          Uint64 context_handle,
                          Uint64 *key_handle,
                          Rc4Type rc4_type,
                          Uint8 *client_master_secret,
                          Uint16 clear_master_secret_length,
                          Uint16 encrypted_master_secret_length,
                          Uint16 modlength,
                          Uint8 *challenge,
                          Uint16 challenge_length,
                          Uint8 *connection_id,
                          Uint8 *session_id,
                          Uint8 *client_finished,
                          Uint8 *server_finished,
                          Uint8 *server_verify,
                          Uint8 *master_secret,
                          Uint16 *master_secret_length,
                          Uint32 *request_id,Uint32 dev_id);

Uint32
Csp1RsaSsl20ServerFullRc4(n1_request_type request_type,
                          Uint64 context_handle,
                          Uint64 *key_handle,
                          Rc4Type rc4_type,
                          Uint8 *client_master_secret,
                          Uint16 clear_master_secret_length,
                          Uint16 encrypted_master_secret_length,
                          Uint16 modlength,
                          Uint8 *challenge,
                          Uint16 challenge_length,
                          Uint8 *connection_id,
                          Uint8 *session_id,
                          Uint8 *client_finished,
                          Uint8 *server_finished,
                          Uint8 *server_verify,
                          Uint8 *master_secret,
                          Uint16 *master_secret_length,
                          Uint32 *request_id);



/*+****************************************************************************/
 /*! \ingroup SSL_OPS
 *
 * CspRsaSsl20ServerClientAuthRc4
 *
 * Generates key material, and certificate req, verify messages.
 *
 *
 * Supported ciphers
 *    SSL_CK_RC4_128_WITH_MD5
 *    SSL_CK_RC4_128_EXPORT40_WITH_MD5
 *
 *
 * \param request_type    CAVIUM_BLOCKING or CAVIUM_NON_BLOCKING
 * \param context_handle    64-bit byte-pointer to context (context_handle\%8=0)
 * \param key_handle    pointer to 64-bit key memory handle
 * \param rc4_type    RC4_128 or RC4_EXPORT_40
 * \param client_master_secret    master key received in client-master-key handshake message.
 * \param clear_master_secret_length    length (in bytes) of clear portion of client_master_secret
 * \param encrypted_master_secret_length    length (in bytes) of encrypted portion of client_master_secret
 * \param modlength    size of RSA operation in bytes (64<=modlength<=256, modlength\%8=0)
 * \param challenge    pointer to challenge data.
 * \param challenge_length    length (in bytes) of challenge data.
 * \param connection_id    pointer to 16 bytes of connection ID.
 * \param session_id    pointer to 16 bytes of Session ID.
 * \param auth_type    SSLv2 authentication type
 * \param cert_challenge    SSLv2 certificate challenge
 *
 * \param cert_request    SSLv2 certificate request
 * \param client_finished    pointer to encrypted part of client finished message
 * \param server_verify    pointer to encrypted part of server verify message
 * \param master_secret    master secret to used in session caching for reuse.
 * \param master_secret_length    size in bytes of master secret.
 * \param request_id    Unique ID for this request
 *
 * \param dev_id    Device ID
 *
 * \retval SUCCESS 0
 * \retval FAILURE/PENDING #CspErrorCodes
 * \verbatim
 * Context format:
 *    Context is left in a state where it can be used for record processing:
 *    Word
 *    0-15    reserved for hashing
 *    16-21    master secret
 *    To server
 *    22        Sequence number
 *    23        Unused
 *    24-15    Rc4 Key
 *    26-59    Rc4 State
 *    To client
 *    60        Sequence number
 *    61        Unused
 *    62-63    Rc4 Key
 *    64-97    Rc4 State
 * \endverbatim
 */
 /*-***************************************************************************/

Uint32
CspRsaSsl20ServerClientAuthRc4(
                    n1_request_type request_type,
                     Uint64 context_handle,
                      Uint64 *key_handle,
                      Rc4Type rc4_type,
                      Uint8 *client_master_secret,
                      Uint16 clear_master_secret_length,
                      Uint16 encrypted_master_secret_length,
                      Uint16 modlength,
                      Uint8 *challenge,
                      Uint16 challenge_length,
                      Uint8 *connection_id,
                      Uint8 *session_id,
                      Uint8 *client_finished,
                    Uint8 auth_type,
                    Uint8 *cert_challenge,
                    Uint8 *cert_request,
                      Uint8 *server_verify,
                      Uint8 *master_secret,
                      Uint16 *master_secret_length,
                    Uint32 *request_id,Uint32 dev_id);

Uint32
Csp1RsaSsl20ServerClientAuthRc4(
                    n1_request_type request_type,
                     Uint64 context_handle,
                      Uint64 *key_handle,
                      Rc4Type rc4_type,
                      Uint8 *client_master_secret,
                      Uint16 clear_master_secret_length,
                      Uint16 encrypted_master_secret_length,
                      Uint16 modlength,
                      Uint8 *challenge,
                      Uint16 challenge_length,
                      Uint8 *connection_id,
                      Uint8 *session_id,
                      Uint8 *client_finished,
                    Uint8 auth_type,
                    Uint8 *cert_challenge,
                    Uint8 *cert_request,
                      Uint8 *server_verify,
                      Uint8 *master_secret,
                      Uint16 *master_secret_length,
                    Uint32 *request_id);



/*+****************************************************************************/
 /*! \ingroup SSL_OPS
 *
 * CspSsl20ResumeRc4
 *
 * Resumes a previously negotiated session.
 *
 *
 * Supported ciphers
 *    SSL_CK_RC4_128_WITH_MD5
 *    SSL_CK_RC4_128_EXPORT40_WITH_MD5
 *
 *
 * \param request_type    CAVIUM_BLOCKING or CAVIUM_NON_BLOCKING
 * \param context_handle    64-bit byte-pointer to context (context_handle\%8=0)
 * \param key_handle    pointer to 64-bit key memory handle
 * \param rc4_type    RC4_128 or RC4_EXPORT_40
 * \param master_secret    master secret from previous session.
 * \param master_secret_length    size in bytes of master secret.
 * \param challenge    pointer to challenge data.
 * \param challenge_length    length (in bytes) of challenge data.
 * \param connection_id    pointer to 16 bytes of connection ID.
 * \param session_id    pointer to 16 bytes of Session ID.
 * \param client_finished    pointer to encrypted part of client finished message.
 * \param server_finished    pointer to encrypted part of server finished message.
 * \param server_verify    pointer to encrypted part of server verify message
 * \param request_id    Unique ID for this request
 *
 * \param dev_id    Device ID
 *
 * \retval SUCCESS 0
 * \retval FAILURE/PENDING #CspErrorCodes
 * \verbatim
 * Context format:
 *    Context is left in a state where it can be used for record processing:
 *    Word
 *    0-15    reserved for hashing
 *    16-21    master secret
 *    To server
 *    22        Sequence number
 *    23        Unused
 *    24-15    Rc4 Key
 *    26-59    Rc4 State
 *    To client
 *    60        Sequence number
 *    61        Unused
 *    62-63    Rc4 Key
 *    64-97    Rc4 State
 * \endverbatim
 */
 /*-***************************************************************************/

Uint32
CspSsl20ResumeRc4 (n1_request_type request_type,
            Uint64 context_handle,
            Uint64 *key_handle,
            Rc4Type rc4_type,
            Uint8 *master_secret,
            Uint16 master_secret_length,
            Uint8 *challenge,
            Uint16 challenge_length,
            Uint8 *connection_id,
            Uint8 *session_id,
            Uint8 *client_finished,
            Uint8 *server_finished,
            Uint8 *server_verify,
            Uint32 *request_id,Uint32 dev_id);

Uint32
Csp1Ssl20ResumeRc4 (n1_request_type request_type,
            Uint64 context_handle,
            Uint64 *key_handle,
            Rc4Type rc4_type,
            Uint8 *master_secret,
            Uint16 master_secret_length,
            Uint8 *challenge,
            Uint16 challenge_length,
            Uint8 *connection_id,
            Uint8 *session_id,
            Uint8 *client_finished,
            Uint8 *server_finished,
            Uint8 *server_verify,
            Uint32 *request_id);




/*+****************************************************************************/
 /*! \ingroup SSL_OPS
 *
 * CspSsl20ResumeClientAuthRc4
 *
 * Uses master key from a previous session, generates key material, cert req,
 * and verify messages.
 *
 *
 * Supported ciphers
 *    SSL_CK_RC4_128_WITH_MD5
 *    SSL_CK_RC4_128_EXPORT40_WITH_MD5
 *
 *
 * \param request_type    CAVIUM_BLOCKING or CAVIUM_NON_BLOCKING
 * \param context_handle    64-bit byte-pointer to context (context_handle\%8=0)
 * \param key_handle    pointer to 64-bit key memory handle
 * \param rc4_type    RC4_128 or RC4_EXPORT_40
 * \param master_secret    master secret from previous session.
 * \param master_secret_length    size in bytes of master secret.
 * \param challenge    pointer to challenge data.
 * \param challenge_length    length (in bytes) of challenge data.
 * \param connection_id    pointer to 16 bytes of connection ID.
 * \param session_id    pointer to 16 bytes of Session ID.
 * \param client_finished    pointer to encrypted part of client finished message
 * \param auth_type    client auth type
 * \param cert_challenge    cert challenge
 *
 * \param cert_request    pointer to encrypted part of cert request message
 * \param server_verify    pointer to encrypted part of server verify message
 * \param request_id    Unique ID for this request
 *
 * \param dev_id    Device ID
 *
 * \retval SUCCESS 0
 * \retval FAILURE/PENDING #CspErrorCodes
 * \verbatim
 * Context format:
 *    Context is left in a state where it can be used for record processing:
 *    Word
 *    0-15    reserved for hashing
 *    16-21    master secret
 *    To server
 *    22        Sequence number
 *    23        Unused
 *    24-15    Rc4 Key
 *    26-59    Rc4 State
 *    To client
 *    60        Sequence number
 *    61        Unused
 *    62-63    Rc4 Key
 *    64-97    Rc4 State
 * \endverbatim
 */
 /*-***************************************************************************/

Uint32
CspSsl20ResumeClientAuthRc4 (n1_request_type request_type,
                    Uint64 context_handle,
                    Uint64 *key_handle,
                    Rc4Type rc4_type,
                    Uint8 *master_secret,
                    Uint16 master_secret_length,
                    Uint8 *challenge,
                    Uint16 challenge_length,
                    Uint8 *connection_id,
                    Uint8 *session_id,
                    Uint8 *client_finished,
                    Uint8 auth_type,
                    Uint8 *cert_challenge,
                    Uint8 *cert_request,
                    Uint8 *server_verify,
                    Uint32 *request_id,Uint32 dev_id);

Uint32
Csp1Ssl20ResumeClientAuthRc4 (n1_request_type request_type,
                    Uint64 context_handle,
                    Uint64 *key_handle,
                    Rc4Type rc4_type,
                    Uint8 *master_secret,
                    Uint16 master_secret_length,
                    Uint8 *challenge,
                    Uint16 challenge_length,
                    Uint8 *connection_id,
                    Uint8 *session_id,
                    Uint8 *client_finished,
                    Uint8 auth_type,
                    Uint8 *cert_challenge,
                    Uint8 *cert_request,
                    Uint8 *server_verify,
                    Uint32 *request_id);




/*+****************************************************************************/
 /*! \ingroup SSL_OPS
 *
 * CspRsaSsl20ServerFull3Des
 *
 * Does a full SSL2.0 handshake on the server with RSA <= 2048 bits.
 *
 *
 * Supported ciphers
 *    SSL_CK_DES_64_CBC_WITH_MD5
    SSL_CK_DES_192_EDE3_CBC_WITH_MD5
 *
 *
 * \param request_type    CAVIUM_BLOCKING or CAVIUM_NON_BLOCKING
 * \param context_handle    64-bit byte-pointer to context (context_handle\%8=0)
 * \param key_handle    pointer to 64-bit key memory handle
 * \param des_type    DES or DES3_192
 * \param client_master_secret    master key received in client-master-key handshake message.
 * \param clear_master_secret_length    length (in bytes) of clear portion of client_master_secret
 * \param encrypted_master_secret_length    length (in bytes) of encrypted portion of client_master_secret
 * \param modlength    size of RSA operation in bytes (64<=modlength<=256, modlength\%8=0)
 * \param challenge    pointer to challenge data.
 * \param challenge_length    length (in bytes) of challenge data.
 * \param connection_id    pointer to 16 bytes of connection ID.
 * \param session_id    pointer to 16 bytes of Session ID.
 * \param iv    initialization vectore sent by client
 *
 * \param client_finished    pointer to encrypted part of client finished message
 * \param server_finished    pointer to encrypted part of server finished message
 * \param server_verify    pointer to encrypted part of server verify message
 * \param master_secret    master secret to used in session caching for reuse.
 * \param master_secret_length    size in bytes of master secret.
 * \param request_id    Unique ID for this request
 *
 * \param dev_id    Device ID
 *
 * \retval SUCCESS 0
 * \retval FAILURE/PENDING #CspErrorCodes
 * \verbatim
 * Context format:
 *    Context is left in a state where it can be used for record processing:
 *    Word
 *    0-15    reserved for hashing
 *    16-21    master secret
 *    To server
 *    22        Sequence number
 *    23        Unused
 *    24        IV
 *    25-27    3Des Keys
 *    To client
 *    28        Sequence number
 *    29        Unused
 *    30        IV
 *    31-33    3Des Keys
 * \endverbatim
 */
 /*-***************************************************************************/
Uint32
CspRsaSsl20ServerFull3Des(n1_request_type request_type,
                           Uint64 context_handle,
                          Uint64 *key_handle,
                          DesType des_type,
                          Uint8 *client_master_secret,
                          Uint16 clear_master_secret_length,
                          Uint16 encrypted_master_secret_length,
                          Uint16 modlength,
                          Uint8 *challenge,
                          Uint16 challenge_length,
                          Uint8 *connection_id,
                          Uint8 *session_id,
                          Uint8 *iv,
                          Uint8 *client_finished,
                          Uint8 *server_finished,
                          Uint8 *server_verify,
                          Uint8 *master_secret,
                          Uint16 *master_secret_length,
                          Uint32 *request_id,Uint32 dev_id);

Uint32
Csp1RsaSsl20ServerFull3Des(n1_request_type request_type,
                           Uint64 context_handle,
                          Uint64 *key_handle,
                          DesType des_type,
                          Uint8 *client_master_secret,
                          Uint16 clear_master_secret_length,
                          Uint16 encrypted_master_secret_length,
                          Uint16 modlength,
                          Uint8 *challenge,
                          Uint16 challenge_length,
                          Uint8 *connection_id,
                          Uint8 *session_id,
                          Uint8 *iv,
                          Uint8 *client_finished,
                          Uint8 *server_finished,
                          Uint8 *server_verify,
                          Uint8 *master_secret,
                          Uint16 *master_secret_length,
                          Uint32 *request_id);



/*+****************************************************************************/
 /*! \ingroup SSL_OPS
 *
 * CspRsaSsl20ServerClientAuth3Des
 *
 * Generates key material, verifies cllient finished msg, creates server verify
 * and cert request messages.
 *
 *
 * Supported ciphers
 *    SSL_CK_DES_64_CBC_WITH_MD5
    SSL_CK_DES_192_EDE3_CBC_WITH_MD5
 *
 *
 * \param request_type    CAVIUM_BLOCKING or CAVIUM_NON_BLOCKING
 * \param context_handle    64-bit byte-pointer to context (context_handle\%8=0)
 * \param key_handle    pointer to 64-bit key memory handle
 * \param des_type    DES or DES3_192
 * \param client_master_secret    master key received in client-master-key handshake message.
 * \param clear_master_secret_length    length (in bytes) of clear portion of client_master_secret
 * \param encrypted_master_secret_length    length (in bytes) of encrypted portion of client_master_secret
 * \param modlength    size of RSA operation in bytes (64<=modlength<=256, modlength\%8=0)
 * \param challenge    pointer to challenge data.
 * \param challenge_length    length (in bytes) of challenge data.
 * \param connection_id    pointer to 16 bytes of connection ID.
 * \param session_id    pointer to 16 bytes of Session ID.
 * \param iv    initialization vectore sent by client
 * \param auth_type    client auth type
 * \param cert_challenge    certficate challenge.
 *
 * \param client_finished    pointer to encrypted part of client finished message
 * \param cert_request    pointer to encrypted part of certificate request message
 * \param server_verify    pointer to encrypted part of server verify message
 * \param master_secret    master secret to used in session caching for reuse.
 * \param master_secret_length    size in bytes of master secret.
 * \param request_id    Unique ID for this request
 *
 * \param dev_id    Device ID
 *
 * \retval SUCCESS 0
 * \retval FAILURE/PENDING #CspErrorCodes
 * \verbatim
 * Context format:
 *    Context is left in a state where it can be used for record processing:
 *    Word
 *    0-15    reserved for hashing
 *    16-21    master secret
 *    To server
 *    22        Sequence number
 *    23        Unused
 *    24        IV
 *    25-27    3Des Keys
 *    To client
 *    28        Sequence number
 *    29        Unused
 *    30        IV
 *    31-33    3Des Keys
 * \endverbatim
 */
 /*-***************************************************************************/

Uint32
CspRsaSsl20ServerClientAuth3Des(
                        n1_request_type request_type,
                        Uint64 context_handle,
                        Uint64 *key_handle,
                        DesType des_type,
                        Uint8 *client_master_secret,
                        Uint16 clear_master_secret_length,
                        Uint16 encrypted_master_secret_length,
                        Uint16 modlength,
                        Uint8 *challenge,
                        Uint16 challenge_length,
                        Uint8 *connection_id,
                        Uint8 *session_id,
                        Uint8 *iv,
                        Uint8 *client_finished,
                        Uint8 auth_type,
                        Uint8 *cert_challenge,
                        Uint8 *cert_request,
                        Uint8 *server_verify,
                        Uint8 *master_secret,
                        Uint16 *master_secret_length,
                        Uint32 *request_id,Uint32 dev_id);

Uint32
Csp1RsaSsl20ServerClientAuth3Des(
                        n1_request_type request_type,
                        Uint64 context_handle,
                        Uint64 *key_handle,
                        DesType des_type,
                        Uint8 *client_master_secret,
                        Uint16 clear_master_secret_length,
                        Uint16 encrypted_master_secret_length,
                        Uint16 modlength,
                        Uint8 *challenge,
                        Uint16 challenge_length,
                        Uint8 *connection_id,
                        Uint8 *session_id,
                        Uint8 *iv,
                        Uint8 *client_finished,
                        Uint8 auth_type,
                        Uint8 *cert_challenge,
                        Uint8 *cert_request,
                        Uint8 *server_verify,
                        Uint8 *master_secret,
                        Uint16 *master_secret_length,
                        Uint32 *request_id);


/*+****************************************************************************/
 /*! \ingroup SSL_OPS
 *
 * CspSsl20Resume3Des
 *
 * Resumes a previouly negotiated handshake.
 *
 *
 * Supported ciphers
 *    SSL_CK_DES_64_CBC_WITH_MD5
 *    SSL_CK_DES_192_EDE3_CBC_WITH_MD5
 *
 *
 * \param request_type    CAVIUM_BLOCKING or CAVIUM_NON_BLOCKING
 * \param context_handle    64-bit byte-pointer to context (context_handle\%8=0)
 * \param key_handle    pointer to 64-bit key memory handle
 * \param des_type    DES or DES3_192
 * \param master_secret    master key generated in previous handshake
 * \param master_secret_length    size in bytes of master secret.
 * \param challenge    pointer to challenge data.
 * \param challenge_length    length (in bytes) of challenge data.
 * \param connection_id    pointer to 16 bytes of connection ID.
 * \param session_id    pointer to 16 bytes of Session ID.
 * \param iv    initialization vectore sent by client
 *
 * \param client_finished    pointer to encrypted part of client finished message
 * \param server_finished    pointer to encrypted part of server finished message
 * \param server_verify    pointer to encrypted part of server verify message
 * \param request_id    Unique ID for this request
 *
 * \param dev_id    Device ID
 *
 * \retval SUCCESS 0
 * \retval FAILURE/PENDING #CspErrorCodes
 * \verbatim
 * Context format:
 *    Context is left in a state where it can be used for record processing:
 *    Word
 *    0-15    reserved for hashing
 *    16-21    master secret
 *    To server
 *    22        Sequence number
 *    23        Unused
 *    24        IV
 *    25-27    3Des Keys
 *    To client
 *    28        Sequence number
 *    29        Unused
 *    30        IV
 *    31-33    3Des Keys
 * \endverbatim
 */
 /*-***************************************************************************/
Uint32
CspSsl20Resume3Des(
            n1_request_type request_type,
            Uint64 context_handle,
          Uint64 *key_handle,
          DesType des_type,
          Uint8 *master_secret,
          Uint16 master_secret_length,
          Uint8 *challenge,
          Uint16 challenge_length,
          Uint8 *connection_id,
          Uint8 *session_id,
          Uint8 *iv,
          Uint8 *client_finished,
          Uint8 *server_finished,
          Uint8 *server_verify,
          Uint32 *request_id,Uint32 dev_id);

Uint32
Csp1Ssl20Resume3Des(
            n1_request_type request_type,
            Uint64 context_handle,
          Uint64 *key_handle,
          DesType des_type,
          Uint8 *master_secret,
          Uint16 master_secret_length,
          Uint8 *challenge,
          Uint16 challenge_length,
          Uint8 *connection_id,
          Uint8 *session_id,
          Uint8 *iv,
          Uint8 *client_finished,
          Uint8 *server_finished,
          Uint8 *server_verify,
          Uint32 *request_id);




/*+****************************************************************************/
 /*! \ingroup SSL_OPS
 *
 * CspSsl20ResumeClientAuth3Des
 *
 * Uses master key from a previous session, generates key material, cert req,
 * and verify messages.
 *
 *
 * Supported ciphers
 *    SSL_CK_DES_64_CBC_WITH_MD5
    SSL_CK_DES_192_EDE3_CBC_WITH_MD5
 *
 *
 * \param request_type    CAVIUM_BLOCKING or CAVIUM_NON_BLOCKING
 * \param context_handle    64-bit byte-pointer to context (context_handle\%8=0)
 * \param key_handle    pointer to 64-bit key memory handle
 * \param des_type    DES or DES3_192
 * \param master_secret    master key generated in previous handshake
 * \param master_secret_length    size in bytes of master secret.
 * \param challenge    pointer to challenge data.
 * \param challenge_length    length (in bytes) of challenge data.
 * \param connection_id    pointer to 16 bytes of connection ID.
 * \param session_id    pointer to 16 bytes of Session ID.
 * \param iv    initialization vectore sent by client
 * \param client_finished    pointer to encrypted part of client finished message
 * \param auth_type    client authentication type
 * \param cert_challenge    cert request challenge
 * \param cert_request    certificate request
 *
 *
 *
 * \param cert_request    pointer to encrypted part of cert request message
 * \param server_verify    pointer to encrypted part of server verify message
 * \param request_id    Unique ID for this request
 *
 * \param dev_id    Device ID
 *
 * \retval SUCCESS 0
 * \retval FAILURE/PENDING #CspErrorCodes
 * \verbatim
 * Context format:
 *    Context is left in a state where it can be used for record processing:
 *    Word
 *    0-15    reserved for hashing
 *    16-21    master secret
 *    To server
 *    22        Sequence number
 *    23        Unused
 *    24        IV
 *    25-27    3Des Keys
 *    To client
 *    28        Sequence number
 *    29        Unused
 *    30        IV
 *    31-33    3Des Keys
 * \endverbatim
 */
 /*-***************************************************************************/
Uint32
CspSsl20ResumeClientAuth3Des(
            n1_request_type request_type,
            Uint64 context_handle,
          Uint64 *key_handle,
          DesType des_type,
          Uint8 *master_secret,
          Uint16 master_secret_length,
          Uint8 *challenge,
          Uint16 challenge_length,
          Uint8 *connection_id,
          Uint8 *session_id,
          Uint8 *iv,
          Uint8 *client_finished,
          Uint8 auth_type,
          Uint8 *cert_challenge,
          Uint8 *cert_request,
          Uint8 *server_verify,
          Uint32 *request_id,Uint32 dev_id);

Uint32
Csp1Ssl20ResumeClientAuth3Des(
          n1_request_type request_type,
          Uint64 context_handle,
          Uint64 *key_handle,
          DesType des_type,
          Uint8 *master_secret,
          Uint16 master_secret_length,
          Uint8 *challenge,
          Uint16 challenge_length,
          Uint8 *connection_id,
          Uint8 *session_id,
          Uint8 *iv,
          Uint8 *client_finished,
          Uint8 auth_type,
          Uint8 *cert_challenge,
          Uint8 *cert_request,
          Uint8 *server_verify,
          Uint32 *request_id);


/*+****************************************************************************/
 /*! \ingroup SSL_OPS
 *
 * CspSsl20DecryptRecordRc4
 *
 *    Decrypts the SSL record for Rc4  cipher when using SSLversion 2.0.
 *
 * \param request_type    CAVIUM_BLOCKING or CAVIUM_NON_BLOCKING
 * \param context_handle    64-bit pointer to context (context_handle\%8=0)
 * \param record_length    size of record in bytes (0<=length<=2^16-1)
 * \param record    pointer to length-byte encrypted part of record
 *
 * \param message    pointer to decrypted message
 * \param request_id    Unique ID for this request
 *
 * \param dev_id    Device ID
 *
 * \retval SUCCESS 0
 * \retval FAILURE/PENDING #CspErrorCodes
 */
 /*-***************************************************************************/
Uint32
CspSsl20DecryptRecordRc4(
                n1_request_type request_type,
                Uint64 context_handle,
                Uint16 record_length,
                Uint8 *record,
                Uint8 *message,
                Uint32 *request_id,Uint32 dev_id);

Uint32
Csp1Ssl20DecryptRecordRc4(
                n1_request_type request_type,
                Uint64 context_handle,
                Uint16 record_length,
                Uint8 *record,
                Uint8 *message,
                Uint32 *request_id);




/*+****************************************************************************/
 /*! \ingroup SSL_OPS
 *
 * CspSsl20EncryptRecordRc4
 *
 *    Encrypts the SSL record for RC4 cipher when using SSLversion 2.0.
 *
 * \param request_type    CAVIUM_BLOCKING or CAVIUM_NON_BLOCKING
 * \param context_handle    64-bit pointer to context (context_handle\%8=0)
 * \param message_length    size of message in bytes (0<=length<=2^16-1)
 * \param message    pointer to length-byte message
 *
 * \param record    pointer to encrypted record
 * \param request_id    Unique ID for this request
 *
 * \param dev_id    Device ID
 *
 * \retval SUCCESS 0
 * \retval FAILURE/PENDING #CspErrorCodes
 */
 /*-***************************************************************************/
Uint32
CspSsl20EncryptRecordRc4(
                n1_request_type request_type,
                Uint64 context_handle,
                Uint16 message_length,
                Uint8 *message,
                Uint8 *record,
                Uint32 *request_id,Uint32 dev_id);

Uint32
Csp1Ssl20EncryptRecordRc4(
                n1_request_type request_type,
                Uint64 context_handle,
                Uint16 message_length,
                Uint8 *message,
                Uint8 *record,
                Uint32 *request_id);



/*+****************************************************************************/
 /*! \ingroup SSL_OPS
 *
 * CspSsl20DecryptRecord3Des
 *
 *    Decrypts the SSL record for 3Des cipher when using SSLversion 2.0.
 *
 * \param request_type    CAVIUM_BLOCKING or CAVIUM_NON_BLOCKING
 * \param context_handle    64-bit pointer to context (context_handle\%8=0)
 * \param des_type    DES or DES3_192
 * \param record_length    size of record in bytes (0<=length<=2^16-1)
 * \param record    pointer to length-byte encrypted part of record
 *
 * \param message    pointer to decrypted message
 * \param request_id    Unique ID for this request
 *
 * \param dev_id    Device ID
 *
 * \retval SUCCESS 0
 * \retval FAILURE/PENDING #CspErrorCodes
 */
 /*-***************************************************************************/
Uint32
CspSsl20DecryptRecord3Des(
                   n1_request_type request_type,
                   Uint64 context_handle,
                   DesType des_type,
                   Uint16 record_length,
                   Uint8 *record,
                   Uint8 *message,
                   Uint32 *request_id,Uint32 dev_id);

Uint32
Csp1Ssl20DecryptRecord3Des(
                   n1_request_type request_type,
                   Uint64 context_handle,
                   DesType des_type,
                   Uint16 record_length,
                   Uint8 *record,
                   Uint8 *message,
                   Uint32 *request_id);


/*+****************************************************************************/
 /*! \ingroup SSL_OPS
 *
 * CspSsl20EncryptRecord3Des
 *
 *    Encrypts the SSL record for 3Des cipher when using SSLversion 2.0.
 *
 * \param request_type    CAVIUM_BLOCKING or CAVIUM_NON_BLOCKING
 * \param context_handle    64-bit pointer to context (context_handle\%8=0)
 * \param des_type    DES or DES3_192
 * \param message_length    size of message in bytes (0<=length<=2^16-1)
 * \param message    pointer to length-byte message
 *
 * \param record    pointer to encrypted record
 * \param record_length    SSLv2 record size in bytes
 * \param request_id    Unique ID for this request
 *
 * \param dev_id    Device ID
 *
 * \retval SUCCESS 0
 * \retval FAILURE/PENDING #CspErrorCodes
 */
 /*-***************************************************************************/
Uint32
CspSsl20EncryptRecord3Des(
                n1_request_type request_type,
                Uint64 context_handle,
                DesType des_type,
                Uint16 message_length,
                Uint8 *message,
                Uint16 *record_length,
                Uint8 *record,
                Uint32 *request_id,Uint32 dev_id);

Uint32
Csp1Ssl20EncryptRecord3Des(
                n1_request_type request_type,
                Uint64 context_handle,
                DesType des_type,
                Uint16 message_length,
                Uint8 *message,
                Uint16 *record_length,
                Uint8 *record,
                Uint32 *request_id);





#endif /* CSP1_KERNEL */

#endif /* _CAVIUM_SSL_H_ */
