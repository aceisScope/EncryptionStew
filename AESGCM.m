
//
//  AESGCM.m
//  OmniShare
//
//  Created by Liu Binghui on 24/08/15.
//  Copyright (c) 2015 HUT. All rights reserved.
//

#import "AESGCM.h"
#include <openssl/bio.h>
#include <openssl/evp.h>

/**
 *  https://github.com/openssl/openssl/blob/master/demos/evp/aesgcm.c
 *  https://wiki.openssl.org/index.php/EVP_Authenticated_Encryption_and_Decryption#Authenticated_Encryption_using_GCM_mode
 */

@implementation AESGCM

void logChar(char *tag, unsigned char *content)
{
    NSData *dataData = [NSData dataWithBytes:content length:strlen((char*)content)];
    NSLog(@"%s = %@", tag, dataData);
}

int aes_encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *aad,
                int aad_len, unsigned char *key, unsigned char *iv,int iv_len,
                unsigned char *ciphertext, unsigned char *tag)
{
    EVP_CIPHER_CTX *ctx;
    
    int len;
    
    int ciphertext_len;
    
    
    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();
    
    /* Initialise the encryption operation. */
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL))
        handleErrors();
    
    /* Set IV length if default 12 bytes (96 bits) is not appropriate */
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL))
        handleErrors();
    
    /* Initialise key and IV */
    if(1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv)) handleErrors();
    
    /* Provide any AAD data. This can be called zero or more times as
     * required
     */
    if (aad != NULL || aad_len != 0) {
        if(1 != EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len))
            handleErrors();
    }

    
    /* Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        handleErrors();
    ciphertext_len = len;
    
    /* Finalise the encryption. Normally ciphertext bytes may be written at
     * this stage, but this does not occur in GCM mode
     */
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) handleErrors();
    ciphertext_len += len;
    
    /* Get the tag */
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag))
        handleErrors();
    
    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);
    
    return ciphertext_len;
}


int aes_decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *aad,
                int aad_len, unsigned char *tag, unsigned char *key, unsigned char *iv,int iv_len,
                unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;
    int ret;
    
    //    printf("Ciphertext:\n");
    //    BIO_dump_fp(stdout, gcm_ct, sizeof(gcm_ct));
    
    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();
    
    /* Initialise the decryption operation. */
    if(!EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL))
        handleErrors();
    
    /* Set IV length. Not necessary if this is 12 bytes (96 bits) */
    if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL))
        handleErrors();
    
    //logChar("key",(unsigned char *)gcm_key);
    
    /* Initialise key and IV */
    if(!EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv)) handleErrors();
    
    /* Provide any AAD data. This can be called zero or more times as
     * required
     */
    if (aad != NULL || aad_len != 0) {
        if(!EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len))
            handleErrors();
    }
    
    /* Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary
     */
    if(!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        handleErrors();
    plaintext_len = len;
    
    //    printf("Plaintext:\n");
    //    BIO_dump_fp(stdout, outbuf, len);
    
    /* Set expected tag value. Works in OpenSSL 1.0.1d and later */
    if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag))
        handleErrors();
    
    /* Finalise the decryption. A positive return value indicates success,
     * anything else is a failure - the plaintext is not trustworthy.
     */
    ret = EVP_DecryptFinal_ex(ctx, plaintext, &len);
    
    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);
    
    if(ret > 0)
    {
        /* Success */
        plaintext_len += len;
        return plaintext_len;
    }
    else
    {
        /* Verify failed */
        return -1;
    }
}
void handleErrors()
{
    NSLog(@"error in GCM");
}

+ (BOOL)AES_GCM_encryptWithPlaintext:(NSData*)plaintext aad:(NSData*)aad key:(NSData*)key iv:(NSData*)iv returnCiphertext:(NSData**)ciphertext andTag:(NSData**)tag
{
    unsigned char *plaintextbytes = (unsigned char*)[plaintext bytes];
    unsigned char *aadbytes = (unsigned char*)[aad bytes];
    unsigned char *keybytes = (unsigned char*)[key bytes];
    unsigned char *ivbytes = (unsigned char*)[iv bytes];
    
    unsigned char cipherbuffer[1024];
    unsigned char tagbuffer[16];
    
    int cipher_len = aes_encrypt(plaintextbytes, [plaintext length], aadbytes, [aad length], keybytes, ivbytes, [iv length], cipherbuffer, tagbuffer);
    
    if (cipher_len == -1) {
        return NO;
    }
    
    *ciphertext = [NSData dataWithBytes:cipherbuffer length:cipher_len];
    *tag = [NSData dataWithBytes:tagbuffer length:16];
    
    
    return YES;
}

+ (BOOL)AES_GCM_decryptWithCiphertext:(NSData*)ciphertext aad:(NSData*)aad key:(NSData*)key iv:(NSData*)iv tag:(NSData*)tag returnPlaintext:(NSData**)plaintext
{
    unsigned char *ciphertextbytes = (unsigned char *)[ciphertext bytes];
    unsigned char *aadbytes = (unsigned char*)[aad bytes];
    unsigned char *keybytes = (unsigned char*)[key bytes];
    unsigned char *ivbytes = (unsigned char*)[iv bytes];
    unsigned char *tagbytes = (unsigned char*)[tag bytes];
    
    unsigned char plainbuffer[1024];
    
    int plain_len = aes_decrypt(ciphertextbytes, [ciphertext length], aadbytes, [aad length], tagbytes, keybytes, ivbytes, [iv length], plainbuffer);
    
    if (plain_len == -1) {
        return NO;
    }
    
    *plaintext = [NSData dataWithBytes:plainbuffer length:plain_len];
    
    
    return YES;
}

+ (void)test
{
    /*
    unsigned char ciphtertext[16];
    unsigned char tag[16];
    unsigned char plaintext[16];
    int encrypt = aes_encrypt((unsigned char *)gcm_pt, sizeof(gcm_pt), (unsigned char *)gcm_aad, sizeof(gcm_aad), (unsigned char *)gcm_key, (unsigned char *)gcm_iv, sizeof(gcm_iv), ciphtertext, tag);
    NSLog(@"encrypt result %d",encrypt);
    BIO_dump_fp(stdout, tag, 16);

    int decrypt = aes_decrypt(ciphtertext, sizeof(ciphtertext), (unsigned char *)gcm_aad, sizeof(gcm_aad),(unsigned char *) tag, (unsigned char *)gcm_key, (unsigned char *)gcm_iv,sizeof(gcm_iv), plaintext);
    NSLog(@"decrypt result %d",decrypt);
    BIO_dump_fp(stdout, plaintext, 16);
    */
    
    // http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-spec.pdf
    // test case 3
    NSData *K = [[self class] stringToHexData:@"feffe9928665731c6d6a8f9467308308"];
    NSData *P = [[self class] stringToHexData:@"d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255"];
    NSData *IV = [[self class] stringToHexData:@"cafebabefacedbaddecaf888"];
    

    NSData *ct = [NSData data];
    NSData *_tag = [NSData data];
    NSData *_pt = [NSData data];
    int e_result = [[self class] AES_GCM_encryptWithPlaintext:P aad:NULL key:K iv:IV returnCiphertext:&ct andTag:&_tag];
    NSLog(@"%d %@ %@",e_result, ct, _tag);
    
    int d_result = [[self class] AES_GCM_decryptWithCiphertext:ct aad:NULL key:K iv:IV tag:_tag returnPlaintext:&_pt];
    NSLog(@"%d %@",d_result,_pt);
    
    
}


+ (NSData *) stringToHexData:(NSString *)hexString
{
    int len = [hexString length] / 2;    // Target length
    unsigned char *buf = malloc(len);
    unsigned char *whole_byte = buf;
    char byte_chars[3] = {'\0','\0','\0'};
    
    int i;
    for (i=0; i < [hexString length] / 2; i++) {
        byte_chars[0] = [hexString characterAtIndex:i*2];
        byte_chars[1] = [hexString characterAtIndex:i*2+1];
        *whole_byte = strtol(byte_chars, NULL, 16);
        whole_byte++;
    }
    
    NSData *data = [NSData dataWithBytes:buf length:len];
    free( buf );
    return data;
}

@end
