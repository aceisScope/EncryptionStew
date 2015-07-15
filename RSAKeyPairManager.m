//
//  KeyPairManager.m
//  KeyPair
//
//  Created by Liu Binghui on 15/06/15.
//  Copyright (c) 2015 HUT. All rights reserved.
//

#import "RSAKeyPairManager.h"
#import <Security/Security.h>
#import<Security/SecBase.h>
#import <CommonCrypto/CommonDigest.h>
#import <CommonCrypto/CommonCryptor.h>

/**
 *  https://developer.apple.com/library/mac/documentation/Security/Conceptual/CertKeyTrustProgGuide/iPhone_Tasks/iPhone_Tasks.html
 *  Encrypting and Decrypting Data
 */

#define kChosenCipherBlockSize 16
#define kChosenCipherKeySize 8
SecKeyRef oPublicKey;
SecKeyRef oPrivateKey;

CFDictionaryRef myDictionary;

CFTypeRef keys[2];
CFTypeRef values[2];
const size_t BUFFER_SIZE = 64;
const size_t CIPHER_BUFFER_SIZE = 1024;
const uint32_t PADDING = kSecPaddingNone;


//Defines unique strings to be added as attributes to the private and public key keychain items to make them easier to find later
static const UInt8 publicKeyIdentifier[] = "cs.hut.publickey222\0";
static const UInt8 privateKeyIdentifier[] = "cs.hut.privatekey111\0";

SecKeyRef publicKey;
SecKeyRef privateKey;


#define kKeyPairGeneration @"KeyPairGeneration"

@implementation RSAKeyPairManager

+ (instancetype)keypair {
    static RSAKeyPairManager *shared = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        shared = [[self alloc] init];
    });
    return shared;
}

- (id)init {
    if (self = [super init])
    {
        // check if key pair generation has already been done
        if (![[NSUserDefaults standardUserDefaults] objectForKey:kKeyPairGeneration])
        {
            [self generateKeyPairPlease];
            [[NSUserDefaults standardUserDefaults] setObject:@"YES" forKey:kKeyPairGeneration];
            [[NSUserDefaults standardUserDefaults] synchronize];
        }
    }
    return self;
}

#pragma mark - Public
- (NSData *)encryptWithPublicKey:(NSData *)dataToEncrypt
{
    char *plainTemp = (char*) [dataToEncrypt bytes];
    //plainTemp[[dataToEncrypt length] - 1]='\0';
    
    int len = [dataToEncrypt length];  // don't use strlen(plainTemp) since its last bit may not be \0
    if (len > BUFFER_SIZE) len = BUFFER_SIZE-1;
    
    uint8_t* plainBuffer = (uint8_t *)calloc(BUFFER_SIZE, sizeof(uint8_t));
    uint8_t* cipherBuffer = (uint8_t *)calloc(CIPHER_BUFFER_SIZE, sizeof(uint8_t));
    
    strncpy( (char *)plainBuffer,plainTemp, len);

    
    NSLog(@"init() plainBuffer: %s", plainBuffer);
    [self encryptWithPublicKey:(UInt8 *)plainBuffer cipherBuffer:cipherBuffer];
    NSLog(@"encrypted data: %s", cipherBuffer);
    
    
    NSMutableData *data=[[NSMutableData alloc] init];
    [data appendBytes:cipherBuffer length:strlen( (char*)cipherBuffer ) + 1];

    
    return data;
}

- (NSData*)decryptWithPrivateKey: (NSData *)dataToDecrypt
{
    char* cipher = (char*) [dataToDecrypt bytes];
    
    uint8_t* cipherBuffer = (uint8_t *)calloc(CIPHER_BUFFER_SIZE, sizeof(uint8_t));
    uint8_t* decryptedBuffer = (uint8_t *)calloc(BUFFER_SIZE, sizeof(uint8_t));
    
    strncpy( (char *)cipherBuffer, cipher, strlen(cipher));
    
    NSLog(@"CIPHER %s",cipherBuffer);
    [self decryptWithPrivateKey:cipherBuffer plainBuffer:decryptedBuffer];
    NSLog(@"decrypted data: %s", decryptedBuffer);
    
    
    NSMutableData *data=[[NSMutableData alloc] init];
    [data appendBytes:decryptedBuffer length:strlen( (char*)decryptedBuffer ) + 1];
    
    return data;
    
}

- (NSData *)getSelfPublicKeyBits
{
    OSStatus sanityCheck = noErr;
    NSData * publicKeyBits = nil;
    
    
    NSMutableDictionary * queryPublicKey = [[NSMutableDictionary alloc] init];
    NSData *publicTag = [NSData dataWithBytes:publicKeyIdentifier
                                       length:strlen((const char *)publicKeyIdentifier)];
    
    [queryPublicKey setObject:(__bridge id)kSecClassKey forKey:(__bridge id)kSecClass];
    [queryPublicKey setObject: publicTag forKey:(__bridge id)kSecAttrApplicationTag];
    [queryPublicKey setObject:(__bridge id)kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
    [queryPublicKey setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)kSecReturnData];
    
    CFTypeRef publicKeyResult;
    
    sanityCheck = SecItemCopyMatching((__bridge CFDictionaryRef)queryPublicKey, (CFTypeRef *)&publicKeyResult);
    
    if (sanityCheck != noErr)
    {
        publicKeyBits = nil;
    }
    
    publicKeyBits = CFBridgingRelease(publicKeyResult);
    
    return publicKeyBits;
}

- (BOOL)addPublicKey:(NSData *)key withTag:(NSString *)tag
{
    NSData *d_tag = [NSData dataWithBytes:[tag UTF8String] length:[tag length]];
    
    // Delete any old lingering key with the same tag
    NSMutableDictionary *publicKey = [[NSMutableDictionary alloc] init];
    [publicKey setObject:(__bridge id) kSecClassKey forKey:(__bridge id)kSecClass];
    [publicKey setObject:(__bridge id) kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
    [publicKey setObject:d_tag forKey:(__bridge id)kSecAttrApplicationTag];
    SecItemDelete((__bridge CFDictionaryRef)publicKey);
    
    CFTypeRef persistKey = nil;
    
    // Add persistent version of the key to system keychain
    [publicKey setObject:key forKey:(__bridge id)kSecValueData];
    [publicKey setObject:(__bridge id) kSecAttrKeyClassPublic forKey:(__bridge id)kSecAttrKeyClass];
    [publicKey setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)kSecReturnPersistentRef];
    
    OSStatus secStatus = SecItemAdd((__bridge CFDictionaryRef)publicKey, &persistKey);
    if (persistKey != nil) CFRelease(persistKey);
    
    if ((secStatus != noErr) && (secStatus != errSecDuplicateItem)) {
        return(FALSE);
    }
    
    // Now fetch the SecKeyRef version of the key
    SecKeyRef keyRef = nil;
    
    [publicKey removeObjectForKey:(__bridge id)kSecValueData];
    [publicKey removeObjectForKey:(__bridge id)kSecReturnPersistentRef];
    [publicKey setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)kSecReturnRef
     ];
    [publicKey setObject:(__bridge id) kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
    SecItemCopyMatching((__bridge CFDictionaryRef)publicKey,(CFTypeRef *)&keyRef);
    
    
    if (keyRef == nil) return(FALSE);
    
    
    return(TRUE);
}

- (NSData *)encrypt:(NSData *)dataToEncrypt WithPublicKeyOfPeer:(NSString *)tag
{
    char *plainTemp = (char*) [dataToEncrypt bytes];
    //plainTemp[[dataToEncrypt length] - 1]='\0';
    
    int len = [dataToEncrypt length];  // don't use strlen(plainTemp) since its last bit may not be \0
    if (len > BUFFER_SIZE) len = BUFFER_SIZE-1;
    
    uint8_t* plainBuffer = (uint8_t *)calloc(BUFFER_SIZE, sizeof(uint8_t));
    uint8_t* cipherBuffer = (uint8_t *)calloc(CIPHER_BUFFER_SIZE, sizeof(uint8_t));
    
    strncpy( (char *)plainBuffer,plainTemp, len);
    
    
    OSStatus status = noErr;
    
    
    size_t plainBufferSize = strlen((char *)plainBuffer);
    size_t cipherBufferSize = CIPHER_BUFFER_SIZE;
    SecKeyRef key=[self getPeerKeyRef:tag];
    //  Error handling
    // Encrypt using the public.
    status = SecKeyEncrypt(key,
                           PADDING,
                           plainBuffer,
                           plainBufferSize,
                           &cipherBuffer[0],
                           &cipherBufferSize
                           );

    NSLog(@"peer :%@ encrypted data: %s",tag, cipherBuffer);
    
    if (status != noErr) return nil;
    
    NSMutableData *data=[[NSMutableData alloc] init];
    [data appendBytes:cipherBuffer length:strlen( (char*)cipherBuffer ) + 1];
    
    
    return data;

}

#pragma mark- Private

- (void)generateKeyPairPlease
{
    // clear previous record
    [[NSUserDefaults standardUserDefaults] setObject:nil forKey:kKeyPairGeneration];
    [[NSUserDefaults standardUserDefaults] synchronize];
    
    OSStatus status = noErr;
    NSMutableDictionary *privateKeyAttr = [[NSMutableDictionary alloc] init];
    NSMutableDictionary *publicKeyAttr = [[NSMutableDictionary alloc] init];
    NSMutableDictionary *keyPairAttr = [[NSMutableDictionary alloc] init];
    
    NSData * publicTag = [NSData dataWithBytes:publicKeyIdentifier
                                        length:strlen((const char *)publicKeyIdentifier)];
    
    NSData * privateTag = [NSData dataWithBytes:privateKeyIdentifier
                                         length:strlen((const char *)privateKeyIdentifier)];
    publicKey = NULL;
    privateKey = NULL;
    
    //Sets the key-type attribute for the key pair to RSA
    [keyPairAttr setObject:(__bridge id)kSecAttrKeyTypeRSA
                    forKey:(__bridge id)kSecAttrKeyType];
    
    //Sets the key-size attribute for the key pair to 1024 bits
    [keyPairAttr setObject:[NSNumber numberWithInt:1024]
                    forKey:(__bridge id)kSecAttrKeySizeInBits];
    
    //Sets an attribute specifying that the private key is to be stored permanently (that is, put into the keychain)
    [privateKeyAttr setObject:[NSNumber numberWithBool:YES]
                       forKey:(__bridge id)kSecAttrIsPermanent];
    
    [privateKeyAttr setObject:privateTag
                       forKey:(__bridge id)kSecAttrApplicationTag];
    
    //Sets an attribute specifying that the public key is to be stored permanently (that is, put into the keychain)
    [publicKeyAttr setObject:[NSNumber numberWithBool:YES]
                      forKey:(__bridge id)kSecAttrIsPermanent];
    
    [publicKeyAttr setObject:publicTag
                      forKey:(__bridge id)kSecAttrApplicationTag];
    
    [keyPairAttr setObject:privateKeyAttr
                    forKey:(__bridge id)kSecPrivateKeyAttrs];
    
    [keyPairAttr setObject:publicKeyAttr
                    forKey:(__bridge id)kSecPublicKeyAttrs];
    
    status = SecKeyGeneratePair((__bridge CFDictionaryRef)keyPairAttr,
                                &publicKey, &privateKey);
}

- (void)encryptWithPublicKey:(uint8_t *)plainBuffer cipherBuffer:(uint8_t *)cipherBuffer
{
    //  NSLog(@"== encryptWithPublicKey()");
    
    OSStatus status = noErr;
    
    //NSLog(@"** original plain text 0: %s", plainBuffer);
    
    size_t plainBufferSize = strlen((char *)plainBuffer);
    size_t cipherBufferSize = CIPHER_BUFFER_SIZE;
    SecKeyRef key=[self getPublicKeyRef];
    //NSLog(@"SecKeyGetBlockSize() public = %lu", SecKeyGetBlockSize(key));
    //  Error handling
    // Encrypt using the public.
    status = SecKeyEncrypt(key,
                           PADDING,
                           plainBuffer,
                           plainBufferSize,
                           &cipherBuffer[0],
                           &cipherBufferSize
                           );
    // NSLog(@"encryption result code: %d (size: %d)", status, cipherBufferSize);
    //NSLog(@"encrypted text: %s", cipherBuffer);
}
- (void)decryptWithPrivateKey:(uint8_t *)cipherBuffer plainBuffer:(uint8_t *)plainBuffer
{
    OSStatus status = noErr;
    
    size_t cipherBufferSize = strlen((char *)cipherBuffer);
    
    //NSLog(@"decryptWithPrivateKey: length of buffer: %lu", BUFFER_SIZE);
    //NSLog(@"decryptWithPrivateKey: length of cipher: %lu", cipherBufferSize);
    
    // DECRYPTION
    size_t plainBufferSize = BUFFER_SIZE;
    
    //  Error handling
    status = SecKeyDecrypt([self getPrivateKeyRef],
                           PADDING,
                           &cipherBuffer[0],
                           cipherBufferSize,
                           &plainBuffer[0],
                           &plainBufferSize
                           );
    //NSLog(@"decryption result code: %lu (size: %lu)", status, plainBufferSize);
    NSLog(@"FINAL decrypted text: %s", plainBuffer);
    
}

- (SecKeyRef)getPublicKeyRef
{
    OSStatus resultCode = noErr;
    SecKeyRef publicKeyReference = NULL;
    
    if(publicKey == NULL) {
        NSMutableDictionary * queryPublicKey = [[NSMutableDictionary alloc] init];
        
        NSData *publicTag = [NSData dataWithBytes:publicKeyIdentifier
                             
                                           length:strlen((const char *)publicKeyIdentifier)];
        
        // Set the public key query dictionary.
        [queryPublicKey setObject:(__bridge id)kSecClassKey forKey:(__bridge id)kSecClass];
        
        [queryPublicKey setObject:publicTag forKey:(__bridge id)kSecAttrApplicationTag];
        
        [queryPublicKey setObject:(__bridge id)kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
        
        [queryPublicKey setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)kSecReturnRef];
        
        // Get the key.
        resultCode = SecItemCopyMatching((__bridge CFDictionaryRef)queryPublicKey, (CFTypeRef *)&publicKeyReference);
        NSLog(@"getPublicKey: result code: %lu", resultCode);
        
        if(resultCode != noErr)
        {
            publicKeyReference = NULL;
        }
        
        
    } else {
        publicKeyReference = publicKey;
    }
    
    return publicKeyReference;
}

- (SecKeyRef)getPrivateKeyRef
{
    OSStatus resultCode = noErr;
    SecKeyRef privateKeyReference = NULL;
    
    if(privateKey == NULL) {
        NSMutableDictionary * queryPrivateKey = [[NSMutableDictionary alloc] init];
        NSData *privateTag = [NSData dataWithBytes:privateKeyIdentifier
                              
                                            length:strlen((const char *)privateKeyIdentifier)];
        // Set the private key query dictionary.
        [queryPrivateKey setObject:(__bridge id)kSecClassKey forKey:(__bridge id)kSecClass];
        [queryPrivateKey setObject:privateTag forKey:(__bridge id)kSecAttrApplicationTag];
        [queryPrivateKey setObject:(__bridge id)kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
        [queryPrivateKey setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)kSecReturnRef];
        
        // Get the key.
        resultCode = SecItemCopyMatching((__bridge CFDictionaryRef)queryPrivateKey, (CFTypeRef *)&privateKeyReference);
        //NSLog(@"getPrivateKey: result code: %lu", resultCode);
        
        if(resultCode != noErr)
        {
            privateKeyReference = NULL;
        }
        
    } else {
        privateKeyReference = privateKey;
    }
    
    return privateKeyReference;
}



- (SecKeyRef)getPeerKeyRef:(NSString *)peerName {
    SecKeyRef persistentRef = NULL;
    
    
    NSData *d_tag = [NSData dataWithBytes:[peerName UTF8String] length:[peerName length]];
    NSMutableDictionary *publicKey = [[NSMutableDictionary alloc] init];
    [publicKey setObject:(__bridge id) kSecClassKey forKey:(__bridge id)kSecClass];
    [publicKey setObject:(__bridge id) kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
    [publicKey setObject:d_tag forKey:(__bridge id)kSecAttrApplicationTag];
    [publicKey setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)kSecReturnRef];
    [publicKey setObject:(__bridge id) kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
    [publicKey setObject:(__bridge id) kSecAttrKeyClassPublic forKey:(__bridge id)kSecAttrKeyClass];
    SecItemCopyMatching((__bridge CFDictionaryRef)publicKey,(CFTypeRef *)&persistentRef);
    
    
    return persistentRef;
    
}

@end
