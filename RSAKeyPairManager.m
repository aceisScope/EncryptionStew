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
 *  https://developer.apple.com/library/ios/samplecode/CryptoExercise/Listings/Classes_SecKeyWrapper_m.html#//apple_ref/doc/uid/DTS40008019-Classes_SecKeyWrapper_m-DontLinkElementID_17`
 *  Encrypting and Decrypting Data
 *
 *  http://blog.wingsofhermes.org/?p=42
 *  special for android
 */



CFDictionaryRef myDictionary;


const size_t BUFFER_SIZE = 64; //64;
const size_t CIPHER_BUFFER_SIZE = 1024;
const size_t KEY_SIZE = 2048;
const uint32_t DECRYPT_PADDING =kSecPaddingPKCS1; //  kSecPaddingOAEP;
const uint32_t ENCRYPT_PADDING= kSecPaddingPKCS1;


//Defines unique strings to be added as attributes to the private and public key keychain items to make them easier to find later
static const UInt8 publicKeyIdentifier[] = "cs.tkk.publickey.new\0";
static const UInt8 privateKeyIdentifier[] = "cs.tkk.privatekey.new\0";



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
    uint8_t*  plainBuffer = (uint8_t*)[dataToEncrypt bytes];
    size_t plainBufferSize = [dataToEncrypt length];;
    

    OSStatus status = noErr;

    
    SecKeyRef publicKey=[self getPublicKeyRef];
    //NSLog(@"ENCRYPT SecKeyGetBlockSize() public = %lu", SecKeyGetBlockSize(publicKey));
    
    size_t keyBlockSize = SecKeyGetBlockSize(publicKey);
    
    size_t cipherBufferSize = keyBlockSize;
    uint8_t*  cipherBuffer = malloc( cipherBufferSize * sizeof(uint8_t) );
    memset((void *)cipherBuffer, 0x0, cipherBufferSize);
    
    
    //NSLog(@"ENCRYPT plaintext %s length %lu",plainBuffer,plainBufferSize);
    
    //  Error handling
    // Encrypt using the public.
    status = SecKeyEncrypt(publicKey,
                           ENCRYPT_PADDING,
                           plainBuffer,
                           plainBufferSize,
                           cipherBuffer,
                           &cipherBufferSize
                           );
    //NSLog(@"ENCRYPT encryption result code: %d cipher buffer %@ (size: %lu)", (int)status,[self hexStringWithData:cipherBuffer ofLength:strlen((char*)cipherBuffer)], strlen((char*)cipherBuffer));
    //NSLog(@"ENCRYPT plain buffer %s (size %lu)",plainBuffer,plainBufferSize);
    //NSLog(@"encrypted text: %s", cipherBuffer);
    

//    NSMutableData *data=[[NSMutableData alloc] init];
//    [data appendBytes:cipherBuffer length:strlen( (char*)cipherBuffer ) ];
    
    NSData *data = [NSData dataWithBytes:cipherBuffer length:cipherBufferSize];
    free(cipherBuffer);
    
    if (publicKey) CFRelease(publicKey);
    
    return data;
}

- (NSData *)encrypt:(NSData *)dataToEncrypt WithPublicKeyOfPeer:(NSString *)tag
{
    uint8_t*  plainBuffer = (uint8_t*)[dataToEncrypt bytes];
    size_t plainBufferSize = [dataToEncrypt length];;
    
    
    OSStatus status = noErr;
    
    SecKeyRef key=[self getPeerKeyRef:tag];
   
    
    size_t keyBlockSize = SecKeyGetBlockSize(key);
    
    //NSLog(@"ENCRYPT SecKeyGetBlockSize() public = %lu", keyBlockSize);
    
    size_t cipherBufferSize = keyBlockSize;
    uint8_t*  cipherBuffer = malloc( cipherBufferSize * sizeof(uint8_t) );
    memset((void *)cipherBuffer, 0x0, cipherBufferSize);
    
    //NSLog(@"ENCRYPT plaintext %s length %lu",plainBuffer,plainBufferSize);
    //  Error handling
    // Encrypt using the public.
    status = SecKeyEncrypt(key,
                           ENCRYPT_PADDING,
                           plainBuffer,
                           plainBufferSize,
                           cipherBuffer,
                           &cipherBufferSize
                           );
    
    //NSLog(@"ENCRYPT encryption result code: %d cipher buffer %@ (size: %lu)", (int)status,[self hexStringWithData:cipherBuffer ofLength:strlen((char*)cipherBuffer)], strlen((char*)cipherBuffer));
    
    if (status != noErr) return nil;
    
    NSData *data = [NSData dataWithBytes:cipherBuffer length:cipherBufferSize];
    free(cipherBuffer);
    
    if (key) CFRelease(key);
    
    return data;
}


- (NSData*)decryptWithPrivateKey: (NSData *)dataToDecrypt
{
    
    uint8_t*  cipherBuffer = (uint8_t*)[dataToDecrypt bytes];
    size_t cipherBufferSize = (size_t)[dataToDecrypt length];
    
    
    OSStatus status = noErr;

    
    //NSLog(@"DECRYPT cipher buffer %@ (size %lu)",[self hexStringWithData:cipherBuffer ofLength:strlen((char*)cipherBuffer)],cipherBufferSize);
    

    SecKeyRef privateKey = [self getPrivateKeyRef];
    
    size_t keyBlockSize = SecKeyGetBlockSize(privateKey);
    size_t plainBufferSize = keyBlockSize;
    
    uint8_t*  plainBuffer = malloc( plainBufferSize * sizeof(uint8_t) );
    memset((void *)plainBuffer, 0x0, plainBufferSize);
    
    
    //  Error handling
    status = SecKeyDecrypt(privateKey,
                           DECRYPT_PADDING,
                           cipherBuffer,
                           cipherBufferSize,
                           plainBuffer,
                           &plainBufferSize
                           );
    
    //NSLog(@"DECRYPT cipher buffer %@ (size %lu)",[self hexStringWithData:cipherBuffer ofLength:cipherBufferSize],cipherBufferSize);
    NSLog(@"DECRYPT decryption result code: %d plain buffer %s(size: %lu)", (int)status,plainBuffer, strlen((char*)plainBuffer));
    //NSLog(@"FINAL decrypted text: %s", plainBuffer);
    
    
    
    
//    NSMutableData *data=[[NSMutableData alloc] init];
//    [data appendBytes:plainBuffer length:strlen( (char*)plainBuffer ) ];
    
    NSData *data = [NSData dataWithBytes:plainBuffer length:plainBufferSize];
    free(plainBuffer);
    
    if(privateKey) CFRelease(privateKey);
    
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
    
    //NSLog(@"GETSELFPUBLIC  publickeybits = %d %@", [publicKeyBits length],publicKeyBits);
    
    
    return publicKeyBits;
}


- (NSString *)getSelfPublicKeyBase64
{
    NSData *publicKeyBits = [self getSelfPublicKeyBits];
    
    NSString * publicKeyBase64 = [publicKeyBits base64EncodedStringWithOptions:(NSDataBase64Encoding64CharacterLineLength)];
    
    return publicKeyBase64;
}


// Helper function for ASN.1 encoding

size_t encodeLength(unsigned char * buf, size_t length) {
    
    // encode length in ASN.1 DER format
    if (length < 128) {
        buf[0] = length;
        return 1;
    }
    
    size_t i = (length / 256) + 1;
    buf[0] = i + 0x80;
    for (size_t j = 0 ; j < i; ++j) {         buf[i - j] = length & 0xFF;         length = length >> 8;
    }
    
    return i + 1;
}

- (NSData *)getSelfPublicKeyBitsForAndroid
{
    static const unsigned char _encodedRSAEncryptionOID[15] = {
        
        /* Sequence of length 0xd made up of OID followed by NULL */
        0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
        0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00
        
    };
    
    // OK - that gives us the "BITSTRING component of a full DER
    // encoded RSA public key - we now need to build the rest
    NSData * publicKeyBits = [self getSelfPublicKeyBits];
    
    unsigned char builder[15];
    NSMutableData * encKey = [[NSMutableData alloc] init];
    int bitstringEncLength;
    
    // When we get to the bitstring - how will we encode it?
    if  ([publicKeyBits length ] + 1  < 128 )
        bitstringEncLength = 1 ;
    else
        bitstringEncLength = (([publicKeyBits length ] +1 ) / 256 ) + 2 ;
    
    // Overall we have a sequence of a certain length
    builder[0] = 0x30;    // ASN.1 encoding representing a SEQUENCE
    // Build up overall size made up of -
    // size of OID + size of bitstring encoding + size of actual key
    size_t i = sizeof(_encodedRSAEncryptionOID) + 2 + bitstringEncLength +
    [publicKeyBits length];
    size_t j = encodeLength(&builder[1], i);
    [encKey appendBytes:builder length:j +1];
    
    // First part of the sequence is the OID
    [encKey appendBytes:_encodedRSAEncryptionOID
                 length:sizeof(_encodedRSAEncryptionOID)];
    
    // Now add the bitstring
    builder[0] = 0x03;
    j = encodeLength(&builder[1], [publicKeyBits length] + 1);
    builder[j+1] = 0x00;
    [encKey appendBytes:builder length:j + 2];
    
    // Now the actual key
    [encKey appendData:publicKeyBits];
    
    return encKey;
}

- (NSString *)getSelfPublicKeyBase64ForAndroid
{
    NSData *publicKeyBits = [self getSelfPublicKeyBitsForAndroid];
    
    NSString * publicKeyBase64 = [publicKeyBits base64EncodedStringWithOptions:(NSDataBase64Encoding64CharacterLineLength)];
    
    return publicKeyBase64;
}


- (NSData *)getSelfPrivateKeyBits
{
    OSStatus sanityCheck = noErr;
    NSData * privateKeyBits = nil;
    
    
    NSMutableDictionary * queryPrivateKey = [[NSMutableDictionary alloc] init];
    NSData *privateTag = [NSData dataWithBytes:privateKeyIdentifier
                                       length:strlen((const char *)privateKeyIdentifier)];
    
    [queryPrivateKey setObject:(__bridge id)kSecClassKey forKey:(__bridge id)kSecClass];
    [queryPrivateKey setObject: privateTag forKey:(__bridge id)kSecAttrApplicationTag];
    [queryPrivateKey setObject:(__bridge id)kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
    [queryPrivateKey setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)kSecReturnData];
    
    CFTypeRef privateKeyResult;
    
    sanityCheck = SecItemCopyMatching((__bridge CFDictionaryRef)queryPrivateKey, (CFTypeRef *)&privateKeyResult);
    
    if (sanityCheck != noErr)
    {
        privateKeyBits = nil;
    }
    
    privateKeyBits = CFBridgingRelease(privateKeyResult);
    
    return privateKeyBits;
}

- (NSString *)getSelfPrivateKeyBase64
{
    NSData *privateKeyBits = [self getSelfPrivateKeyBits];
    
    NSString * privateKeyBase64 = [privateKeyBits base64EncodedStringWithOptions:(NSDataBase64Encoding64CharacterLineLength)];
    
    return privateKeyBase64;
}

- (BOOL)addPublicKey:(NSData *)key withTag:(NSString *)tag
{
    //NSLog(@"ADDPEERKEY %d %@",[key length],key);
    
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
    
    //NSLog(@"ADDPEERKEY SecKeyGetBlockSize() public = %lu", SecKeyGetBlockSize(keyRef));
    
    
    if (keyRef == nil) return(FALSE);
    
    
    return(TRUE);
}

- (BOOL)addAndroidPublicKey:(NSData*)rawFormattedKey withTag:(NSString*)tag
{
    
    /* Now strip the uncessary ASN encoding guff at the start */
    unsigned char * bytes = (unsigned char *)[rawFormattedKey bytes];
    size_t bytesLen = [rawFormattedKey length];
    
    /* Strip the initial stuff */
    size_t i = 0;
    if (bytes[i++] != 0x30)
        return FALSE;
    
    /* Skip size bytes */
    if (bytes[i] > 0x80)
        i += bytes[i] - 0x80 + 1;
    else
        i++;
    
    if (i >= bytesLen)
        return FALSE;
    
    if (bytes[i] != 0x30)
        return FALSE;
    
    /* Skip OID */
    i += 15;
    
    if (i >= bytesLen - 2)
        return FALSE;
    
    if (bytes[i++] != 0x03)
        return FALSE;
    
    /* Skip length and null */
    if (bytes[i] > 0x80)
        i += bytes[i] - 0x80 + 1;
    else
        i++;
    
    if (i >= bytesLen)
        return FALSE;
    
    if (bytes[i++] != 0x00)
        return FALSE;
    
    if (i >= bytesLen)
        return FALSE;
    
    /* Here we go! */
    NSData * extractedKey = [NSData dataWithBytes:&bytes[i] length:bytesLen - i];
    
    BOOL result = [self addPublicKey:extractedKey withTag:tag];
    
    return result;
    
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
    SecKeyRef publicKey = NULL;
    SecKeyRef privateKey = NULL;
    
    //Sets the key-type attribute for the key pair to RSA
    [keyPairAttr setObject:(__bridge id)kSecAttrKeyTypeRSA
                    forKey:(__bridge id)kSecAttrKeyType];
    
    //Sets the key-size attribute for the key pair to 1024 bits
    [keyPairAttr setObject:[NSNumber numberWithInt:KEY_SIZE]
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
    
    if(publicKey) CFRelease(publicKey);
    if(privateKey) CFRelease(privateKey);
}


- (SecKeyRef)getPublicKeyRef
{
    OSStatus resultCode = noErr;
    SecKeyRef publicKeyReference = NULL;
    
//    if(publicKey == NULL) {
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
        
        
//    } else {
//        publicKeyReference = publicKey;
//    }
    
    return publicKeyReference;
}

- (SecKeyRef)getPrivateKeyRef
{
    OSStatus resultCode = noErr;
    SecKeyRef privateKeyReference = NULL;
    
//    if(privateKey == NULL) {
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
        
//    } else {
//        privateKeyReference = privateKey;
//    }
    
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
    [publicKey setObject:(__bridge id) kSecAttrKeyClassPublic forKey:(__bridge id)kSecAttrKeyClass];
    SecItemCopyMatching((__bridge CFDictionaryRef)publicKey,(CFTypeRef *)&persistentRef);
    
    
    return persistentRef;
    
}

- (NSString*) hexStringWithData: (unsigned char*) data ofLength: (NSUInteger) len
{
    NSMutableString *tmp = [NSMutableString string];
    for (NSUInteger i=0; i<len; i++)
        [tmp appendFormat:@"%02x", data[i]];
    return [NSString stringWithString:tmp];
}

- (NSData *)getPublicKeyExp
{
    NSData* pk = [self getSelfPublicKeyBits];
    if (pk == NULL) return NULL;
    
    int iterator = 0;
    
    iterator++; // TYPE - bit stream - mod + exp
    [self derEncodingGetSizeFrom:pk at:&iterator]; // Total size
    
    iterator++; // TYPE - bit stream mod
    int mod_size = [self derEncodingGetSizeFrom:pk at:&iterator];
    iterator += mod_size;
    
    iterator++; // TYPE - bit stream exp
    int exp_size = [self derEncodingGetSizeFrom:pk at:&iterator];
    
    return [pk subdataWithRange:NSMakeRange(iterator, exp_size)];
}

- (NSData *)getPublicKeyMod
{
    NSData* pk = [self getSelfPublicKeyBits];
    if (pk == NULL) return NULL;
    
    int iterator = 0;
    
    iterator++; // TYPE - bit stream - mod + exp
    [self derEncodingGetSizeFrom:pk at:&iterator]; // Total size
    
    iterator++; // TYPE - bit stream mod
    int mod_size = [self derEncodingGetSizeFrom:pk at:&iterator];
    
    return [pk subdataWithRange:NSMakeRange(iterator, mod_size)];
}
- (int)derEncodingGetSizeFrom:(NSData*)buf at:(int*)iterator
{
    const uint8_t* data = [buf bytes];
    int itr = *iterator;
    int num_bytes = 1;
    int ret = 0;
    
    if (data[itr] > 0x80) {
        num_bytes = data[itr] - 0x80;
        itr++;
    }
    
    for (int i = 0 ; i < num_bytes; i++) ret = (ret * 0x100) + data[itr + i];
    
    *iterator = itr + num_bytes;
    return ret;
}

@end
