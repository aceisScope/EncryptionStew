//
//  ECKeyPairManager.m
//  KeyPair
//
//  Created by Liu Binghui on 17/06/15.
//  Copyright (c) 2015 HUT. All rights reserved.
//

#import "ECKeyPairManager.h"
#import <Security/Security.h>
#import<Security/SecBase.h>
#import <CommonCrypto/CommonDigest.h>
#import <CommonCrypto/CommonCryptor.h>

#import "GMEllipticCurveCrypto.h"

static const UInt8 publicKeyIdentifier[] = "cs.hut.publickey222\0";
static const UInt8 privateKeyIdentifier[] = "cs.hut.privatekey111\0";

#define kKeyPairGeneration @"KeyPairGeneration"

@implementation ECKeyPairManager

+ (instancetype)keypair {
    static ECKeyPairManager *shared = nil;
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

- (NSString *)getSelfPublicKeyBase64
{
    OSStatus sanityCheck = noErr;
    NSData * publicKeyBits = nil;
    
    
    NSMutableDictionary * queryPublicKey = [[NSMutableDictionary alloc] init];
    NSData *publicTag = [NSData dataWithBytes:publicKeyIdentifier
                                       length:strlen((const char *)publicKeyIdentifier)];
    
    [queryPublicKey setObject:(__bridge id)kSecClassKey forKey:(__bridge id)kSecClass];
    [queryPublicKey setObject: publicTag forKey:(__bridge id)kSecAttrApplicationTag];
    [queryPublicKey setObject:(__bridge id)kSecAttrKeyTypeEC forKey:(__bridge id)kSecAttrKeyType];
    [queryPublicKey setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)kSecReturnData];
    
    CFTypeRef publicKeyResult;
    
    sanityCheck = SecItemCopyMatching((__bridge CFDictionaryRef)queryPublicKey, (CFTypeRef *)&publicKeyResult);
    
    if (sanityCheck != noErr)
    {
        publicKeyBits = nil;
    }
    
    publicKeyBits = CFBridgingRelease(publicKeyResult);
    
    
    NSString * publicKeyBase64 = [publicKeyBits base64EncodedStringWithOptions:(NSDataBase64Encoding64CharacterLineLength)];
    
    //NSLog(@"fetch public key %@",publicKeyBase64);
    
    return publicKeyBase64;
    
}

- (NSString *)getSelfPrivateKeyBase64
{
    OSStatus sanityCheck = noErr;
    NSData * privateKeyBits = nil;
    
    
    NSMutableDictionary * queryPrivateKey = [[NSMutableDictionary alloc] init];
    NSData *privateTag = [NSData dataWithBytes:privateKeyIdentifier
                                       length:strlen((const char *)privateKeyIdentifier)];
    
    [queryPrivateKey setObject:(__bridge id)kSecClassKey forKey:(__bridge id)kSecClass];
    [queryPrivateKey setObject: privateTag forKey:(__bridge id)kSecAttrApplicationTag];
    [queryPrivateKey setObject:(__bridge id)kSecAttrKeyTypeEC forKey:(__bridge id)kSecAttrKeyType];
    [queryPrivateKey setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)kSecReturnData];
    
    CFTypeRef privateKeyResult;
    
    sanityCheck = SecItemCopyMatching((__bridge CFDictionaryRef)queryPrivateKey, (CFTypeRef *)&privateKeyResult);
    
    if (sanityCheck != noErr)
    {
        privateKeyBits = nil;
    }
    
    privateKeyBits = CFBridgingRelease(privateKeyResult);
    
    
    NSString * privateKeyBase64 = [privateKeyBits base64EncodedStringWithOptions:(NSDataBase64Encoding64CharacterLineLength)];
    
    //NSLog(@"fetch private key %@",privateKeyBase64);
    
    return privateKeyBase64;
}


- (BOOL)addPublicKey:(NSString *)key fromPeer:(NSString *)tag
{
    NSData *d_tag = [NSData dataWithBytes:[tag UTF8String] length:[tag length]];
    
    // Delete any old lingering key with the same tag
    NSMutableDictionary *publicKey = [[NSMutableDictionary alloc] init];
    [publicKey setObject:(__bridge id) kSecClassKey forKey:(__bridge id)kSecClass];
    [publicKey setObject:(__bridge id) kSecAttrKeyTypeEC forKey:(__bridge id)kSecAttrKeyType];
    [publicKey setObject:d_tag forKey:(__bridge id)kSecAttrApplicationTag];
    SecItemDelete((__bridge CFDictionaryRef)publicKey);
    
    CFTypeRef persistKey = nil;
    
    // Add persistent version of the key to system keychain
    NSData *keyData = [[NSData alloc] initWithBase64EncodedString:key options:0];
    [publicKey setObject:keyData forKey:(__bridge id)kSecValueData];
    [publicKey setObject:(__bridge id) kSecAttrKeyClassPublic forKey:(__bridge id)kSecAttrKeyClass];
    [publicKey setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)kSecReturnPersistentRef];
    
    OSStatus secStatus = SecItemAdd((__bridge CFDictionaryRef)publicKey, &persistKey);
    if (persistKey != nil) CFRelease(persistKey);
    
    if ((secStatus != noErr) && (secStatus != errSecDuplicateItem)) {
        return(FALSE);
    }
    
    return(TRUE);
}

- (NSString *)getPublicKeyBase64ForPeerRef:(NSString *)peerName
{
    OSStatus sanityCheck = noErr;
    CFTypeRef * publicKeyRef = nil;
    
    NSData *d_tag = [NSData dataWithBytes:[peerName UTF8String] length:[peerName length]];
    
    NSMutableDictionary *publicKey = [[NSMutableDictionary alloc] init];
    [publicKey setObject:(__bridge id) kSecClassKey forKey:(__bridge id)kSecClass];
    [publicKey setObject:(__bridge id) kSecAttrKeyTypeEC forKey:(__bridge id)kSecAttrKeyType];
    [publicKey setObject:d_tag forKey:( __bridge id)kSecAttrApplicationTag];
    [publicKey setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)kSecReturnData];
    
    sanityCheck = SecItemCopyMatching((__bridge CFDictionaryRef)publicKey, (CFTypeRef *)&publicKeyRef);
    
    if (sanityCheck != noErr)
    {
        publicKeyRef = nil;
    }
    

    NSData* publicKeyBits = CFBridgingRelease(publicKeyRef);
    
    
    NSString * publicKeyBase64 = [publicKeyBits base64EncodedStringWithOptions:(NSDataBase64Encoding64CharacterLineLength)];
    
    //NSLog(@"fetch public key %@",publicKeyBase64);
    
    return publicKeyBase64;
    
}

- (NSData*)getSharedSecretWithPeer:(NSString*)peerName
{
    GMEllipticCurveCrypto *curve = [GMEllipticCurveCrypto cryptoForCurve:
                                    GMEllipticCurveSecp192r1];
    curve.privateKeyBase64 = [self getSelfPrivateKeyBase64];
    NSData *sharedSecret = [curve sharedSecretForPublicKeyBase64:[self getPublicKeyBase64ForPeerRef:peerName]];
    
    return sharedSecret;

}

- (NSString*)getSharedSecretWithPeerPublicKey:(NSString*)key
{
    
    GMEllipticCurveCrypto *curve = [GMEllipticCurveCrypto cryptoForCurve:
                                    GMEllipticCurveSecp192r1];
    curve.privateKeyBase64 = [self getSelfPrivateKeyBase64];
    NSData *sharedSecret = [curve sharedSecretForPublicKeyBase64:key];
    
    return [sharedSecret base64EncodedStringWithOptions:NSDataBase64Encoding64CharacterLineLength];
}

#pragma mark- Private

- (BOOL)generateKeyPairPlease
{
    GMEllipticCurveCrypto *curve = [GMEllipticCurveCrypto generateKeyPairForCurve: GMEllipticCurveSecp192r1];  // the same as prime192v1
    
    NSLog(@"generate public key %@ private key %@",curve.publicKeyBase64,curve.privateKeyBase64);
    
    NSData * publicTag = [NSData dataWithBytes:publicKeyIdentifier
                                        length:strlen((const char *)publicKeyIdentifier)];
    
    // Delete any old lingering key with the same tag
    NSMutableDictionary *publicKey = [[NSMutableDictionary alloc] init];
    [publicKey setObject:(__bridge id) kSecClassKey forKey:(__bridge id)kSecClass];
    [publicKey setObject:(__bridge id) kSecAttrKeyTypeEC forKey:(__bridge id)kSecAttrKeyType];
    [publicKey setObject:publicTag forKey:(__bridge id)kSecAttrApplicationTag];
    SecItemDelete((__bridge CFDictionaryRef)publicKey);
    
    CFTypeRef persistPublicKey = nil;
    
    // Add persistent version of the key to system keychain
    [publicKey setObject:curve.publicKey forKey:(__bridge id)kSecValueData];
    [publicKey setObject:(__bridge id) kSecAttrKeyClassPublic forKey:(__bridge id)kSecAttrKeyClass];
    [publicKey setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)kSecReturnPersistentRef];
    
    OSStatus secPubliceStatus = SecItemAdd((__bridge CFDictionaryRef)publicKey, &persistPublicKey);
    if (persistPublicKey != nil) CFRelease(persistPublicKey);
    
    if ((secPubliceStatus != noErr) && (secPubliceStatus != errSecDuplicateItem)) {
        return(FALSE);
    }
    

    NSData * privateTag = [NSData dataWithBytes:privateKeyIdentifier
                                        length:strlen((const char *)privateKeyIdentifier)];
    
    // Delete any old lingering key with the same tag
    NSMutableDictionary *privateKey = [[NSMutableDictionary alloc] init];
    [privateKey setObject:(__bridge id) kSecClassKey forKey:(__bridge id)kSecClass];
    [privateKey setObject:(__bridge id) kSecAttrKeyTypeEC forKey:(__bridge id)kSecAttrKeyType];
    [privateKey setObject:privateTag forKey:(__bridge id)kSecAttrApplicationTag];
    SecItemDelete((__bridge CFDictionaryRef)privateKey);
    
    CFTypeRef persistPrivateKey = nil;
    
    // Add persistent version of the key to system keychain
    [privateKey setObject:curve.privateKey forKey:(__bridge id)kSecValueData];
    [privateKey setObject:(__bridge id) kSecAttrKeyClassPrivate forKey:(__bridge id)kSecAttrKeyClass];
    [privateKey setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)kSecReturnPersistentRef];
    
    OSStatus secPrivateStatus = SecItemAdd((__bridge CFDictionaryRef)privateKey, &persistPrivateKey);
    if (persistPrivateKey != nil) CFRelease(persistPrivateKey);
    
    if ((secPrivateStatus != noErr) && (secPrivateStatus != errSecDuplicateItem)) {
        return(FALSE);
    }


    return YES;
}



@end
