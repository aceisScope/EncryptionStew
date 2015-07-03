//
//  KeyGenerator.m
//  PeopleNearby
//
//  Created by Liu Binghui on 24/06/15.
//  Copyright (c) 2015 HUT. All rights reserved.
//

#import "KeyGenerator.h"
#include <stdlib.h>
#import <CommonCrypto/CommonCryptor.h>
#import <CommonCrypto/CommonKeyDerivation.h>
#include "NSData+Conversion.h"

const CCAlgorithm kAlgorithm = kCCAlgorithmAES128;
const NSUInteger kAlgorithmKeySize = kCCKeySizeAES128;
const NSUInteger kAlgorithmBlockSize = kCCBlockSizeAES128;
const NSUInteger kAlgorithmIVSize = kCCBlockSizeAES128;
const NSUInteger kPBKDFSaltSize = 8;
const NSUInteger kPBKDFRounds = 10000;  // ~80ms on an iPhone 4


@implementation KeyGenerator

// 160bit = 20Byte

+ (NSData*)ckeyGenerate
{
    uint8_t randomBytes[20];
    int result = SecRandomCopyBytes(kSecRandomDefault, 20, &randomBytes);
    NSData* theData = [[NSData alloc] initWithBytes:randomBytes length:20];
    return theData;
}


// http://robnapier.net/aes-commoncrypto
// https://curlaye.wordpress.com/2013/06/06/keyderivation_commoncryptor/
// All lengths are in bytes - not bits
+ (NSData*)rkeyGenerateWithIrand:(NSData*)irand rrand:(NSData*)rrand
{
    /**************ACHTUNG!!!***************/
    // the length of the key matters
    // https://en.wikipedia.org/wiki/Hash-based_message_authentication_code for SHA-1 64bytes?
    NSMutableData * derivedKey = [NSMutableData dataWithLength:64];
    
    int
    result = CCKeyDerivationPBKDF(kCCPBKDF2,            // algorithm
                                  irand.bytes,  // password
                                  irand.length,  // passwordLength
                                  rrand.bytes,           // salt
                                  rrand.length,          // saltLen
                                  kCCPRFHmacAlgSHA1,    // PRF
                                  kPBKDFRounds,         // rounds
                                  derivedKey.mutableBytes, // derivedKey
                                  derivedKey.length); // derivedKeyLen
    
    // Do not log password here
    NSAssert(result == kCCSuccess,
             @"Unable to create AES key for password: %d", result);;
    
    return derivedKey;
}

+ (NSString *) randomStringGeneratorWithLength: (int) len
{
    
    NSString *letters = @"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    
    NSMutableString *randomString = [NSMutableString stringWithCapacity: len];
    
    for (int i=0; i<len; i++) {
        [randomString appendFormat: @"%C", [letters characterAtIndex: arc4random_uniform([letters length])]];
    }
    
    return randomString;
}


+ (NSString *)doHmacSha1:(NSString *)dataIn key:(NSData *)key
{
    NSData *data = [dataIn dataUsingEncoding:NSUTF8StringEncoding];
    NSMutableData *macOut = [NSMutableData dataWithLength:CC_SHA1_DIGEST_LENGTH];
    CCHmac( kCCHmacAlgSHA256,
           key.bytes, key.length,
           data.bytes, data.length,
           macOut.mutableBytes);
    
    NSString *hash = [macOut base64EncodedStringWithOptions:0];
    return hash;
}




@end
