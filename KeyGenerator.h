//
//  KeyGenerator.h
//  PeopleNearby
//
//  Created by Liu Binghui on 24/06/15.
//  Copyright (c) 2015 HUT. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface KeyGenerator : NSObject

/**
 *  generate ckey, {0.1} 160 means 20 randoms bytes
 *  http://stackoverflow.com/questions/17607968/any-shortcut-to-generate-a-16-byte-random-data-as-initialisation-vector-for-aes1
 *
 *  @return 20 bytes key
 */
+ (NSData*)ckeyGenerate;



/**
 *  KDF for rkey
 *  http://opensource.apple.com/source/CommonCrypto/CommonCrypto-55010/CommonCrypto/CommonKeyDerivation.h
 *
 *  @param irand irand as password
 *  @param rrand rrand as salt
 *
 *  @return rkey
 */

+ (NSData*)rkeyGenerateWithIrand:(NSData*)irand rrand:(NSData*)rrand;



/**
 *  HMAC SHA1 hash
 *
 *  @param dataIn input string in UTF8 encoding
 *  @param key    key for hashing
 *
 *  @return hashed value in base 64 string
 */
+ (NSString *)doHmacSha1:(NSString *)dataIn key:(NSData *)key;

@end
