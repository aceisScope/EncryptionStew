//
//  SRPClient.h
//  SRPtest
//
//  Created by Liu Binghui on 09/07/15.
//  Copyright (c) 2015 HUT. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import "srp.h"

@interface SRPClient : NSObject

+ (instancetype)client;

/**
 *  client generate A     ------ step 1
 *
 *  @param _username user name
 *  @param _password password
 */
- (void)generateClientByteAWithPassword:(const char*)_username andPassword:(const char*)_password;

/**
 *  generate session key with B and salt from host    ------ step 4
 *
 *  @param _byteB B from host in bytes
 *  @param _lenB  length of B
 *  @param _byteS salt from host in bytes
 *  @param _lenS  length of salt
 */
- (void)generateSessionKeyWithBytesB:(const unsigned char*)_byteB lengthB:(int)_lenB salt:(const unsigned char*)_byteS lengthSalt:(int)_lenS;

/**
 *  complete authentication by verifying if session key match with host  ------ step 6
 *
 *  @param _bytesHAMK H(A, M, K) in bytes
 *
 *  @return 1- verified 0- not
 */
- (int)verifySessionWithBytesHAMK:(const unsigned char*)_bytesHAMK;

//A = g^a	Public ephemeral value from client
- (const unsigned char *)getABytes;

// I	Username
- (const char *)getIdentity;

// M = H(H(N) xor H(g), H(I), s, A, B, K)	Session key verifier from client
- (const unsigned char *)getMBytes;
- (int) getALength;



@end
