//
//  SRPHost.h
//  SRPtest
//
//  Created by Liu Binghui on 09/07/15.
//  Copyright (c) 2015 HUT. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import "srp.h"

// http://pythonhosted.org/srp/srp.html

@interface SRPHost : NSObject


+ (instancetype)host;

/**
 *  generate salt and verification, stored in bytes_s and ver. ------ step 2
 *
 *  @param _username Username, the I in the python version
 *  @param _password password
 */
- (void) generateSaltAndVerificationWithIdentity:(const char*)_username andPassword:(const char*)_password;

/**
 *  generate session key with A from client.   ------ step 3
 *
 *  @param _bytesA Public ephemeral value A in bytes from client
 *  @param _lenA   length of A in integer
 */
- (void) generateSessionKeyWithBytesA:(const unsigned char*)_bytesA lengthA:(int)_lenA;

/**
 *  complete authentication by verifying if session key match with client  ------ step 5
 *
 *  @param _bytesM Session key verifier from client in bytes
 *
 *  @return 1- verified 0- not
 */
- (int) verifySessionWithBytesM:(const unsigned char*)_bytesM;


// B = kv + g^b	Public ephemeral value from host
- (const unsigned char *)getBytes;

// s: Small salt for the verification key from host
- (const unsigned char *)getSaltBytes;

// HAMK: server -> client: H(A, M, K)
- (const unsigned char *)getHAMKBytes;

- (int) getBLength;
- (int) getSaltLength;

@end
