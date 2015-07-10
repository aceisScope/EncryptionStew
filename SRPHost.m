//
//  SRPHost.m
//  SRPtest
//
//  Created by Liu Binghui on 09/07/15.
//  Copyright (c) 2015 HUT. All rights reserved.
//

#import "SRPHost.h"

@interface SRPHost ()
{
    struct SRPVerifier * ver;
    
    const char * username;
    const char * password;
    
    const unsigned char * bytes_s ;
    const unsigned char * bytes_v ;
    
    const unsigned char * bytes_A ;
    const unsigned char * bytes_B ;
    const unsigned char * bytes_M ;
    const unsigned char * bytes_HAMK ;
    
    int len_s;
    int len_v;
    int len_A;
    int len_B;
    int len_M;
    
    SRP_HashAlgorithm alg ;
    SRP_NGType        ng_type ;
    
    const unsigned char * sessionKey;
    int len_Key;
}

@end


@implementation SRPHost

+ (instancetype)host {
    static SRPHost *shared = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        shared = [[self alloc] init];
    });
    return shared;
}

- (id)init {
    if (self = [super init])
    {
        username = 0;
        password = 0;
        
        bytes_A = 0;
        bytes_B = 0;
        bytes_s = 0;
        bytes_M = 0;
        bytes_v = 0;
        bytes_HAMK = 0;
        
        len_A = 0;
        len_B = 0;
        len_M = 0;
        len_s = 0;
        len_v = 0;
        
        alg     = SRP_SHA1;
        ng_type = SRP_NG_2048;
        
        sessionKey = 0;
        len_Key = 0;
    }
    return self;
}


/**
 *  server -> client: s, B = kv + g^b
 *  s(salt) and password verifier v is generated in this step
 */

- (void)generateSaltAndVerificationWithIdentity:(const char*)_username andPassword:(const char*)_password
{
    username = _username;
    password = _password;
    
    // n and g are fixed value defined in rfc5054
    srp_create_salted_verification_key( alg, ng_type, username,
                                       (const unsigned char *)password,
                                       strlen(password),
                                       &bytes_s, &len_s,
                                       &bytes_v, &len_v,
                                       NULL, NULL );
    
}


/**
 *  server -> client: s, B = kv + g^b
 *  B is generated in this step
 *
 *  create a verifier in host
 *  
 *  At this point, both the client and server calculate the shared session key:
 *  client & server: u = H(A,B)
 *  server: K = H( (Av^u) ^ b )
 */
- (void) generateSessionKeyWithBytesA:(const unsigned char*)_bytesA lengthA:(int)_lenA
{
    bytes_A = _bytesA;
    len_A = _lenA;
    
    ver =  srp_verifier_new( alg, ng_type, username, bytes_s, len_s, bytes_v, len_v,
                            bytes_A, len_A, & bytes_B, &len_B, NULL, NULL );
    
    if ( !bytes_B ) {
        printf("Verifier SRP-6a safety check violated!\n");
    }
    
    sessionKey = srp_verifier_get_session_key(ver, &(len_Key));
    
    // debug only, shouldn't log out in release
    NSLog(@"host key %@",[NSData dataWithBytes:sessionKey length:len_Key]);
}

/**
 * client -> server: M = H(H(N) xor H(g), H(I), s, A, B, K)
 * need to prove that session key match
 * host generates HAMK =  H(A, M, K) and send it to client
 */
- (int) verifySessionWithBytesM:(const unsigned char*)_bytesM
{
    bytes_M = _bytesM;
    
    srp_verifier_verify_session( ver, bytes_M, &bytes_HAMK );
    
    if ( !bytes_HAMK )
    {
        printf("User authentication failed!\n");
        return NO;
    }
    
    int result = srp_verifier_is_authenticated(ver);
    
    [self cleanup];
    
    return result;
}

- (const unsigned char *)getBytes
{
    return bytes_B;
}

- (int) getBLength
{
    return len_B;
}

- (const unsigned char *)getSaltBytes
{
    return bytes_s;
}

- (int) getSaltLength
{
    return len_s;
}

- (const unsigned char *)getHAMKBytes
{
    return bytes_HAMK;
}

- (void)cleanup
{
    free( (char *)bytes_s );
    free( (char *)bytes_v );
}

@end
