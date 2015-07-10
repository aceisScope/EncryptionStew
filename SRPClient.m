//
//  SRPClient.m
//  SRPtest
//
//  Created by Liu Binghui on 09/07/15.
//  Copyright (c) 2015 HUT. All rights reserved.
//

#import "SRPClient.h"
 #include <string.h>

@interface SRPClient ()
{
    struct SRPUser * usr;
    const char * username;
    const char * password;
    
    const char * auth_username;
    const unsigned char * bytes_A;
    const unsigned char * bytes_B;
    const unsigned char * bytes_s;
    const unsigned char * bytes_M;
    const unsigned char * bytes_HAMK ;
    
    int len_A;
    int len_B;
    int len_s;
    int len_M;
    
    SRP_HashAlgorithm alg ;
    SRP_NGType        ng_type ;
    
    const unsigned char * sessionKey;
    int len_Key;
}



@end



@implementation SRPClient


+ (instancetype)client {
    static SRPClient *shared = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        shared = [[self alloc] init];
    });
    return shared;
}

- (id)init {
    if (self = [super init])
    {
        auth_username = 0;
        username = 0;
        password = 0;
        
        bytes_A = 0;
        bytes_B = 0;
        bytes_s = 0;
        bytes_M = 0;
        
        len_A = 0;
        len_B = 0;
        len_M = 0;
        len_s = 0;
        
        alg     = SRP_SHA1;
        ng_type = SRP_NG_2048;
        
        sessionKey = 0;
        len_Key = 0;
        
        
    }
    return self;
}

/**
 *  create a SRP user
 *  client -> server: I, A = g^a
 *  A = g^a is generated in the step
 */
- (void)generateClientByteAWithPassword:(const char*)_username andPassword:(const char*)_password
{
    password = _password;
    username = _username;
    
    
    // n and g are fixed value defined in rfc5054
    usr =  srp_user_new( alg, ng_type, username,
                        (const unsigned char *)password,
                        strlen(password), NULL, NULL );
    srp_user_start_authentication( usr, &auth_username, &bytes_A, &len_A );
}


/**
 *  at this point, both the client and server calculate the shared session key:
 *  client: x = H( s, H( I + ':' + p ) )        p is plaintext password
 *          K = H( (B - kg^x) ^ (a + ux) )      u = H(A,B)	Random scrambling parameter
 *  
 *  session key for client is generated
 *  client -> server: M = H(H(N) xor H(g), H(I), s, A, B, K) M is generated
 */
- (void)generateSessionKeyWithBytesB:(const unsigned char*)_byteB lengthB:(int)_lenB salt:(const unsigned char*)_byteS lengthSalt:(int)_lenS
{
    bytes_B = _byteB;
    len_B = _lenB;
    
    bytes_s = _byteS;
    len_s = _lenS;
    
    srp_user_process_challenge( usr, bytes_s, len_s, bytes_B, len_B, &bytes_M, &len_M );
    
    if ( !bytes_M ) {
        printf("User SRP-6a safety check violation!\n");
    }
    
    sessionKey = srp_user_get_session_key(usr, &len_Key);
    
    // debug only, shouldn't log out in release
    NSLog(@"client key %@",[NSData dataWithBytes:sessionKey length:len_Key]);
}

/**
 *  receive HMAK from host
 *  server -> client: H(A, M, K)
 *  need to prove session key match
 */
- (int)verifySessionWithBytesHAMK:(const unsigned char*)_bytesHAMK
{
    bytes_HAMK = _bytesHAMK;
    
    srp_user_verify_session( usr, bytes_HAMK );
    
    int result = srp_user_is_authenticated(usr);
    
    return result;
}

- (const unsigned char *)getABytes
{
    return bytes_A;
}

- (int) getALength
{
    return len_A;
}

- (const char *)getIdentity
{
    return auth_username;
}

- (const unsigned char *)getMBytes
{
    return bytes_M;
}



@end
