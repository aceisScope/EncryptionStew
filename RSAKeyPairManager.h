//
//  KeyPairManager.h
//  KeyPair
//
//  Created by Liu Binghui on 15/06/15.
//  Copyright (c) 2015 HUT. All rights reserved.
//

#import <Foundation/Foundation.h>
/**
 *  ACHTUNG!!! VERLASSEN!!!
 */


@interface RSAKeyPairManager : NSObject

- (NSData *)getPublicKeyExp;
- (NSData *)getPublicKeyMod;

+ (instancetype)keypair;

/**
 *  Encrypt data with own public key
 *
 *  @param dataToEncrypt
 *
 *  @return return cipher data
 */
- (NSData *)encryptWithPublicKey:(NSData *)dataToEncrypt;

/**
 *  Decrypt data with own private key
 *
 *  @param dataToDecrypt
 *
 *  @return return plain text data
 */
- (NSData *)decryptWithPrivateKey: (NSData *)dataToDecrypt;

/**
 *  Get own public key, in order to exchange
 *
 *  @return own public key in NSData
 */
- (NSData *)getSelfPublicKeyBits;


/**
 *  public key
 *
 *  @return public key in base64 string
 */
- (NSString *)getSelfPublicKeyBase64;

/**
 *  Get own private key, in order to be hashed to root key
 *
 *  @return own private key in NSData
 */
- (NSData *)getSelfPrivateKeyBits;

/**
 *  Get own private key, in order to be hashed to root key
 *
 *  @return own private key in Base64
 */
- (NSString *)getSelfPrivateKeyBase64;

/**
 *  Add peer's public key to key chain
 *
 *  @param key peer's public key in NSData
 *  @param tag peer's name
 *
 *  @return Success or not
 */
- (BOOL)addPublicKey:(NSData *)key withTag:(NSString *)tag;

/**
 *  Encrypt data with peer's public key
 *
 *  @param dataToEncrypt
 *  @param tag           peer's name
 *
 *  @return cipher data
 */
- (NSData *)encrypt:(NSData *)dataToEncrypt WithPublicKeyOfPeer:(NSString *)tag;

@end
