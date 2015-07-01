//
//  ECKeyPairManager.h
//  KeyPair
//
//  Created by Liu Binghui on 17/06/15.
//  Copyright (c) 2015 HUT. All rights reserved.
//

#import <Foundation/Foundation.h>

/**
 *  ACHTUNG!!! AKTIV!!!
 */

@interface ECKeyPairManager : NSObject

/**
 *  Init with generating ECDH key pair
 *
 *  @return singleton
 */
+ (instancetype)keypair;

/**
 *  public key
 *
 *  @return public key in base64 string
 */
- (NSString *)getSelfPublicKeyBase64;

/**
 *  private key
 *
 *  @return private key in base64 string
 */
- (NSString *)getSelfPrivateKeyBase64;

/**
 *  add peer's public key to keychain
 *
 *  @param key peer's public key in base64
 *  @param tag peer's name
 *
 *  @return success or not
 */
- (BOOL)addPublicKey:(NSString *)key fromPeer:(NSString *)peerName;

/**
 *  get peer's public key from keychain
 *
 *  @param peerName peer's name, used as identifier
 *
 *  @return peer's public key in base64 string
 */
- (NSString *)getPublicKeyBase64ForPeerRef:(NSString *)peerName;

/**
 *  get shared secret with peer
 *
 *  @param peerName peer's name
 *
 *  @return shared secret in nsdata
 */
- (NSData*)getSharedSecretWithPeer:(NSString*)peerName;

/**
 *  get shared secret with peer's key
 *
 *  @param key peer's public key in base64 string
 *
 *  @return shard secret in base64 string
 */
- (NSString*)getSharedSecretWithPeerPublicKey:(NSString*)key;

@end
