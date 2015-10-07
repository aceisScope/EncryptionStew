//
//  AESGCM.h
//  OmniShare
//
//  Created by Liu Binghui on 24/08/15.
//  Copyright (c) 2015 HUT. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface AESGCM : NSObject

+ (void)test;

+ (BOOL)AES_GCM_encryptWithPlaintext:(NSData*)plaintext aad:(NSData*)aad key:(NSData*)key iv:(NSData*)iv returnCiphertext:(NSData**)ciphertext andTag:(NSData**)tag;
+ (BOOL)AES_GCM_decryptWithCiphertext:(NSData*)ciphertext aad:(NSData*)aad key:(NSData*)key iv:(NSData*)iv tag:(NSData*)tag returnPlaintext:(NSData**)plaintext;


@end
