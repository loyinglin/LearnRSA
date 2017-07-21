//
//  ViewController.m
//  LearnRSA
//
//  Created by loyinglin on 2017/7/14.
//  Copyright © 2017年 loying lin. All rights reserved.
//

#import "ViewController.h"

#import <Security/Security.h>
#import <CommonCrypto/CommonCrypto.h>
#import <sys/xattr.h>

@interface ViewController ()

@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    // Do any additional setup after loading the view, typically from a nib.
    
    [self signAndVerify];
    [self justVerify];
}


- (void)justVerify {
    
    NSData *sourceData = [NSData dataWithContentsOfFile:[[NSBundle mainBundle] pathForResource:@"ios" ofType:@"jsbundle"]];
    NSString *md5Str = [self MD5WithNSData:sourceData];
    NSData *md5Data = [md5Str dataUsingEncoding:NSUTF8StringEncoding];
        
    NSData *signatureData = [NSData dataWithContentsOfFile:[[NSBundle mainBundle] pathForResource:@"signature" ofType:@""]];
    
    NSAssert(PKCSVerifyBytesSHA256withRSA(md5Data, signatureData, [self loadPublicKey]), @"签名验证失败");
}

- (void)signAndVerify {
    
    SecKeyRef privateKeyRef = [self getPrivateKeyRefWithContentsOfFile:[NSData dataWithContentsOfFile:[[NSBundle mainBundle] pathForResource:@"private_key" ofType:@"p12"]] password:@""];
    
    
    NSData *sourceData = [NSData dataWithContentsOfFile:[[NSBundle mainBundle] pathForResource:@"ios" ofType:@"jsbundle"]];
    
    NSString *md5Str = [self MD5WithNSData:sourceData];
    NSData *md5Data = [md5Str dataUsingEncoding:NSUTF8StringEncoding];
    
    NSData *signatureData = PKCSSignBytesSHA256withRSA(md5Data, privateKeyRef);
    NSString *dataPath = [NSTemporaryDirectory() stringByAppendingPathComponent:@"signature"];
    [signatureData writeToFile:dataPath atomically:NO];
    
    NSAssert(PKCSVerifyBytesSHA256withRSA(md5Data, signatureData, [self loadPublicKey]), @"签名验证失败");
}

- (void)didReceiveMemoryWarning {
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
    
    
}


#pragma mark - security

- (BOOL)verifyWithData:(NSData *)data signature:(NSData *)signData {
    SecKeyRef publicKeyRef = [self loadPublicKey];
    return PKCSVerifyBytesSHA256withRSA(data, signData, publicKeyRef);
}

BOOL PKCSVerifyBytesSHA256withRSA(NSData* plainData, NSData* signature, SecKeyRef publicKey)
{
    if (!plainData || !signature) { // 保护
        return NO;
    }
    size_t signedHashBytesSize = SecKeyGetBlockSize(publicKey);
    const void* signedHashBytes = [signature bytes];
    
    size_t hashBytesSize = CC_SHA256_DIGEST_LENGTH;
    uint8_t* hashBytes = malloc(hashBytesSize);
    if (!CC_SHA256([plainData bytes], (CC_LONG)[plainData length], hashBytes)) {
        return NO;
    }
    
    OSStatus status = SecKeyRawVerify(publicKey,
                                      kSecPaddingPKCS1SHA256,
                                      hashBytes,
                                      hashBytesSize,
                                      signedHashBytes,
                                      signedHashBytesSize);
    
    return status == errSecSuccess;
}

NSData* PKCSSignBytesSHA256withRSA(NSData* plainData, SecKeyRef privateKey)
{
    size_t signedHashBytesSize = SecKeyGetBlockSize(privateKey);
    uint8_t* signedHashBytes = malloc(signedHashBytesSize);
    memset(signedHashBytes, 0x0, signedHashBytesSize);
    
    size_t hashBytesSize = CC_SHA256_DIGEST_LENGTH;
    uint8_t* hashBytes = malloc(hashBytesSize);
    if (!CC_SHA256([plainData bytes], (CC_LONG)[plainData length], hashBytes)) {
        return nil;
    }
    
    SecKeyRawSign(privateKey,
                  kSecPaddingPKCS1SHA256,
                  hashBytes,
                  hashBytesSize,
                  signedHashBytes,
                  &signedHashBytesSize);
    
    NSData* signedHash = [NSData dataWithBytes:signedHashBytes
                                        length:(NSUInteger)signedHashBytesSize];
    
    if (hashBytes)
        free(hashBytes);
    if (signedHashBytes)
        free(signedHashBytes);
    
    return signedHash;
}

- (SecKeyRef)loadPublicKey {
    SecKeyRef publicKeyRef;
    NSString *path = [[NSBundle mainBundle] pathForResource:@"public_key" ofType:@"der"];
    NSData *cerData = [NSData dataWithContentsOfFile:path];
    
    publicKeyRef = [self getPublicKeyRefrenceFromeData:cerData];
    
    
    return publicKeyRef;
}

//获取私钥
- (SecKeyRef)getPrivateKeyRefWithContentsOfFile:(NSData *)p12Data password:(NSString*)password {
    if (!p12Data) {
        return nil;
    }
    SecKeyRef privateKeyRef = NULL;
    NSMutableDictionary * options = [[NSMutableDictionary alloc] init];
    [options setObject: password forKey:(__bridge id)kSecImportExportPassphrase];
    CFArrayRef items = CFArrayCreate(NULL, 0, 0, NULL);
    OSStatus securityError = SecPKCS12Import((__bridge CFDataRef) p12Data, (__bridge CFDictionaryRef)options, &items);
    if (securityError == noErr && CFArrayGetCount(items) > 0) {
        CFDictionaryRef identityDict = CFArrayGetValueAtIndex(items, 0);
        SecIdentityRef identityApp = (SecIdentityRef)CFDictionaryGetValue(identityDict, kSecImportItemIdentity);
        securityError = SecIdentityCopyPrivateKey(identityApp, &privateKeyRef);
        if (securityError != noErr) {
            privateKeyRef = NULL;
        }
    }
    CFRelease(items);
    
    return privateKeyRef;
}

- (SecKeyRef)getPublicKeyRefrenceFromeData:(NSData *)certData {
    SecKeyRef publicKeyRef = NULL;
    CFDataRef myCertData = (__bridge CFDataRef)certData;
    SecCertificateRef cert = SecCertificateCreateWithData(NULL, (CFDataRef)myCertData);
    if (cert == nil) {
        NSLog(@"Can not read certificate ");
        return nil;
    }
    SecPolicyRef policy = SecPolicyCreateBasicX509();
    SecCertificateRef certArray[1] = {cert};
    CFArrayRef myCerts = CFArrayCreate(NULL, (void *)(void *)certArray, 1, NULL);
    SecTrustRef trust;
    OSStatus status = SecTrustCreateWithCertificates(myCerts, policy, &trust);
    if (status != noErr) {
        NSLog(@"SecTrustCreateWithCertificates fail. Error Code: %d", (int)status);
        CFRelease(cert);
        CFRelease(policy);
        CFRelease(myCerts);
        return nil;
    }
    SecTrustResultType trustResult;
    status = SecTrustEvaluate(trust, &trustResult);
    if (status != noErr) {
        NSLog(@"SecTrustEvaluate fail. Error Code: %d", (int)status);
        CFRelease(cert);
        CFRelease(policy);
        CFRelease(trust);
        CFRelease(myCerts);
        return nil;
    }
    publicKeyRef = SecTrustCopyPublicKey(trust);
    
    CFRelease(cert);
    CFRelease(policy);
    CFRelease(trust);
    CFRelease(myCerts);
    
    return publicKeyRef;
}

-(NSString *)MD5WithStr:(NSString *)str {
    const char *cStr = [str UTF8String];
    unsigned char result[16];
    CC_MD5( cStr, (CC_LONG)strlen(cStr), result);
    
    return [NSString stringWithFormat:
            @"%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X",
            result[0], result[1], result[2], result[3],
            result[4], result[5], result[6], result[7],
            result[8], result[9], result[10], result[11],
            result[12], result[13], result[14], result[15]
            ];
}

-(NSString *)MD5WithNSData:(NSData *)data
{
    unsigned char result[16];
    CC_MD5([data bytes], (CC_LONG)[data length], result);
    return [NSString stringWithFormat:
            @"%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
            result[0], result[1], result[2], result[3],
            result[4], result[5], result[6], result[7],
            result[8], result[9], result[10], result[11],
            result[12], result[13], result[14], result[15]
            ];
}


-(BOOL)setExtendValueWithPath:(NSString *)path key:(NSString *)key value:(NSData *)value {
    ssize_t writelen = setxattr([path fileSystemRepresentation],
                                [key UTF8String],
                                [value bytes],
                                [value length],
                                0,
                                0);
    return writelen == 0;
}




// 长度不超过1024
-(NSData *)getExtendValueWithPath:(NSString *)path key:(NSString *)key {
    ssize_t readlen = 1024;
    do {
        char buffer[readlen];
        bzero(buffer, sizeof(buffer));
        size_t leng = sizeof(buffer);
        readlen = getxattr([path fileSystemRepresentation],
                           [key UTF8String],
                           buffer,
                           leng,
                           0,
                           0);
        if (readlen < 0){
            return nil;
        }
        else if (readlen > sizeof(buffer)) {
            continue;
        }else{
            NSData *result = [NSData dataWithBytes:buffer length:readlen];
            return result;
        }
    } while (YES);
    return nil;
}

@end
