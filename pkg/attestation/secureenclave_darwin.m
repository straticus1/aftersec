//go:build darwin

#import <Foundation/Foundation.h>
#import <Security/Security.h>
#include <stdlib.h>
#include <string.h>

int se_public_point(uint8_t **out, int *out_len) {
	if (!out || !out_len) return 2;
	*out = NULL;
	*out_len = 0;
	NSDictionary *attrs = @{
		(__bridge id)kSecAttrKeyType: (__bridge id)kSecAttrKeyTypeECSECPrimeRandom,
		(__bridge id)kSecAttrKeySizeInBits: @256,
		(__bridge id)kSecAttrTokenID: (__bridge id)kSecAttrTokenIDSecureEnclave,
		(__bridge id)kSecPrivateKeyAttrs: @{
			(__bridge id)kSecAttrIsPermanent: @NO,
		},
	};
	CFErrorRef error = NULL;
	SecKeyRef privateKey = SecKeyCreateRandomKey((__bridge CFDictionaryRef)attrs, &error);
	if (!privateKey) {
		if (error) CFRelease(error);
		return 1;
	}
	CFErrorRef exportError = NULL;
	CFDataRef leaked = SecKeyCopyExternalRepresentation(privateKey, &exportError);
	if (leaked) {
		CFRelease(leaked);
		if (exportError) CFRelease(exportError);
		CFRelease(privateKey);
		return 2;
	}
	if (exportError) CFRelease(exportError);
	SecKeyRef publicKey = SecKeyCopyPublicKey(privateKey);
	CFRelease(privateKey);
	if (!publicKey) return 3;
	CFErrorRef publicError = NULL;
	CFDataRef point = SecKeyCopyExternalRepresentation(publicKey, &publicError);
	CFRelease(publicKey);
	if (!point) {
		if (publicError) CFRelease(publicError);
		return 4;
	}
	CFIndex n = CFDataGetLength(point);
	if (n != 65) {
		CFRelease(point);
		return 5;
	}
	*out = malloc((size_t)n);
	if (!*out) {
		CFRelease(point);
		return 6;
	}
	memcpy(*out, CFDataGetBytePtr(point), (size_t)n);
	*out_len = (int)n;
	CFRelease(point);
	return 0;
}
