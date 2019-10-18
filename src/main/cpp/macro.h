#ifndef __HEADER_MACRO_H__
#define __HEADER_MACRO_H__



#ifdef __cplusplus //|| defined(c_plusplus)
extern "C"{
#endif

#define WRONG						0
#define RIGHT						1

//macro for common bn
#define WordLen						32
#define ByteLen						8
#define WordByteLen					(WordLen/ByteLen)
#define LSBOfWord					0x00000001
#define MSBOfWord					0x80000000
#define Plus						0x00000000
#define Minus						0x00000001

#define BNBitLen					256
#define BNByteLen					(BNBitLen/ByteLen)
#define BNWordLen					(BNBitLen/WordLen)

//macro for BN in Pailler Encryption algoirhtm
#define PaiBNBitLen					1024
#define PaiBNByteLen				128
#define PaiBNWordLen				32
#define PaiLogLen					10
#define PaiPrimeWordLen				16
#define MAXPrimeWordLen				32
#define Ext_PaiBNWordLen			(PaiBNWordLen + 2)
#define BNMAXWordLen				(2 * PaiBNWordLen + 2)


#ifdef __cplusplus //|| defined(c_plusplus)
}
#endif

#endif
