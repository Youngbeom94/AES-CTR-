//* 암호 최적화 및 암호응용 연구실 20175204 김영범
#ifndef __PLUS__
#define __PLUS__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <memory.h>

#define _CRT_SECURE_NO_WARNINGS
#define xtime(x) ((x << 1) ^ (((x >> 7) & 1) * 0x1b))
#define Nb 4 //Number of colmns
#define Nk 4 //Number of 32-bit words comprising the Cipher Key //happy
#define BLOCKSIZE  256//!CTR Block size

#if Nk == 4
#define AES_MAXNR 10 //10 round
#define AES_KEY_BIT 128 // 128 bit
#elif Nk == 6
#define AES_MAXNR 12 // 12 round
#define AES_KEY_BIT 192 // 192 bit
#else Nk == 8
#define AES_MAXNR 14 // 14 round
#define AES_KEY_BIT 256 // 256bit
#endif

typedef struct aes_key_st
{
    unsigned int rd_key[4 * (AES_MAXNR + 1)];
    int rounds;
} AES_KEY;

void reset_count(unsigned char *count);//count를 0로 리셋해주는 함수 Nonce 값은 제외
int AES_set_encrypt_key(unsigned char *userKey,int bits, AES_KEY *key);//AES key 생성 (라운드키를 모두 생성한다)
void AES_encrypt(unsigned char *in, unsigned char *out, AES_KEY *key);//AES encryption
void Count_Addition(unsigned char *count);//AES -CTR 모드에서 Count를 1씩 증가해 주는 함수
void CRYPTO_ctr128_encrypt(unsigned char *in, unsigned char *out, size_t len, void *masterkey, unsigned char *count);//AES CTR 운영모드 패딩 계산이 들어가있다
void SubByte(unsigned char *state);//Subbyte
void ShiftRow(unsigned char *state);//shiftRow
void MixColumns(unsigned char *state);//Mixcolumn
void AddRoundKey(unsigned char *state,AES_KEY *key, int *round);//Addround key

//!FACE - Optimize  --- AES - CTR 운영모드를 최적화 하는 모드이다. Round1,2 에 대한 연산을 테이블로 사전계산하여 만든 함수이다.
void Make_LUTRd1(unsigned char LUT_Rd1[][256],unsigned char LUT_Rd1_plus[12],unsigned char *userkey,unsigned char *count);// LUK Table of Round 1
void Make_LUTRd2(unsigned char LUT_Rd1[][256],unsigned char LUT_Rd1_plus[12],unsigned char LUT_Rd2_plus[4][4][256],unsigned char *userkey,unsigned char *count);//! LUK Table of Round 2
void Make_Mixtable(unsigned char *state,unsigned char Mixtable[16],AES_KEY *key);// Mixcolumn 연산중에 중복되는 값들을 테이블로 만든것이다
void AES_encrypt_FACE(unsigned char *in,unsigned char LUT_Rd2[4][4][256], unsigned char *out, AES_KEY *key);//AES encryption of FACE mode
void CRYPTO_ctr128_encrypt_FACE(unsigned char *in, unsigned char *out, unsigned char LUT_Rd2[4][4][256],size_t len, void *masterkey, unsigned char *count);//AES CTR Mode of FACE Ver

//!FACE - Light - Optimize  --- AES - CTR 운영모드를 최적화 하는 모드이다. Round1,2 에 대한 연산을 테이블로 사전계산하여 만든 함수이다.
void AddRoundKey_For_FL(unsigned char *state,AES_KEY *key, int *round);//Addround key
void Count_Addition_FACE_Light(unsigned char *count,int cnt_k);//AES -CTR_FACE-LIGHT 모드에서 Count를 1씩 증가해 주는 함수
void Count_Add_FACE_Light(unsigned char *count);//AES -CTR_FACE-LIGHT 모드에서 Count를 1씩 증가해 주는 함수
void state_copy(unsigned char *dst , unsigned char *src);

#if BLOCKSIZE <= 256
void Make_LUT_Face_Light(unsigned char LUT_FL[4][4][256],unsigned char *userkey,unsigned char *count);//! LUK Table of FACE_Light
#else
void Make_LUT_Face_Light(unsigned char LUT_FL[4][4][256],unsigned char *userkey,unsigned char *count);//! LUK Table of FACE_Light
#endif

void AES_encrypt_FACE_Light(unsigned char *in,unsigned char LUT_FL[4][4][256], unsigned char *out, AES_KEY *key);//AES encryption of FACE mode
void CRYPTO_ctr128_encrypt_FACE_Light(unsigned char *in, unsigned char *out, unsigned char LUT_FL[4][4][256],size_t len, void *masterkey, unsigned char *count);//AES CTR Mode of FACE Ver


//!FACE - Extended - Optimize
void state_copy_12(unsigned char *dst , unsigned char *src);
void Make_LUT_Face_Ex(unsigned char LUT_FL[4][4][256],unsigned char LUT_Rd1_plus[12],unsigned char *userkey,unsigned char *count);//! LUK Table of FACE_Light
void AES_encrypt_FACE_EX(unsigned char *in,unsigned char LUT_Rd1[][256],unsigned char LUT_FL[4][4][256], unsigned char *out, AES_KEY *key);//AES encryption of FACE mode
void CRYPTO_ctr128_encrypt_FACE_Ex(unsigned char *in, unsigned char *out, unsigned char LUT_Rd1[][256],unsigned char LUT_FL[4][4][256],size_t len, void *masterkey, unsigned char *count);//AES CTR Mode of FACE Ver





//!clock test
unsigned long long cpucycles();// cpucycle measuring instrument


#endif