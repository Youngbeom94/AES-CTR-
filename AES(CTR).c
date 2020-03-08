#include "AES(CTR).h"

static const unsigned char Rcon[13] = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab};
static const unsigned char sbox[256] = {
    //0     1    2      3     4    5     6     7      8    9     A      B    C     D     E     F
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16};
unsigned long long cpucycles()
{
    return __rdtsc();
}
void reset_count(unsigned char *count)
{
    int cnt_i = 0;

    for (cnt_i = 0; cnt_i < 16; cnt_i++)
    {
        count[cnt_i] = 0x00;
    }
}

void SubByte(unsigned char *state)
{
    int cnt_i;
    for (cnt_i = 0; cnt_i < 16; cnt_i++)
    {
        *(state + cnt_i) = sbox[state[cnt_i]]; //sbox를 이용해 치환하기
    }
}
void ShiftRow(unsigned char *state)
{
    int temp, temp2;
    temp = state[13]; //2번째 행 1칸 Leftshift
    state[13] = state[1];
    state[1] = state[5];
    state[5] = state[9];
    state[9] = temp;

    temp = state[10]; //3번째 행 2칸 Leftshift
    temp2 = state[14];
    state[10] = state[2];
    state[14] = state[6];
    state[2] = temp;
    state[6] = temp2;

    temp = state[7]; // 4번째 행 3칸 Leftshift
    state[7] = state[3];
    state[3] = state[15];
    state[15] = state[11];
    state[11] = temp;
}
void MixColumns(unsigned char *state)
{
    unsigned char temp[2];
    unsigned char src[4];
    for (int cnt_i = 0; cnt_i < 4; cnt_i++)
    {
        //? 02 03 01 01
        temp[0] = state[4 * cnt_i] ^ state[4 * cnt_i + 1]; // 02 03 에해당하는 xtime
        temp[0] = xtime(temp[0]);
        temp[1] = state[4 * cnt_i + 1] ^ state[4 * cnt_i + 2] ^ state[4 * cnt_i + 3]; // 1 에 해당하는 plaintxt
        src[0] = temp[0] ^ temp[1];                                                   // 최종 src
        //? 01 02 03 01
        temp[0] = state[4 * cnt_i + 1] ^ state[4 * cnt_i + 2]; // 02 03 에해당하는 xtime
        temp[0] = xtime(temp[0]);
        temp[1] = state[4 * cnt_i] ^ state[4 * cnt_i + 2] ^ state[4 * cnt_i + 3]; // 1 에 해당하는 plaintxt
        src[1] = temp[0] ^ temp[1];                                               // 최종 src
        //? 01 01 02 03
        temp[0] = state[4 * cnt_i + 2] ^ state[4 * cnt_i + 3]; // 02 03 에해당하는 xtime
        temp[0] = xtime(temp[0]);
        temp[1] = state[4 * cnt_i] ^ state[4 * cnt_i + 1] ^ state[4 * cnt_i + 3]; // 1 에 해당하는 plaintxt
        src[2] = temp[0] ^ temp[1];                                               // 최종 src
        //? 03 01 01 03
        temp[0] = state[4 * cnt_i] ^ state[4 * cnt_i + 3]; // 02 03 에해당하는 xtime
        temp[0] = xtime(temp[0]);
        temp[1] = state[4 * cnt_i] ^ state[4 * cnt_i + 1] ^ state[4 * cnt_i + 2];
        src[3] = temp[0] ^ temp[1]; // 최종 src

        for (int cnt_j = 0; cnt_j < 4; cnt_j++) // 각각의 src값을 state에 대입해주기
        {
            state[4 * cnt_i + cnt_j] = src[cnt_j];
        }
    }
}
void RotWord(int *Word) // int 기준으로 값을 받고 1byte left Rotation
{
    int temp;
    temp = *Word << 8;
    *Word = *Word >> 24;
    *Word &= 0x000000ff;
    *Word ^= temp;
}
void SubWord(int *Word) // int 기준으로 값을 받고 int를 4개의 byte로 쪼개서 byte를 sbox의 값으로 치환
{
    int cnt_i = 0;
    unsigned char temp[4] = {0x00};
    int temp2;
    for (cnt_i = 0; cnt_i < 4; cnt_i++) // 값 쪼개서 sbox로 치환해서 temp배열에 저장
    {
        temp2 = (*Word >> (24 - (8 * cnt_i)));
        temp2 &= 0x000000ff;
        temp[cnt_i] = sbox[temp2];
    }
    *Word = 0;
    for (cnt_i = 0; cnt_i < 4; cnt_i++)
    {
        *Word += (temp[cnt_i] << (24 - (8 * cnt_i))); // 다시 쪼개고 치환한 값들을 다시 합쳐주기
    }
}

void Byte_Int_Set(unsigned char *userKey, AES_KEY *key, int start) // byte 16개 배열을 int함수에 저장시키는 함수
{
    int temp = 0;
    for (int cnt_i = 0; cnt_i < 4; cnt_i++) // 저장할 공간을 먼저 초기화 시키기
    {
        key->rd_key[start + cnt_i] = 0;
    }

    for (int cnt_i = 0; cnt_i < 4; cnt_i++) // byte 16개를 int 4개 배열에 저장시키기
    {
        for (int cnt_j = 0; cnt_j < 4; cnt_j++)
        {
            temp = userKey[cnt_j + (cnt_i * 4)] << ((3 - cnt_j) * 8);
            key->rd_key[start + cnt_i] += temp;
            temp = 0;
        }
    }
}
int AES_set_encrypt_key(unsigned char *userkey, int bits, AES_KEY *key) //키생성 함수
{
    int cnt_i;
    int temp;
    Byte_Int_Set(userkey, key, 0); //처음 Masterkey(userkey)를 처음 4개의 배열에 저장시키기

    for (cnt_i = 4; cnt_i < Nb * (AES_MAXNR + 1); cnt_i++) // Round 10번에 관한 Key 생성
    {
        temp = key->rd_key[cnt_i - 1];
        if (cnt_i % Nk == 0)
        {
            RotWord(&temp);
            SubWord(&temp);
            temp ^= Rcon[(cnt_i / Nk) - 1] << 24;
        }
        else if ((Nk > 6) && (cnt_i % Nk == 4)) // 192bit 이상일때
        {
            SubWord(&temp);
        }
        key->rd_key[cnt_i] = key->rd_key[cnt_i - Nk] ^ temp;
    }
    if (bits == 128) // 반환값은 bits에 따라 라운드 값을 반환하기.
        return 10;
    if (bits == 192)
        return 12;
    if (bits == 256)
        return 14;
    printf("\nERROR\n");
    return -1;
}

void AddRoundKey(unsigned char *state, AES_KEY *key, int *round)
{
    int cnt_i, cnt_j = 0;
    int temp;
    for (cnt_i = 0; cnt_i < 4; cnt_i++)
    { // 키는 int 배열 4개이고 state는 byte배열 16개 이므로 XoR시 쪼개고 합치는 과정이 필요
        for (cnt_j = 0; cnt_j < 4; cnt_j++)
        {
            temp = (key->rd_key[(*round * 4) + cnt_i]);
            temp = temp >> (24 - (8 * cnt_j));
            temp &= 0x000000ff;
            state[cnt_j + (cnt_i * 4)] ^= temp;
        }
    }
    *round += 1;
}

void AES_encrypt(unsigned char *in, unsigned char *out, AES_KEY *key)
{
    unsigned char state[4 * Nb];
    int cnt_i;
    int round = 0;

    for (cnt_i = 0; cnt_i < 4 * Nb; cnt_i++)
    {
        state[cnt_i] = in[cnt_i];
    }

    AddRoundKey(state, key, &round); //Round 0때는 오직 AddRoundkey 함수 연산만 있다
    
    for (cnt_i = 1; cnt_i < AES_MAXNR; cnt_i++)
    {
        SubByte(state);
        ShiftRow(state);
        MixColumns(state);
        AddRoundKey(state, key, &round);
    }

    SubByte(state);
    ShiftRow(state);
    AddRoundKey(state, key, &round);

    for (cnt_i = 0; cnt_i < 4 * Nb; cnt_i++)
    {
        out[cnt_i] = state[cnt_i];
    }
}
void Count_Addition(unsigned char *count) //Count 배열에서 값을 1증가시키는 함수
{
    int cnt_i, carry = 0;           //맨처음 Carry 값은 0
    unsigned char out[16] = {0x00}; // 최종배열
    unsigned char one[16] = {0x00}; // 0x01을 의미하는 배열
    one[15] = 0x01;

    for (cnt_i = 15; cnt_i >= 0; cnt_i--)
    {
        out[cnt_i] = count[cnt_i] + one[cnt_i] + carry; // 마지막 배열 끼리 순차적으로 더해주면서 carry를 계산한다.
        //만약 out의 결과값의 count값보다 작은 경우 carry가 발생했다. 만약 0xffffffff..인 경우 1을 더해주면 자동적으로 0x00상태로 돌아간다
        if (out[cnt_i] < count[cnt_i])
            carry = 1;
        else
        {
            carry = 0;
        }
    }
    for (cnt_i = 0; cnt_i < 16; cnt_i++)
    {
        count[cnt_i] = out[cnt_i];
    }
}

void Count_Addition_FACE_Light(unsigned char *count)//AES -CTR _FACE_Light 모드에서 Count를 1씩 증가해 주는 함수
{
    int cnt_i, carry = 0;           //맨처음 Carry 값은 0
    unsigned char out[16] = {0x00}; // 최종배열
    unsigned char one[16] = {0x00}; // 0x01을 의미하는 배열
    one[15] = 0x01;

    for (cnt_i = 4; cnt_i >= 0; cnt_i--)
    {
        out[cnt_i] = count[cnt_i] + one[cnt_i] + carry; // 마지막 배열 끼리 순차적으로 더해주면서 carry를 계산한다.
        //만약 out의 결과값의 count값보다 작은 경우 carry가 발생했다. 만약 0xffffffff..인 경우 1을 더해주면 자동적으로 0x00상태로 돌아간다
        if (out[cnt_i] < count[cnt_i])
            carry = 1;
        else
        {
            carry = 0;
        }
    }
    for (cnt_i = 0; cnt_i < 16; cnt_i++)
    {
        count[cnt_i] = out[cnt_i];
    }

}

void CRYPTO_ctr128_encrypt(unsigned char *in, unsigned char *out, size_t len, void *masterkey, unsigned char *count)
{
    int cnt_i, cnt_j;
    int paddingcnt = len % 16;
    unsigned char PT[BLOCKSIZE][16] = {0x00};
    unsigned char CT[BLOCKSIZE][16] = {0x00};
    unsigned char iparray[16];
    unsigned char oparray[16];
    AES_KEY USER_KEY;
    AES_KEY *key = &USER_KEY;

    key->rounds = AES_set_encrypt_key(masterkey, AES_KEY_BIT, key); //!

    for (cnt_i = 0; cnt_i < BLOCKSIZE - 1; cnt_i++)
    {
        for (cnt_j = 0; cnt_j < 16; cnt_j++)
        {
            PT[cnt_i][cnt_j] = in[cnt_i * 16 + cnt_j];
        }
    }
    if (paddingcnt == 0)
    {
        for (cnt_j = 0; cnt_j < 16; cnt_j++)
        {
            PT[BLOCKSIZE - 1][cnt_j] = in[(BLOCKSIZE - 1) * 16 + cnt_j];
        }
    }

    if (paddingcnt != 0) // 패딩 함수. Padding cnt 만큼 뺴주는 방식을 취한다.
    {
        for (cnt_j = 0; cnt_j < paddingcnt; cnt_j++)
        {
            PT[BLOCKSIZE - 1][cnt_j] = in[(BLOCKSIZE - 1) * 16 + cnt_j];
        }
        for (cnt_j = paddingcnt; cnt_j < 16; cnt_j++)
        {
            PT[BLOCKSIZE - 1][cnt_j] = (0x10 - paddingcnt);
        }
    }

    for (cnt_i = 0; cnt_i < BLOCKSIZE; cnt_i++) //각각의 count마다 1더하기 해주고, 암호화 시킨다음에 PT와 XoR 해준다. CORE
    {
        if (cnt_i != 0)
            Count_Addition(count);

        for (cnt_j = 0; cnt_j < 16; cnt_j++)
        {
            iparray[cnt_j] = count[cnt_j];
        }
        AES_encrypt(iparray, oparray, key);
        for (cnt_j = 0; cnt_j < 16; cnt_j++)
        {
            CT[cnt_i][cnt_j] = oparray[cnt_j] ^ PT[cnt_i][cnt_j];
        }
    }

    for (cnt_i = 0; cnt_i < BLOCKSIZE; cnt_i++)
    {
        for (cnt_j = 0; cnt_j < 16; cnt_j++)
        {
            out[cnt_i * 16 + cnt_j] = CT[cnt_i][cnt_j];
        }
    }
}
void Make_LUTRd1(unsigned char LUT[][256], unsigned char LUT_plus[12], unsigned char *userkey, unsigned char *count)
{
    unsigned char Rd0Table[12] = {0x00};//Round0 에 관해 테이블을 형성해 주는 변수이다.
    unsigned char state[16] = {0x00};//상태값을 저장해주는 변수
    unsigned char round = 0x00;
    int rd_AES = 1;
    int cnt_i, cnt_j = 0;
    AES_KEY Key;
    AES_KEY *key = &Key;
    key->rounds = AES_set_encrypt_key(userkey, 128, key);
    reset_count(count);

    for (cnt_i = 0; cnt_i < 3; cnt_i++)//Ctr 값이 1증가하고 나머지는 같다.
    {
        for (cnt_j = 0; cnt_j < 4; cnt_j++)
        {
            Rd0Table[cnt_j + (cnt_i * 4)] = count[cnt_j + (cnt_i * 4)] ^ userkey[cnt_j + (cnt_i * 4)];
            state[cnt_j + (cnt_i * 4)] = Rd0Table[cnt_j + (cnt_i * 4)];
        }
    }
    for (cnt_i = 0; cnt_i < 256; cnt_i++) // 총테이블을 256개 만들어준다. iv[15]의 값이 꽉 채워질때 까지.
    {
        for (cnt_j = 0; cnt_j < 12; cnt_j++)
        {
            state[cnt_j] = Rd0Table[cnt_j];// 기존 state는 첫번째 블록과 동일하므로(0 - 12 까지) Round 0를 이용한다.
        }
        state[12] = userkey[12];//나머지변수는 직접 채워준다.
        state[13] = userkey[13];
        state[14] = userkey[14];
        state[15] = round ^ userkey[15];

        rd_AES = 1;// Table을 만들어주기위해 설정해준 Round 변수.
        SubByte(state);
        ShiftRow(state);
        MixColumns(state);
        AddRoundKey(state, key, &rd_AES);

        for (cnt_j = 0; cnt_j < 4; cnt_j++)
        {
            LUT[cnt_j][cnt_i] = state[cnt_j];
        }
        round++;
    }
    for (cnt_i = 0; cnt_i < 12; cnt_i++)
    {
        LUT_plus[cnt_i] = state[cnt_i + 4]; //Round1에서 첫번째 열을 제외하고는 위의 For loop연산을 해도 변하지 않는다 그값을 저장해준다.
    }
}

void Make_LUTRd2(unsigned char LUT_Rd1[][256], unsigned char LUT_Rd1_plus[12], unsigned char LUT_Rd2_plus[4][4][256], unsigned char *userkey, unsigned char *count)
{
    unsigned char MixTable[16] = {0x00};
    unsigned char temp_Rdkey[4] = {0x00};
    unsigned char state[16] = {0x00};
    unsigned char round = 0x00;
    unsigned char n_block = 0x00;
    unsigned char temp;
    unsigned char src[4];
    int rd_AES = 2;
    int cnt_i, cnt_j, cnt_k = 0;
    AES_KEY Key;
    AES_KEY *key = &Key;
    key->rounds = AES_set_encrypt_key(userkey, 128, key);

    for (cnt_i = 0; cnt_i < 4; cnt_i++)//Make_LUTRD2함수를 통해 만들어준 LUT_RD1테이블을 이용하여 state 값을 갱신시킨다.
    {
        state[cnt_i] = LUT_Rd1[cnt_i][n_block];
    }
    for (cnt_i = 0; cnt_i < 12; cnt_i++)
    {
        state[cnt_i + 4] = LUT_Rd1_plus[cnt_i];//위와 마찬가지이다.
    }

    SubByte(state);//2라운드의 Subyte이다.
    ShiftRow(state);//2라운드의 ShiftRow이다.
    Make_Mixtable(state, MixTable, key);//Mixcolumn 연산을 하기전에 중복되는 값들을 테이블로 저장하기 위한 Table을 만들어주는 함수이다.

    for (cnt_i = 0; cnt_i < 256; cnt_i++)
    {//위의 LUT_Rd1테이블은 Round1이 끝났을때 상태값이며, Subyte와  ShiftRow가 적용되지 않은 상태이다. ShiftRow까지 생각해서 만든 Mixtable이니 Subyte만 넣어주면된다. 
        temp = xtime(sbox[LUT_Rd1[0][cnt_i]]); //? 2 1 1 3 S[0]
        LUT_Rd2_plus[0][0][cnt_i] = temp ^ MixTable[0];//MixTable은 Addroundkey 까지 XoR 한 값이 들어가있으므로 xtime함수를 적절히 호출하여 XoR만 해주면된다.
        LUT_Rd2_plus[0][1][cnt_i] = sbox[LUT_Rd1[0][cnt_i]] ^ MixTable[1];
        LUT_Rd2_plus[0][2][cnt_i] = sbox[LUT_Rd1[0][cnt_i]] ^ MixTable[2];
        LUT_Rd2_plus[0][3][cnt_i] = sbox[LUT_Rd1[0][cnt_i]] ^ temp ^ MixTable[3];

        temp = xtime(sbox[LUT_Rd1[3][cnt_i]]); //? 1 1 3 2 S[3] ,shiftRow 때문에 S[3]이 왔다.
        LUT_Rd2_plus[1][0][cnt_i] = sbox[LUT_Rd1[3][cnt_i]] ^ MixTable[4];
        LUT_Rd2_plus[1][1][cnt_i] = sbox[LUT_Rd1[3][cnt_i]] ^ MixTable[5];
        LUT_Rd2_plus[1][2][cnt_i] = sbox[LUT_Rd1[3][cnt_i]] ^ temp ^ MixTable[6];
        LUT_Rd2_plus[1][3][cnt_i] = temp ^ MixTable[7];

        temp = xtime(sbox[LUT_Rd1[2][cnt_i]]); //? 1 3 2 1 S[2]
        LUT_Rd2_plus[2][0][cnt_i] = sbox[LUT_Rd1[2][cnt_i]] ^ MixTable[8];
        LUT_Rd2_plus[2][1][cnt_i] = sbox[LUT_Rd1[2][cnt_i]] ^ temp ^ MixTable[9];
        LUT_Rd2_plus[2][2][cnt_i] = temp ^ MixTable[10];
        LUT_Rd2_plus[2][3][cnt_i] = sbox[LUT_Rd1[2][cnt_i]] ^ MixTable[11];

        temp = xtime(sbox[LUT_Rd1[1][cnt_i]]); //? 3 2 1 1 S[1]
        LUT_Rd2_plus[3][0][cnt_i] = sbox[LUT_Rd1[1][cnt_i]] ^ temp ^ MixTable[12];
        LUT_Rd2_plus[3][1][cnt_i] = temp ^ MixTable[13];
        LUT_Rd2_plus[3][2][cnt_i] = sbox[LUT_Rd1[1][cnt_i]] ^ MixTable[14];
        LUT_Rd2_plus[3][3][cnt_i] = sbox[LUT_Rd1[1][cnt_i]] ^ MixTable[15];
    }

}

void Make_Mixtable(unsigned char *state, unsigned char Mixtable[16], AES_KEY *key)
{
    unsigned char temp[2];
    unsigned char src[4];
    unsigned char keytemp = 0x00;
    //MixTable의 원리는 기존 iv[15]값에서 count값이 1증가할때 마다,
    // Round1이 끝났을때 실제로 바뀌는 값은 첫번째 열뿐이라는 사실이다. 그래서 중복되는 Mixcolumn값과 Roundkey계산을 미리한다.
    //! S[0]에 관한 Mix table
    //? 03 01 01
    temp[0] = state[1];
    temp[0] = xtime(temp[0]);
    temp[1] = state[1] ^ state[2] ^ state[3]; // 1 에 해당하는 plaintxt
    keytemp = key->rd_key[8] >> 24;
    Mixtable[0] = temp[0] ^ temp[1] ^ keytemp; // 최종 src
    //? 02 03 01
    temp[0] = state[1] ^ state[2]; // 02 03 에해당하는 xtime
    temp[0] = xtime(temp[0]);
    temp[1] = state[2] ^ state[3]; // 1 에 해당하는 plaintxt
    keytemp = key->rd_key[8] >> 16;
    Mixtable[1] = temp[0] ^ temp[1] ^ keytemp; // 최종 src
    //? 01 02 03
    temp[0] = state[2] ^ state[3]; // 02 03 에해당하는 xtime
    temp[0] = xtime(temp[0]);
    temp[1] = state[1] ^ state[3]; // 1 에 해당하는 plaintxt
    keytemp = key->rd_key[8] >> 8;
    Mixtable[2] = temp[0] ^ temp[1] ^ keytemp; // 최종 src
    //? 01 01 02
    temp[0] = state[3]; // 02 03 에해당하는 xtime
    temp[0] = xtime(temp[0]);
    temp[1] = state[1] ^ state[2];
    keytemp = key->rd_key[8];
    Mixtable[3] = temp[0] ^ temp[1] ^ keytemp; // 최종 src

    //! S[3]에 관한 Mix table
    //? 02 03 01
    temp[0] = state[4] ^ state[5]; // 02 03 에해당하는 xtime
    temp[0] = xtime(temp[0]);
    temp[1] = state[5] ^ state[6]; // 1 에 해당하는 plaintxt
    keytemp = key->rd_key[9] >> 24;
    Mixtable[4] = temp[0] ^ temp[1] ^ keytemp; // 최종 src
    //? 01 02 03
    temp[0] = state[5] ^ state[6]; // 02 03 에해당하는 xtime
    temp[0] = xtime(temp[0]);
    temp[1] = state[4] ^ state[6]; // 1 에 해당하는 plaintxt
    keytemp = key->rd_key[9] >> 16;
    Mixtable[5] = temp[0] ^ temp[1] ^ keytemp; // 최종 src
    //? 01 01 02
    temp[0] = state[6]; // 02 03 에해당하는 xtime
    temp[0] = xtime(temp[0]);
    temp[1] = state[4] ^ state[5];
    keytemp = key->rd_key[9] >> 8;
    Mixtable[6] = temp[0] ^ temp[1] ^ keytemp; // 최종 src
    //? 03 01 01
    temp[0] = state[4];
    temp[0] = xtime(temp[0]);
    temp[1] = state[4] ^ state[5] ^ state[6]; // 1 에 해당하는 plaintxt
    keytemp = key->rd_key[9];
    Mixtable[7] = temp[0] ^ temp[1] ^ keytemp; // 최종 src

    //! S[2]에 관한 Mix table
    //? 02 03 01
    temp[0] = state[8] ^ state[9]; // 02 03 에해당하는 xtime
    temp[0] = xtime(temp[0]);
    temp[1] = state[9] ^ state[11]; // 1 에 해당하는 plaintxt
    keytemp = key->rd_key[10] >> 24;
    Mixtable[8] = temp[0] ^ temp[1] ^ keytemp; // 최종 src
    //? 01 02 01
    temp[0] = state[9]; // 02 03 에해당하는 xtime
    temp[0] = xtime(temp[0]);
    temp[1] = state[8] ^ state[11];
    keytemp = key->rd_key[10] >> 16;
    Mixtable[9] = temp[0] ^ temp[1] ^ keytemp; // 최종 src
    //? 01 01 03
    temp[0] = state[11];
    temp[0] = xtime(temp[0]);
    temp[1] = state[8] ^ state[9] ^ state[11]; // 1 에 해당하는 plaintxt
    keytemp = key->rd_key[10] >> 8;
    Mixtable[10] = temp[0] ^ temp[1] ^ keytemp; // 최종 src
    //? 03 01 02
    temp[0] = state[8] ^ state[11]; // 02 03 에해당하는 xtime
    temp[0] = xtime(temp[0]);
    temp[1] = state[8] ^ state[9]; // 1 에 해당하는 plaintxt
    keytemp = key->rd_key[10];
    Mixtable[11] = temp[0] ^ temp[1] ^ keytemp; // 최종 src

    //! S[1]에 관한 Mix table
    //? 02 01 01
    temp[0] = state[12]; // 02 03 에해당하는 xtime
    temp[0] = xtime(temp[0]);
    temp[1] = state[14] ^ state[15];
    keytemp = key->rd_key[11] >> 24;
    Mixtable[12] = temp[0] ^ temp[1] ^ keytemp; // 최종 src
    //? 01 03 01
    temp[0] = state[14];
    temp[0] = xtime(temp[0]);
    temp[1] = state[12] ^ state[14] ^ state[15]; // 1 에 해당하는 plaintxt
    keytemp = key->rd_key[11] >> 16;
    Mixtable[13] = temp[0] ^ temp[1] ^ keytemp; // 최종 src
    //? 01 02 03
    temp[0] = state[14] ^ state[15]; // 02 03 에해당하는 xtime
    temp[0] = xtime(temp[0]);
    temp[1] = state[12] ^ state[15]; // 1 에 해당하는 plaintxt
    keytemp = key->rd_key[11] >> 8;
    Mixtable[14] = temp[0] ^ temp[1] ^ keytemp; // 최종 src
    //? 03 01 02
    temp[0] = state[12] ^ state[15]; // 02 03 에해당하는 xtime
    temp[0] = xtime(temp[0]);
    temp[1] = state[12] ^ state[14]; // 1 에 해당하는 plaintxt
    keytemp = key->rd_key[11];
    Mixtable[15] = temp[0] ^ temp[1] ^ keytemp; // 최종 src
}

void AES_encrypt_FACE(unsigned char *in, unsigned char LUT_Rd2[4][4][256], unsigned char *out, AES_KEY *key)
{//Round만 수정하였다. Face 최적화를 적용하기 위해서
    unsigned char state[4 * Nb];
    int cnt_i;
    int round = 3;

    for (cnt_i = 0; cnt_i < 4; cnt_i++)
    {
        state[4 * cnt_i] = LUT_Rd2[cnt_i][0][in[15]];
        state[4 * cnt_i + 1] = LUT_Rd2[cnt_i][1][in[15]];
        state[4 * cnt_i + 2] = LUT_Rd2[cnt_i][2][in[15]];
        state[4 * cnt_i + 3] = LUT_Rd2[cnt_i][3][in[15]];
    }

    for (cnt_i = 3; cnt_i < AES_MAXNR; cnt_i++)
    {
        SubByte(state);
        ShiftRow(state);
        MixColumns(state);
        AddRoundKey(state, key, &round);
    }

    SubByte(state);
    ShiftRow(state);
    AddRoundKey(state, key, &round);

    for (cnt_i = 0; cnt_i < 4 * Nb; cnt_i++)
    {
        out[cnt_i] = state[cnt_i];
    }
}

void CRYPTO_ctr128_encrypt_FACE(unsigned char *in, unsigned char *out, unsigned char LUT_Rd2[4][4][256], size_t len, void *masterkey, unsigned char *count)
{//함수만 수정하였다. FACE최적화를 위해서
    int cnt_i, cnt_j;
    int paddingcnt = len % 16;
    unsigned char PT[BLOCKSIZE][16] = {0x00};
    unsigned char CT[BLOCKSIZE][16] = {0x00};
    unsigned char iparray[16];
    unsigned char oparray[16];
    AES_KEY USER_KEY;
    AES_KEY *key = &USER_KEY;

    key->rounds = AES_set_encrypt_key(masterkey, AES_KEY_BIT, key); //!
    reset_count(count);

    for (cnt_i = 0; cnt_i < BLOCKSIZE - 1; cnt_i++)
    {
        for (cnt_j = 0; cnt_j < 16; cnt_j++)
        {
            PT[cnt_i][cnt_j] = in[cnt_i * 16 + cnt_j];
        }
    }
    if (paddingcnt == 0)
    {
        for (cnt_j = 0; cnt_j < 16; cnt_j++)
        {
            PT[BLOCKSIZE - 1][cnt_j] = in[(BLOCKSIZE - 1) * 16 + cnt_j];
        }
    }

    if (paddingcnt != 0) // 패딩 함수.
    {
        for (cnt_j = 0; cnt_j < paddingcnt; cnt_j++)
        {
            PT[BLOCKSIZE - 1][cnt_j] = in[(BLOCKSIZE - 1) * 16 + cnt_j];
        }
        for (cnt_j = paddingcnt; cnt_j < 16; cnt_j++)
        {
            PT[BLOCKSIZE - 1][cnt_j] = (0x10 - paddingcnt);
        }
    }

    for (cnt_i = 0; cnt_i < BLOCKSIZE; cnt_i++) //각각의 count마다 1더하기 해주고, 암호화 시킨다음에 PT와 XoR 해준다. CORE
    {
        if (cnt_i != 0)
            Count_Addition(count);

        for (cnt_j = 0; cnt_j < 16; cnt_j++)
        {
            iparray[cnt_j] = count[cnt_j];
        }
        AES_encrypt_FACE(iparray, LUT_Rd2, oparray, key);
        for (cnt_j = 0; cnt_j < 16; cnt_j++)
        {
            CT[cnt_i][cnt_j] = oparray[cnt_j] ^ PT[cnt_i][cnt_j];
        }
    }

    for (cnt_i = 0; cnt_i < BLOCKSIZE; cnt_i++)
    {
        for (cnt_j = 0; cnt_j < 16; cnt_j++)
        {
            out[cnt_i * 16 + cnt_j] = CT[cnt_i][cnt_j];
        }
    }
}