#include "AES(CTR).h"

AES_KEY KEY;
AES_KEY *key = &KEY;
const unsigned char *in;
const unsigned char *userkey;
unsigned char plaintxt[32] = {0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x7, 0x34, 0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x7, 0x34};
unsigned char UserKey[16] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
unsigned char out[32] = {0x00};
unsigned char count[16] = {0x00};


//! CTR TEST
#if 0
int main()
{
    int cnt_i;

    in = plaintxt;
    userkey = UserKey;
    printf("\nPlain Txt   : ");
    for (cnt_i = 0; cnt_i < 32; cnt_i++)
    {
        printf("%02x ", in[cnt_i]);
    }

    printf("\nKEY         : ");
    for (cnt_i = 0; cnt_i < 16; cnt_i++)
    {
        printf("%02x ", userkey[cnt_i]);
    }

    //! Encrypt
    CRYPTO_ctr128_encrypt(in, out, 32, userkey, count);

    printf("\nEncrypt txt : ");
    for (cnt_i = 0; cnt_i < 32; cnt_i++)
    {
        printf("%02x ", out[cnt_i]);
    }
    return 0;
}
#endif


//!성능테스트
#if 1
int main()
{
    unsigned long long cycles1, cycles2, cycles3, cycles4;
    unsigned long long totalcycles1 = 0;
    unsigned long long totalcycles2 = 0;
    int cnt_i = 0;
    in = plaintxt;
    userkey = UserKey;

    // key->rounds = AES_set_encrypt_key(UserKey, AES_KEY_BIT, key);


    for(cnt_i = 0 ; cnt_i < 10000; cnt_i++)
    {

    //! Encrypt
    cycles1 = cpucycles();
    CRYPTO_ctr128_encrypt(in, out, 32, userkey, count);
    cycles2 = cpucycles();

    totalcycles1 += cycles2 - cycles1;
    }
    printf("cpu cycles of AES 32 ENC %10lld\n",totalcycles1/10000);
   
    return 0;
}
#endif


//! 파일 입출력 KAT
#if 0
int main()
{
    int cnt_i, cnt_j = 0;
    FILE *ifp, *ofp;
    ifp = fopen("AES128(CTR)KAT.req", "r"); // Read할 파일 개방
    ofp = fopen("AES128(CTR)KAT.rsp", "w"); //Write할 파일 개방
    if (ifp == NULL)
    {
        printf("ERROR_Not_opened");// NULL 반환시 오류값 생성
        return 1;
    }
    if (ofp == NULL)
    {
        printf("ERROR_Not_opened");// NULL 반환시 오류값 생성
        return 1;
    }
    
    for (cnt_j = 0; cnt_j < 276 ; cnt_j++)
    {
        char c = 0x00; //fgetc함수를 받아주는 char 변수
        unsigned char testkey[16] = {0x00}; // userkey 값을 받아줄 배열
        unsigned char testpt[16] = {0x00};  // plaintxt 값을 받아줄 배열
        for (cnt_i = 0; cnt_i < 6; cnt_i++)
        {
            c = fgetc(ifp); // req 문서의 맨처음 KEY = 을 받아주는 함수
        }
        for (cnt_i = 0; cnt_i < 32; cnt_i++)
        { //실질적 key들의 문자들을 숫자들로 바꾸어 주고 key배열값에 저장시키는 함수
            c = fgetc(ifp);
            if (c >= 'a' && c <= 'z') //ASCII 값에 따라 저장
                c = c - 'a' + 10;
            if (c >= 'A' && c <= 'Z')
                c = c - 'A' + 10;
            if (c >= '0' && c <= '9')
                c = c - '0';

            if (cnt_i % 2 == 0)
                testkey[cnt_i / 2] += c * 16;
            if (cnt_i % 2 == 1)
                testkey[cnt_i / 2] += c;
        }
        c = fgetc(ifp); // 개행문자 \n 삭제

        for (cnt_i = 0; cnt_i < 7; cnt_i++)// CTR = 을 받아주는 함수
        {
            c = fgetc(ifp);
        }
        for(cnt_i = 0 ; cnt_i <16 ; cnt_i ++) // count값 초기화
        {
            count[cnt_i] = 0;
        }

        for (cnt_i = 0; cnt_i < 32; cnt_i++)
        {// 실질적 CTR의 문자들을 숫자들로 바꾸어 주고 CTR배열값에 저장시키는 함수
            c = fgetc(ifp);
            if (c >= 'a' && c <= 'z')
                c = c - 'a' + 10;
            if (c >= 'A' && c <= 'Z')
                c = c - 'A' + 10;
            if (c >= '0' && c <= '9')
                c = c - '0';

            if (cnt_i % 2 == 0)
                count[cnt_i / 2] += c * 16;
            if (cnt_i % 2 == 1)
                count[cnt_i / 2] += c;
        }
        c = fgetc(ifp); // 개행문자 \n 삭제

        for (cnt_i = 0; cnt_i < 6; cnt_i++)// PT = 을 받아주는 함수
        {
            c = fgetc(ifp);
        }

        for (cnt_i = 0; cnt_i < 32; cnt_i++)
        {// 실질적 PT의 문자들을 숫자들로 바꾸어 주고 pt배열값에 저장시키는 함수
            c = fgetc(ifp);
            if (c >= 'a' && c <= 'z')
                c = c - 'a' + 10;
            if (c >= 'A' && c <= 'Z')
                c = c - 'A' + 10;
            if (c >= '0' && c <= '9')
                c = c - '0';

            if (cnt_i % 2 == 0)
                testpt[cnt_i / 2] += c * 16;
            if (cnt_i % 2 == 1)
                testpt[cnt_i / 2] += c;
        }
        c = fgetc(ifp);//개행문자 삭제
        c = fgetc(ifp);
        c = fgetc(ifp);
        c = fgetc(ifp);
    
        fprintf(ofp, "KEY = ");// 출력시킬 파일에 Write 해주는 함수 KEY값 Write
        for (cnt_i = 0; cnt_i < 16; cnt_i++)
        {
            fprintf(ofp, "%02X", testkey[cnt_i]);
        }
        fprintf(ofp, "\nCTR = ");// 출력시킬 파일에 Write 해주는 함수 KEY값 Write
        for (cnt_i = 0; cnt_i < 16; cnt_i++)
        {
            fprintf(ofp, "%02X", count[cnt_i]);
        }
        fprintf(ofp, "\nPT = ");// 출력시킬 파일에 Write 해주는 함수 PT값 Write
        for (cnt_i = 0; cnt_i < 16; cnt_i++)
        {
            fprintf(ofp, "%02X", testpt[cnt_i]);
        }

        // !Encrypt
        in = testpt;
        userkey = testkey;
        CRYPTO_ctr128_encrypt(in, out, 16, userkey, count);

        fprintf(ofp, "\nCT = ");// 출력시킬 파일에 Write 해주는 함수 CT값 Write
        for (cnt_i = 0; cnt_i < 16; cnt_i++)
        {
            fprintf(ofp, "%02X", out[cnt_i]);
        }
        fprintf(ofp, "\n\n");
    }
    fclose(ifp); //개방한 파일들 닫아주기
    fclose(ofp);
    return 0;
}
#endif

//! 파일 입출력 MMT
#if 0
int main()
{
    int cnt_i, cnt_j = 0;
    FILE *ifp, *ofp;
    ifp = fopen("AES128(CTR)MMT.req", "r"); // Read할 파일 개방
    ofp = fopen("AES128(CTR)MMT.rsp", "w"); //Write할 파일 개방
    if (ifp == NULL)
    {
        printf("ERROR_Not_opened");// NULL 반환시 오류값 생성
        return 1;
    }
    if (ofp == NULL)
    {
        printf("ERROR_Not_opened");// NULL 반환시 오류값 생성
        return 1;
    }
    
    for (cnt_j = 0; cnt_j < 10 ; cnt_j++)
    {
        char c = 0x00; //fgetc함수를 받아주는 char 변수
        unsigned char testkey[16] = {0x00}; // userkey 값을 받아줄 배열
        unsigned char testctr[16] = {0x00}; // ctr 값을 받아줄 배열
        unsigned char *testpt;// plaintxt 값을 받아줄 배열
        unsigned char *testout;// ciphertxt 값을 받아줄 배열
        testpt = (unsigned char*)calloc(16*(cnt_j+1),sizeof(unsigned char));
        testout = (unsigned char*)calloc(16*(cnt_j+1),sizeof(unsigned char));
        for (cnt_i = 0; cnt_i < 6; cnt_i++)
        {
            c = fgetc(ifp); // req 문서의 맨처음 KEY = 을 받아주는 함수
        }
        for (cnt_i = 0; cnt_i < 32; cnt_i++)
        { //실질적 key들의 문자들을 숫자들로 바꾸어 주고 key배열값에 저장시키는 함수
            c = fgetc(ifp);
            if (c >= 'a' && c <= 'z') //ASCII 값에 따라 저장
                c = c - 'a' + 10;
            if (c >= 'A' && c <= 'Z')
                c = c - 'A' + 10;
            if (c >= '0' && c <= '9')
                c = c - '0';

            if (cnt_i % 2 == 0)
                testkey[cnt_i / 2] += c * 16;
            if (cnt_i % 2 == 1)
                testkey[cnt_i / 2] += c;
        }
        c = fgetc(ifp); // 개행문자 \n 삭제

        for (cnt_i = 0; cnt_i < 7; cnt_i++)// CTR = 을 받아주는 함수
        {
            c = fgetc(ifp);
        }

        for (cnt_i = 0; cnt_i < 32; cnt_i++)
        {// 실질적 CTR의 문자들을 숫자들로 바꾸어 주고 CTR배열값에 저장시키는 함수
            c = fgetc(ifp);
            if (c >= 'a' && c <= 'z')
                c = c - 'a' + 10;
            if (c >= 'A' && c <= 'Z')
                c = c - 'A' + 10;
            if (c >= '0' && c <= '9')
                c = c - '0';

            if (cnt_i % 2 == 0)
                testctr[cnt_i / 2] += c * 16;
            if (cnt_i % 2 == 1)
                testctr[cnt_i / 2] += c;
        }
        c = fgetc(ifp); // 개행문자 \n 삭제

        for (cnt_i = 0; cnt_i < 6; cnt_i++)// PT = 을 받아주는 함수
        {
            c = fgetc(ifp);
        }

        for (cnt_i = 0; cnt_i < 32*(cnt_j+1); cnt_i++)
        {// 실질적 PT의 문자들을 숫자들로 바꾸어 주고 pt배열값에 저장시키는 함수
            c = fgetc(ifp);
            if (c >= 'a' && c <= 'z')
                c = c - 'a' + 10;
            if (c >= 'A' && c <= 'Z')
                c = c - 'A' + 10;
            if (c >= '0' && c <= '9')
                c = c - '0';

            if (cnt_i % 2 == 0)
                testpt[cnt_i / 2] += c * 16;
            if (cnt_i % 2 == 1)
                testpt[cnt_i / 2] += c;
        }
        c = fgetc(ifp);//개행문자 삭제
        c = fgetc(ifp);
        c = fgetc(ifp);
        c = fgetc(ifp);
    
        fprintf(ofp, "KEY = ");// 출력시킬 파일에 Write 해주는 함수 KEY값 Write
        for (cnt_i = 0; cnt_i < 16; cnt_i++)
        {
            fprintf(ofp, "%02X", testkey[cnt_i]);
        }
        fprintf(ofp, "\nCTR = ");// 출력시킬 파일에 Write 해주는 함수 KEY값 Write
        for (cnt_i = 0; cnt_i < 16; cnt_i++)
        {
            fprintf(ofp, "%02X", testctr[cnt_i]);
        }
        fprintf(ofp, "\nPT = ");// 출력시킬 파일에 Write 해주는 함수 PT값 Write
        for (cnt_i = 0; cnt_i < 16*(cnt_j + 1); cnt_i++)
        {
            fprintf(ofp, "%02X", testpt[cnt_i]);
        }

        // !Encrypt
        in = testpt;
        userkey = testkey;
        CRYPTO_ctr128_encrypt(in, testout, 16 * (cnt_j + 1), userkey, testctr);

        fprintf(ofp, "\nCT = ");// 출력시킬 파일에 Write 해주는 함수 CT값 Write
        for (cnt_i = 0; cnt_i < 16 * (cnt_j + 1); cnt_i++)
        {
            fprintf(ofp, "%02X", testout[cnt_i]);
        }
        fprintf(ofp, "\n\n");
    free(testout);
    free(testpt);
    }
    fclose(ifp); //개방한 파일들 닫아주기
    fclose(ofp);
    return 0;
}
#endif

//! 파일 입출력 MCT
#if 0
int main()
{
    int cnt_i, cnt_j, cnt_k = 0;
    FILE *ifp, *ofp;
    ifp = fopen("AES128(CTR)MCT.req", "r"); // Read할 파일 개방
    ofp = fopen("AES128(CTR)MCT.rsp", "w"); //Write할 파일 개방
    if (ifp == NULL)
    {
        printf("ERROR_Not_opened"); // NULL 반환시 오류값 생성
        return 1;
    }
    if (ofp == NULL)
    {
        printf("ERROR_Not_opened"); // NULL 반환시 오류값 생성
        return 1;
    }

    char c = 0x00;                       //fgetc함수를 받아주는 char 변수
    unsigned char testkey[16] = {0x00};  // userkey 값을 받아줄 배열
    unsigned char testctr[16] = {0x00};  // ivec 값을 받아줄 배열
    unsigned char printctr[16] = {0x00}; // ivec 값을 출력할 배열
    unsigned char printpt[16] = {0x00};  // plain txt 값을 출력할 배열
    unsigned char printkey[16] = {0x00}; // key 값을 출력할 배열
    unsigned char *testpt;               // plaintxt 값을 받아줄 배열
    unsigned char *testout;              // ciphertxt 값을 받아줄 배열
    testpt = (unsigned char *)calloc(16, sizeof(unsigned char));
    testout = (unsigned char *)calloc(16, sizeof(unsigned char));

    for (cnt_i = 0; cnt_i < 6; cnt_i++)
    {
        c = fgetc(ifp); // req 문서의 맨처음 KEY = 을 받아주는 함수
    }
    for (cnt_i = 0; cnt_i < 32; cnt_i++)
    { //실질적 key들의 문자들을 숫자들로 바꾸어 주고 key배열값에 저장시키는 함수
        c = fgetc(ifp);
        if (c >= 'a' && c <= 'z') //ASCII 값에 따라 저장
            c = c - 'a' + 10;
        if (c >= 'A' && c <= 'Z')
            c = c - 'A' + 10;
        if (c >= '0' && c <= '9')
            c = c - '0';

        if (cnt_i % 2 == 0)
            testkey[cnt_i / 2] += c * 16;
        if (cnt_i % 2 == 1)
            testkey[cnt_i / 2] += c;
    }
    c = fgetc(ifp); // 개행문자 \n 삭제

    for (cnt_i = 0; cnt_i < 7; cnt_i++) // CTR = 을 받아주는 함수
    {
        c = fgetc(ifp);
    }

    for (cnt_i = 0; cnt_i < 32; cnt_i++)
    { // 실질적 CTR의 문자들을 숫자들로 바꾸어 주고 CTR배열값에 저장시키는 함수
        c = fgetc(ifp);
        if (c >= 'a' && c <= 'z')
            c = c - 'a' + 10;
        if (c >= 'A' && c <= 'Z')
            c = c - 'A' + 10;
        if (c >= '0' && c <= '9')
            c = c - '0';

        if (cnt_i % 2 == 0)
            testctr[cnt_i / 2] += c * 16;
        if (cnt_i % 2 == 1)
            testctr[cnt_i / 2] += c;
    }
    c = fgetc(ifp); // 개행문자 \n 삭제

    for (cnt_i = 0; cnt_i < 6; cnt_i++) // PT = 을 받아주는 함수
    {
        c = fgetc(ifp);
    }

    for (cnt_i = 0; cnt_i < 32; cnt_i++)
    { // 실질적 PT의 문자들을 숫자들로 바꾸어 주고 pt배열값에 저장시키는 함수
        c = fgetc(ifp);
        if (c >= 'a' && c <= 'z')
            c = c - 'a' + 10;
        if (c >= 'A' && c <= 'Z')
            c = c - 'A' + 10;
        if (c >= '0' && c <= '9')
            c = c - '0';

        if (cnt_i % 2 == 0)
            testpt[cnt_i / 2] += c * 16;
        if (cnt_i % 2 == 1)
            testpt[cnt_i / 2] += c;
    }
    c = fgetc(ifp); //개행문자 삭제

    for (cnt_i = 0; cnt_i < 16; cnt_i++) //먼저 출력할 값들은 처음값에서 바뀌지 않으니 출력변수에 저장
    {
        printctr[cnt_i] = testctr[cnt_i];
        printpt[cnt_i] = testpt[cnt_i];
        printkey[cnt_i] = testkey[cnt_i];
    }

    // !Encrypt
    in = testpt;
    userkey = testkey;
    for (cnt_j = 0; cnt_j < 1000; cnt_j++) //count 0에 대해 999번 encrypt
    {
        CRYPTO_ctr128_encrypt(in, testout, 16, userkey, testctr);
        for (cnt_i = 0; cnt_i < 16; cnt_i++)
        {
            testpt[cnt_i] = testout[cnt_i];
        }
        Count_Addition(testctr);
    }

    fprintf(ofp, "COUNT = %d", 0); // 출력시킬 파일에 Write 해주는 함수 count값 Write
    fprintf(ofp, "\nKEY = ");      // 출력시킬 파일에 Write 해주는 함수 KEY값 Write
    for (cnt_i = 0; cnt_i < 16; cnt_i++)
    {
        fprintf(ofp, "%02X", testkey[cnt_i]);
    }
    fprintf(ofp, "\nCTR = "); // 출력시킬 파일에 Write 해주는 함수 KEY값 Write
    for (cnt_i = 0; cnt_i < 16; cnt_i++)
    {
        fprintf(ofp, "%02X", printctr[cnt_i]);
    }
    fprintf(ofp, "\nPT = "); // 출력시킬 파일에 Write 해주는 함수 PT값 Write
    for (cnt_i = 0; cnt_i < 16; cnt_i++)
    {
        fprintf(ofp, "%02X", printpt[cnt_i]);
    }

    fprintf(ofp, "\nCT = "); // 출력시킬 파일에 Write 해주는 함수 CT값 Write
    for (cnt_i = 0; cnt_i < 16; cnt_i++)
    {
        fprintf(ofp, "%02X", testout[cnt_i]);
    }
    fprintf(ofp, "\n\n");

    for (cnt_k = 1; cnt_k < 100; cnt_k++) // 나머지 99번 COUNT
    {

        for (cnt_i = 0; cnt_i < 16; cnt_i++)
        {
            printpt[cnt_i] = testout[cnt_i]; //기존값 출력변수에 지정
        }
        for (cnt_i = 0; cnt_i < 16; cnt_i++)
        {
            testkey[cnt_i] = printkey[cnt_i] ^ testout[cnt_i]; //기존값 출력변수에 지정 //!128? 192? 256?
        }
        for (cnt_i = 0; cnt_i < 16; cnt_i++)
        {
            printctr[cnt_i] = testctr[cnt_i]; // 기존값 출력변수에 지정
            printkey[cnt_i] = testkey[cnt_i];
        }

        in = testpt;
        userkey = testkey;
    
        for (cnt_j = 0; cnt_j < 1000; cnt_j++) //count 0에 대해 999번 encrypt
    {
        CRYPTO_ctr128_encrypt(in, testout, 16, userkey, testctr);
        for (cnt_i = 0; cnt_i < 16; cnt_i++)
        {
            testpt[cnt_i] = testout[cnt_i];
        }
        Count_Addition(testctr);
    }

        fprintf(ofp, "COUNT = %d", cnt_k); // 출력시킬 파일에 Write 해주는 함수 count값 Write
        fprintf(ofp, "\nKEY = ");          // 출력시킬 파일에 Write 해주는 함수 KEY값 Write
        for (cnt_i = 0; cnt_i < 16; cnt_i++)
        {
            fprintf(ofp, "%02X", printkey[cnt_i]);
        }
        fprintf(ofp, "\nCTR = "); // 출력시킬 파일에 Write 해주는 함수 KEY값 Write
        for (cnt_i = 0; cnt_i < 16; cnt_i++)
        {
            fprintf(ofp, "%02X", printctr[cnt_i]);
        }
        fprintf(ofp, "\nPT = "); // 출력시킬 파일에 Write 해주는 함수 PT값 Write
        for (cnt_i = 0; cnt_i < 16; cnt_i++)
        {
            fprintf(ofp, "%02X", printpt[cnt_i]);
        }

        fprintf(ofp, "\nCT = "); // 출력시킬 파일에 Write 해주는 함수 CT값 Write
        for (cnt_i = 0; cnt_i < 16; cnt_i++)
        {
            fprintf(ofp, "%02X", testout[cnt_i]);
        }
        fprintf(ofp, "\n\n");
    }

    free(testout);
    free(testpt);
    fclose(ifp); //개방한 파일들 닫아주기
    fclose(ofp);
    return 0;
}
#endif
