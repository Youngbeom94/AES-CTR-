#include "AES(CTR).h"

AES_KEY KEY;
AES_KEY *key = &KEY;
unsigned char in[BLOCKSIZE * 16] = {0x00};
unsigned char userkey[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
unsigned char out[BLOCKSIZE * 16] = {0x00};
unsigned char count[16] = {0x00,0x00,0x00,0x00};
unsigned char LUT_Rd1[4][256] = {{0x00}};
unsigned char LUT_Rd1_plus[12] = {0x00};
unsigned char LUT_Rd2_plus[4][4][256] = {{{0x00}}};
unsigned char LUT_FL[4][4][256] = {{{0x00}}};

//! CTR TEST
#if 0
int main()
{
    int cnt_i;
    printf("\nPlain Txt\n");
    for (cnt_i = 0; cnt_i < BLOCKSIZE * 16; cnt_i++)
    {
        if ((cnt_i % 16 == 0) && (cnt_i != 0))
            printf("\n");

        printf("%02x ", in[cnt_i]);
    }

    printf("\n\nKEY:");
    for (cnt_i = 0; cnt_i < 16; cnt_i++)
    {
        printf("%02x ", userkey[cnt_i]);
    }

    //! Encrypt
    CRYPTO_ctr128_encrypt(in, out, BLOCKSIZE * 16, userkey, count);
    printf("\n\nOrign ver CTR Encrypt txt\n");
    for (cnt_i = 0; cnt_i < BLOCKSIZE * 16; cnt_i++)
    {
        if ((cnt_i % 16 == 0) && (cnt_i != 0))
            printf("\n");
        printf("%02x ", out[cnt_i]);
    }

    // //! Encrypt of FACE
    // Make_LUTRd1(LUT_Rd1, LUT_Rd1_plus, userkey, count);
    // Make_LUTRd2(LUT_Rd1, LUT_Rd1_plus, LUT_Rd2_plus, userkey, count);
    // CRYPTO_ctr128_encrypt_FACE(in, out, LUT_Rd2_plus, BLOCKSIZE * 16, userkey, count);

    // printf("\n\nFACE ver CTR Encrypt txt\n");
    // for (cnt_i = 0; cnt_i < BLOCKSIZE * 16; cnt_i++)
    // {
    //     if ((cnt_i % 16 == 0) && (cnt_i != 0))
    //         printf("\n");
    //     printf("%02x ", out[cnt_i]);
    // }

    //! Encrypt of FACE_Light
    // Make_LUT_Face_Light(LUT_FL,userkey,count);
    // CRYPTO_ctr128_encrypt_FACE_Light(in,out,LUT_FL,BLOCKSIZE * 16,userkey,count);
    // printf("\n\nFACE_Light ver CTR Encrypt txt\n");
    // for (cnt_i = 0; cnt_i < BLOCKSIZE * 16; cnt_i++)
    // {
    //     if ((cnt_i % 16 == 0) && (cnt_i != 0))
    //         printf("\n");
    //     printf("%02x ", out[cnt_i]);
    // }

    // //! Encrypt of FACE_Extended
    Make_LUTRd1(LUT_Rd1, LUT_Rd1_plus, userkey, count);
    Make_LUT_Face_Ex(LUT_FL,LUT_Rd1_plus,userkey,count);
    CRYPTO_ctr128_encrypt_FACE_Ex(in, out, LUT_Rd1,LUT_FL, BLOCKSIZE * 16, userkey, count);

    printf("\n\nFACE - Ex Encrypt txt\n");
    for (cnt_i = 0; cnt_i < BLOCKSIZE * 16; cnt_i++)
    {
        if((cnt_i % 16 == 0) && (cnt_i != 0))
            printf("\n");
        printf("%02x ", out[cnt_i]);
    }

    return 0;
}
#endif

//!성능테스트 CTR ver vs FACE CTR ver
#if 0
int main()
{
    unsigned long long cycles1, cycles2, cycles3, cycles4;
    unsigned long long totalcycles1 = 0;
    unsigned long long totalcycles2 = 0;
    int cnt_i = 0;
    Make_LUTRd1(LUT_Rd1, LUT_Rd1_plus, userkey, count);//! 1KB
    Make_LUTRd2(LUT_Rd1, LUT_Rd1_plus, LUT_Rd2_plus, userkey, count);//! 4KB
    Make_LUT_Face_Light(LUT_FL,userkey,count);
    Make_LUT_Face_Ex(LUT_FL,LUT_Rd1_plus,userkey,count);


    int time = 10000;
    for (cnt_i = 0; cnt_i < time; cnt_i++)
    {

        //! Encrypt Origin ver
        cycles1 = cpucycles();
        CRYPTO_ctr128_encrypt(in, out, BLOCKSIZE * 16, userkey, count);
        cycles2 = cpucycles();

        totalcycles1 += cycles2 - cycles1;
    }
    printf("cpu cycles of AES(CTR) ENC %10lld\n", totalcycles1 / time);

    // totalcycles1 = 0x00;
    // for (cnt_i = 0; cnt_i < time; cnt_i++)
    // {
    //     //! Encrypt FACE ver

    //     cycles1 = cpucycles();
    //     CRYPTO_ctr128_encrypt_FACE(in, out, LUT_Rd2_plus, BLOCKSIZE * 16, userkey, count);
    //     cycles2 = cpucycles();

    //     totalcycles1 += cycles2 - cycles1;
    // }
    // printf("cpu cycles of AES_FACE ENC %10lld\n", totalcycles1 / time);

    // totalcycles1 = 0x00;
    // for (cnt_i = 0; cnt_i < time; cnt_i++)
    // {
    //     //! Encrypt FACE_Light ver
    //     cycles1 = cpucycles();
    //     CRYPTO_ctr128_encrypt_FACE_Light(in,out,LUT_FL,BLOCKSIZE * 16,userkey,count);
    //     cycles2 = cpucycles();

    //     totalcycles1 += cycles2 - cycles1;
    // }
    // printf("cpu cycles of AES_FcLt ENC %10lld\n", totalcycles1 / time);

    totalcycles1 = 0x00;
    for (cnt_i = 0; cnt_i < time; cnt_i++)
    {
         //! Encrypt FACE_Extended ver
        cycles3 = cpucycles();
        CRYPTO_ctr128_encrypt_FACE_Ex(in, out, LUT_Rd1,LUT_FL, BLOCKSIZE * 16, userkey, count);
        cycles4 = cpucycles();

        totalcycles1 += cycles4 - cycles3;
    }
    printf("cpu cycles of AES_FaEx ENC %10lld\n", totalcycles1 / time);

    return 0;
}
#endif

//!성능테스트 Make Table
#if 1
int main()
{
    unsigned long long cycles1, cycles2, cycles3, cycles4;
    unsigned long long totalcycles1 = 0;
    unsigned long long totalcycles2 = 0;
    int cnt_i = 0;
    Make_LUTRd1(LUT_Rd1, LUT_Rd1_plus, userkey, count);//! 1KB
    Make_LUTRd2(LUT_Rd1, LUT_Rd1_plus, LUT_Rd2_plus, userkey, count);//! 4KB
    Make_LUT_Face_Light(LUT_FL,userkey,count);
    Make_LUT_Face_Ex(LUT_FL,LUT_Rd1_plus,userkey,count);


    int time = 10000;
    for (cnt_i = 0; cnt_i < time; cnt_i++)
    {

        cycles1 = cpucycles();
        Make_LUTRd1(LUT_Rd1, LUT_Rd1_plus, userkey, count);//! 1KB
        cycles2 = cpucycles();

        totalcycles1 += cycles2 - cycles1;
    }
    printf("cpu cycles of Make_LUTRd1 %10lld\n", totalcycles1 / time);

    totalcycles1 = 0x00;
     for (cnt_i = 0; cnt_i < time; cnt_i++)
    {

        cycles1 = cpucycles();
        Make_LUTRd2(LUT_Rd1, LUT_Rd1_plus, LUT_Rd2_plus, userkey, count);//! 4KB
        cycles2 = cpucycles();

        totalcycles1 += cycles2 - cycles1;
    }
    printf("cpu cycles of Make_LUTRd2 %10lld\n", totalcycles1 / time);

     totalcycles1 = 0x00;
     for (cnt_i = 0; cnt_i < time; cnt_i++)
    {

        cycles1 = cpucycles();
        Make_LUT_Face_Light(LUT_FL,userkey,count);
        cycles2 = cpucycles();

        totalcycles1 += cycles2 - cycles1;
    }
    printf("cpu cycles of Make_LUT_Face_Light %10lld\n", totalcycles1 / time);

     totalcycles1 = 0x00;
     for (cnt_i = 0; cnt_i < time; cnt_i++)
    {

        cycles1 = cpucycles();
        Make_LUT_Face_Ex(LUT_FL,LUT_Rd1_plus,userkey,count);
        cycles2 = cpucycles();

        totalcycles1 += cycles2 - cycles1;
    }
    printf("cpu cycles of Make_LUT_Face_Ex %10lld\n", totalcycles1 / time);
    
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
        CRYPTO_ctr128_encrypt(testpt, out, 16, testkey, count);

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
        CRYPTO_ctr128_encrypt(testpt, testout, 16 * (cnt_j + 1), testkey, testctr);

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
    ofp = fopen("test.rsp", "w"); //Write할 파일 개방
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
