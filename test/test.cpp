/*
 * @Author: LiuKun
 * @Date: 2022-05-04 23:35:42
 * @LastEditTime: 2022-06-20 12:46:43
 * @Description:
 *
 * Copyright (c) 2022 by LLW, All Rights Reserved.
 */
// #include "lwe.h"
#include "lwefunction.h"
#include "rlwefunction.h"
#include "bootstrap.h"
#include <sys/time.h>

using namespace std;

void test_Lwe_encrypt()
{
    usint t = 4;
    usint n = 64;         //维度：应该是512
    NativeInteger q(512); // lwe密文模数

    usint N = 128;   // RLWE维度
    NativeInteger Q; // RLWE模数
    Q = PreviousPrime<NativeInteger>(FirstPrime<NativeInteger>(27, 2048), 2048);
    cout << "Q = " << Q << endl;

    usint ks_base = 25;
    LweParams lweparams(t, n, q, N, Q, ks_base, 3.2);
    LweFunction lwe_function;
    LwePlaintext m = 2;

    LweSecretKey sk_n = lwe_function.LweTerKeyGen_n(lweparams);
    LweSecretKey sk_N = lwe_function.LweTerKeyGen_N(lweparams);
    
    LweCipher cipher1 = lwe_function.LweEncrypt(m, sk_n, lweparams);
    LweCipher cipher2 = lwe_function.LweEncrypt(m, sk_N, lweparams);

    // //3.解密
    LwePlaintext lwe_decrypt1 = lwe_function.LweDecrypt(cipher1, sk_n, lweparams);
    LwePlaintext lwe_decrypt2 = lwe_function.LweDecrypt(cipher2, sk_N, lweparams);
    // 4.输出结果
    cout << "解密为：" << lwe_decrypt1 << " and " << lwe_decrypt2 << endl;
}

void test_KeySwitch()
{
    //   Q = PreviousPrime<NativeInteger>(FirstPrime<NativeInteger>(27, 1024),
    //                                    1024);
    //   lweparams = std::make_shared<LWECryptoParams>(64, 512, 512, Q, 3.19, 25);
    //   m_params =
    //       std::make_shared<RingGSWCryptoParams>(lweparams, 1 << 9, 23, method);
    //   break;;

    usint t = 4;
    usint n = 64;         //维度：应该是512
    NativeInteger q(512); // lwe密文模数

    usint N = 512;   // RLWE维度 1024
    NativeInteger Q; // RLWE模数
    Q = PreviousPrime<NativeInteger>(FirstPrime<NativeInteger>(27, 2 * N), 2 * N);
    cout << "Q = " << Q << endl;

    usint ks_base = 23;
    LweParams lweparams(t, n, q, N, Q, ks_base, 3.2);
    LweFunction lwe_function;
    LwePlaintext m = 2;

    LweSecretKey sk_n = lwe_function.LweTerKeyGen_n(lweparams);
    LweSecretKey sk_N = lwe_function.LweTerKeyGen_N(lweparams);

    //在mod Q下的私钥
    NativeVector newSK = sk_n.GetLweSecretKey();
    newSK.SwitchModulus(Q);
    auto skQ = LweSecretKey(newSK);
    LweCipher cipher1 = lwe_function.LweEncrypt(m, sk_N, lweparams);

    //生成keyswitch密钥
    LweSwitchingKey keysw = lwe_function.LweSwitchingKeyGenV1(sk_N, sk_n, lweparams);
    std::cout << "密钥切换..." << std::endl;
    // keyswitch
    LweCipher cipher2 = lwe_function.LweKeySwitchingV1(cipher1, keysw, lweparams);

    cout << cipher2.GetLweCipher_a().GetModulus() << endl;
    LwePlaintext lwe_decrypt = lwe_function.LweDecrypt(cipher2, skQ, lweparams);
    // 4.输出结果
    cout << "解密为：" << lwe_decrypt << endl;
}

void testModSwitch()
{
    usint t = 4;
    usint n = 8;          //维度：应该是512
    NativeInteger q(512); // lwe密文模数

    usint N = 512;   // RLWE维度 1024
    NativeInteger Q; // RLWE模数
    Q = PreviousPrime<NativeInteger>(FirstPrime<NativeInteger>(27, 2 * N), 2 * N);
    cout << "Q = " << Q << endl;

    usint ks_base = 23;
    LweParams lweparams(t, n, q, N, Q, ks_base, 3.2);
    LweFunction lwe_function;
    LwePlaintext m = 1;

    LweSecretKey sk_n = lwe_function.LweTerKeyGen_n(lweparams);

    //在mod Q下的私钥
    NativeVector newSK = sk_n.GetLweSecretKey();
    newSK.SwitchModulus(Q);
    auto skQ = LweSecretKey(newSK);

    auto ctQ = lwe_function.LweEncrypt(m, skQ, lweparams);

    auto ctq = lwe_function.LweModSwitching(ctQ, lweparams);

    LwePlaintext resultAfterModSwitch = lwe_function.LweDecrypt(ctq, sk_n, lweparams);

    cout << "解密为：" << resultAfterModSwitch << endl;
}

void test_Bootstrapping()
{

    usint t = 4;

#if 1
    // case: TOY
    usint n = 64;          //维度
    NativeInteger q(1024); // lwe密文模数
    usint N = 1024;         // RLWE维度 
    NativeInteger Q;       // RLWE模数
    Q = PreviousPrime<NativeInteger>(FirstPrime<NativeInteger>(27, 2 * N), 2 * N);

    usint ks_base = 23;
    LweParams lweparams(t, n, q, N, Q, ks_base, 3.2);
    usint baseG = 1 << 7;
#endif

#if 0
    // case STD128:
    usint n = 512;        //维度：应该是512
    NativeInteger q(512); // lwe密文模数
    usint N = 1024;       // RLWE维度 1024
    NativeInteger Q;      // RLWE模数
    Q = PreviousPrime<NativeInteger>(FirstPrime<NativeInteger>(27, 2 * N), 2 * N);

    usint ks_base = 23;
    LweParams lweparams(t, n, q, N, Q, ks_base, 3.19);
    usint baseG = 1 << 7;
#endif
    LwePlaintext m = 1;
    LweFunction lwe_func;

    LweSecretKey sk_n = lwe_func.LweTerKeyGen_n(lweparams);
    LweSecretKey sk_N = lwe_func.LweTerKeyGen_N(lweparams);

    LweSwitchingKey keysw = lwe_func.LweSwitchingKeyGenV1(sk_N, sk_n, lweparams);

    // 初始密文
    LweCipher cipher1 = lwe_func.LweEncrypt(m, sk_n, lweparams);

    RLweParams rlweparams(lweparams, baseG);
    RLweFunction rlwefunc;

    // 私钥sk_N->sk(x)的NTT形式
    NativePoly rsk = rlwefunc.RLweTerKeyGen(rlweparams, sk_N);

    // RGSWFunction
    RGSWFunction rgswfunc;
    Bootstrapkey bsk = rgswfunc.BootstrapkeyGen(sk_n, rsk, rlweparams);

    std::cout << "开始Identity自举..." << std::endl;

    // int num = 1;
    clock_t begin = clock();
    for (int32_t i = 0; i < 1000; i++) {

        LweCipher resultOfBoot = rgswfunc.Bootstrap(bsk, cipher1, rlweparams);

    // 密钥切换和模切换之前，密文应该是(a_new, b_new) mod Q N维向量 sk = SK_N
    // LwePlaintext result = lwe_function.LweDecrypt(resultOfBoot, sk_N, lweparams);

    // // keySwitch
        LweCipher cipher2 = lwe_func.LweKeySwitchingV1(resultOfBoot, keysw, lweparams);
    // //modSwitch
        LweCipher ctq = lwe_func.LweModSwitching(cipher2, lweparams);

        LwePlaintext result = lwe_func.LweDecrypt(ctq, sk_n, lweparams);

    }
    clock_t end = clock();
    cout << "finished "<< 1000 <<"  bootstrappings " << endl;
    //cout << "time per bootstrappings ... " << (end - begin) / double(1000) / CLOCKS_PER_SEC <<" s "<< endl;
     cout << "time per bootstrappings (microsecs)... " << (end - begin) / double(1000 - 1)  << endl;

    // LweCipher resultOfBoot = rgswfunc.Bootstrap(bsk, cipher1, rlweparams);

    // // 密钥切换和模切换之前，密文应该是(a_new, b_new) mod Q N维向量 sk = SK_N
    // // LwePlaintext result = lwe_function.LweDecrypt(resultOfBoot, sk_N, lweparams);

    // // // keySwitch
    // LweCipher cipher2 = lwe_func.LweKeySwitchingV1(resultOfBoot, keysw, lweparams);
    // // //modSwitch
    // LweCipher ctq = lwe_func.LweModSwitching(cipher2, lweparams);

    // LwePlaintext result = lwe_func.LweDecrypt(ctq, sk_n, lweparams);

    // // 4.输出结果
    // cout << "自举 " << m << "  解密为:" << result << endl;
}

void test_gateBoot()
{

    usint t = 4;
    // case: TOY
    usint n = 64;          //维度：应该是512
    NativeInteger q(1024); // lwe密文模数
    usint N = 512;         // RLWE维度 1024
    NativeInteger Q;       // RLWE模数
    Q = PreviousPrime<NativeInteger>(FirstPrime<NativeInteger>(27, 2 * N), 2 * N);

    usint ks_base = 23;
    LweParams lweparams(t, n, q, N, Q, ks_base, 3.2);
    usint baseG = 1 << 9;

    LweFunction lwe_function;
    LwePlaintext m0 = 0;
    LwePlaintext m1 = 1;
    LweSecretKey sk_n = lwe_function.LweTerKeyGen_n(lweparams);
    LweSecretKey sk_N = lwe_function.LweTerKeyGen_N(lweparams);

    LweSwitchingKey keysw = lwe_function.LweSwitchingKeyGenV1(sk_N, sk_n, lweparams);

    // 初始密文
    LweCipher cipher1 = lwe_function.LweEncrypt(m0, sk_n, lweparams);
    LweCipher cipher2 = lwe_function.LweEncrypt(m1, sk_n, lweparams);

    RLweParams rlweparams(lweparams, baseG);

    RLweFunction rlwefun;

    // 私钥sk_N->sk(x)的NTT形式
    NativePoly rsk = rlwefun.RLweTerKeyGen(rlweparams, sk_N);

    // //RGSWFunction
    RGSWFunction rgswfunc;
    Bootstrapkey bsk = rgswfunc.BootstrapkeyGen(sk_n, rsk, rlweparams);

    std::cout << "================test NAND================" << std::endl;
    LweCipher result1 = rgswfunc.EvalGateBootstrap(bsk, keysw, NAND, cipher1, cipher1,
                                                   lwe_function, lweparams, rlweparams);
    LweCipher result2 = rgswfunc.EvalGateBootstrap(bsk, keysw, NAND, cipher1, cipher2,
                                                   lwe_function, lweparams, rlweparams);
    LweCipher result3 = rgswfunc.EvalGateBootstrap(bsk, keysw, NAND, cipher2, cipher1,
                                                   lwe_function, lweparams, rlweparams);
    LweCipher result4 = rgswfunc.EvalGateBootstrap(bsk, keysw, NAND, cipher2, cipher2,
                                                   lwe_function, lweparams, rlweparams);

    LwePlaintext out1 = lwe_function.LweDecrypt(result1, sk_n, lweparams);
    LwePlaintext out2 = lwe_function.LweDecrypt(result2, sk_n, lweparams);
    LwePlaintext out3 = lwe_function.LweDecrypt(result3, sk_n, lweparams);
    LwePlaintext out4 = lwe_function.LweDecrypt(result4, sk_n, lweparams);

    cout << m0 << " NAND " << m0 << " :" << out1 << endl;
    cout << m0 << " NAND " << m1 << " :" << out2 << endl;
    cout << m1 << " NAND " << m0 << " :" << out3 << endl;
    cout << m1 << " NAND " << m1 << " :" << out4 << endl;

    std::cout << "================test AND================" << std::endl;
    result1 = rgswfunc.EvalGateBootstrap(bsk, keysw, AND, cipher1, cipher1,
                                         lwe_function, lweparams, rlweparams);
    result2 = rgswfunc.EvalGateBootstrap(bsk, keysw, AND, cipher1, cipher2,
                                         lwe_function, lweparams, rlweparams);
    result3 = rgswfunc.EvalGateBootstrap(bsk, keysw, AND, cipher2, cipher1,
                                         lwe_function, lweparams, rlweparams);
    result4 = rgswfunc.EvalGateBootstrap(bsk, keysw, AND, cipher2, cipher2,
                                         lwe_function, lweparams, rlweparams);

    out1 = lwe_function.LweDecrypt(result1, sk_n, lweparams);
    out2 = lwe_function.LweDecrypt(result2, sk_n, lweparams);
    out3 = lwe_function.LweDecrypt(result3, sk_n, lweparams);
    out4 = lwe_function.LweDecrypt(result4, sk_n, lweparams);

    cout << m0 << " AND " << m0 << " :" << out1 << endl;
    cout << m0 << " AND " << m1 << " :" << out2 << endl;
    cout << m1 << " AND " << m0 << " :" << out3 << endl;
    cout << m1 << " AND " << m1 << " :" << out4 << endl;

    std::cout << "================test OR================" << std::endl;
    result1 = rgswfunc.EvalGateBootstrap(bsk, keysw, OR, cipher1, cipher1,
                                         lwe_function, lweparams, rlweparams);
    result2 = rgswfunc.EvalGateBootstrap(bsk, keysw, OR, cipher1, cipher2,
                                         lwe_function, lweparams, rlweparams);
    result3 = rgswfunc.EvalGateBootstrap(bsk, keysw, OR, cipher2, cipher1,
                                         lwe_function, lweparams, rlweparams);
    result4 = rgswfunc.EvalGateBootstrap(bsk, keysw, OR, cipher2, cipher2,
                                         lwe_function, lweparams, rlweparams);

    out1 = lwe_function.LweDecrypt(result1, sk_n, lweparams);
    out2 = lwe_function.LweDecrypt(result2, sk_n, lweparams);
    out3 = lwe_function.LweDecrypt(result3, sk_n, lweparams);
    out4 = lwe_function.LweDecrypt(result4, sk_n, lweparams);

    cout << m0 << " OR " << m0 << " :" << out1 << endl;
    cout << m0 << " OR " << m1 << " :" << out2 << endl;
    cout << m1 << " OR " << m0 << " :" << out3 << endl;
    cout << m1 << " OR " << m1 << " :" << out4 << endl;

    std::cout << "================test NOR================" << std::endl;
    result1 = rgswfunc.EvalGateBootstrap(bsk, keysw, NOR, cipher1, cipher1,
                                         lwe_function, lweparams, rlweparams);
    result2 = rgswfunc.EvalGateBootstrap(bsk, keysw, NOR, cipher1, cipher2,
                                         lwe_function, lweparams, rlweparams);
    result3 = rgswfunc.EvalGateBootstrap(bsk, keysw, NOR, cipher2, cipher1,
                                         lwe_function, lweparams, rlweparams);
    result4 = rgswfunc.EvalGateBootstrap(bsk, keysw, NOR, cipher2, cipher2,
                                         lwe_function, lweparams, rlweparams);

    out1 = lwe_function.LweDecrypt(result1, sk_n, lweparams);
    out2 = lwe_function.LweDecrypt(result2, sk_n, lweparams);
    out3 = lwe_function.LweDecrypt(result3, sk_n, lweparams);
    out4 = lwe_function.LweDecrypt(result4, sk_n, lweparams);

    cout << m0 << " NOR " << m0 << " :" << out1 << endl;
    cout << m0 << " NOR " << m1 << " :" << out2 << endl;
    cout << m1 << " NOR " << m0 << " :" << out3 << endl;
    cout << m1 << " NOR " << m1 << " :" << out4 << endl;

    std::cout << "================test XOR================" << std::endl;
    result1 = rgswfunc.EvalGateBootstrap(bsk, keysw, XOR, cipher1, cipher1,
                                         lwe_function, lweparams, rlweparams);
    result2 = rgswfunc.EvalGateBootstrap(bsk, keysw, XOR, cipher1, cipher2,
                                         lwe_function, lweparams, rlweparams);
    result3 = rgswfunc.EvalGateBootstrap(bsk, keysw, XOR, cipher2, cipher1,
                                         lwe_function, lweparams, rlweparams);
    result4 = rgswfunc.EvalGateBootstrap(bsk, keysw, XOR, cipher2, cipher2,
                                         lwe_function, lweparams, rlweparams);

    out1 = lwe_function.LweDecrypt(result1, sk_n, lweparams);
    out2 = lwe_function.LweDecrypt(result2, sk_n, lweparams);
    out3 = lwe_function.LweDecrypt(result3, sk_n, lweparams);
    out4 = lwe_function.LweDecrypt(result4, sk_n, lweparams);

    cout << m0 << " XOR " << m0 << " :" << out1 << endl;
    cout << m0 << " XOR " << m1 << " :" << out2 << endl;
    cout << m1 << " XOR " << m0 << " :" << out3 << endl;
    cout << m1 << " XOR " << m1 << " :" << out4 << endl;
}

int main()
{
    // test_Lwe_encrypt();

    // test_KeySwitch();

    // testModSwitch();
     
    cout <<"==============测试Identity自举================"<<endl;
    // 测试Identity自举
    test_Bootstrapping();
    cout <<"=================测试门自举===================="<<endl;
    test_gateBoot();

    return 0;
}