/*
 * @Author: WeiBeniang
 * @Date: 2022-06-01 20:35:50
 * @LastEditTime: 2022-06-19 16:46:13
 * @Description:
 *
 * Copyright (c) 2022 by LLW, All Rights Reserved.
 */

#include "bootstrap.h"

//版本1：使用X^{ai}-1的NTT形式
//该函数在这里只是根据ct.a来计算出来， 还需要X^-ai的，所以应该预计算所有的
void RGSWFunction::init(const RLweParams &rlweparams, vector<NativePoly> &xa, vector<NativePoly> &neg_xa, const LweCipher &ct)
{
    //初始化测试多项式和x^a-1
    NativeInteger Q = rlweparams.GetQ();
    int n = ct.GetLweCipher_a().GetLength(); //获取lwe的维度
    usint N = rlweparams.GetN();
    shared_ptr<ILNativeParams> polyParams = rlweparams.GetPolyParams(); //多项式参数
    for (int i = 0; i < n; i++)
    {
        int ai = ct.GetLweCipher_a()[i].ConvertToInt(); // q=2N
        xa[i] = NativePoly(polyParams, Format::COEFFICIENT, true);
        if (ai < N)
        {
            xa[i][ai] = 1;
        }
        else
        {
            // X^{ai} = X^{ai-N+N} = -X^{ai-N}
            xa[i][ai - N] = Q.ModSub(1, Q);
        }
        // X^ai     ai >N  x^ai  =
        // 常数项为-1;
        xa[i][0] = Q.ModSub(1, Q);
        xa[i].SetFormat(Format::EVALUATION); //转成NTT形式

        // X^{-ai}-1 = -X^{N-ai}-1  0<ai<N
        //  X^{2N-ai}-1  N<=ai<2N
        neg_xa[i] = NativePoly(polyParams, Format::COEFFICIENT, true);
        if (ai < N)
        {
            neg_xa[i][N - ai] = Q.ModSub(1, Q);
        }
        else
        {
            neg_xa[i][2 * N - ai] = 1;
        }
        // X^ai
        // 常数项为-1;
        neg_xa[i][0] = Q.ModSub(1, Q);
        neg_xa[i].SetFormat(Format::EVALUATION); //转成NTT形式
    }
}

// RGSW的加密函数  只加密1比特消息，对应rlwe的密钥  一堆0的密文+ mG,  m={-1,0,1}
RGSWCipher RGSWFunction::RGSWEncrypt(const int &m, const NativePoly &skNTT, RLweParams &rlweparams)
{
    NativeInteger Q = rlweparams.GetQ();
    usint N = rlweparams.GetN();
    usint digitsG = rlweparams.GetDigitsG();
    usint digitsG2 = 2 * digitsG;

    // std::cout << "digits:" << digitsG<<endl;  //3
    //生成是需要是NTT形式
    shared_ptr<ILNativeParams> polyParams = rlweparams.GetPolyParams(); //多项式参数

    // RGSWCipher CT = RGSWCipher(digitsG2, 2);  //新建一个对象 2l*2
    vector<vector<NativePoly>> CT(digitsG2, vector<NativePoly>(2)); //大小的确定 (digitsG2, 2)

    DiscreteUniformGeneratorImpl<NativeVector> dug; //均匀分布发生器
    dug.SetModulus(Q);

    // tempA is introduced to minimize the number of NTTs
    vector<NativePoly> tempA(digitsG2); //定义 2*l 个a(x)

    for (uint32_t i = 0; i < digitsG2; ++i)
    {
        // 均匀分布的 a[i], 系数表示，能否直接是NTT形式
        CT[i][0] = NativePoly(dug, polyParams, Format::COEFFICIENT);
        tempA[i] = CT[i][0];
        // error e
        CT[i][1] = NativePoly(rlweparams.GetDgg(), polyParams, Format::COEFFICIENT);
    }
#if 0
        // FHEW形式的gadget矩阵
         for (uint32_t i = 0; i < digitsG; ++i) {
             if (m > 0) {
             // Add G Multiple
             (*result)[2 * i][0][mm].ModAddEq(rlweparams.GetGPower()[i], Q);
             // [a,as+e] + X^m*G
             (*result)[2 * i + 1][1][mm].ModAddEq(rlweparams.GetGPower()[i], Q);
             } else {
             // Subtract G Multiple
             (*result)[2 * i][0][mm].ModSubEq(rlweparams.GetGPower()[i], Q);
             // [a,as+e] - X^m*G
             (*result)[2 * i + 1][1][mm].ModSubEq(rlweparams.GetGPower()[i], Q);
             }
         }
#endif

    // TFHE形式的gadget矩阵, m= {-1,0,1}
    for (uint32_t i = 0; i < digitsG; ++i)
    {
        if (m > 0) //对应s=1
        {
            // a(x)的常数项+Gpower[i]
            CT[i][0][0].ModAddEq(rlweparams.GetGPower()[i], Q);
            // e(x)的常数项 + Gpowe[i]
            CT[digitsG + i][1][0].ModAddEq(rlweparams.GetGPower()[i], Q);
        }
        else if (m == -1) // s=-1的情况，应该用不到
        {
            // Subtract G Multiple
            CT[i][0][0].ModSubEq(rlweparams.GetGPower()[i], Q);
            // [a,as+e] - X^m*G
            CT[digitsG + i][1][0].ModSubEq(rlweparams.GetGPower()[i], Q);
        }
    }

    // e(x)+a(x)*s(x)
    for (uint32_t i = 0; i < digitsG2; ++i)
    {
        CT[i][0].SetFormat(Format::EVALUATION); // NTT
        tempA[i].SetFormat(Format::EVALUATION); // NTT
        CT[i][1].SetFormat(Format::EVALUATION); // NTT

        CT[i][1] += tempA[i] * skNTT;
    }
    return RGSWCipher(CT); //返回的是NTT类型
}

//无需rgsw的解密

//生成自举密钥， 用RGSW加密基础方案lwe私钥的每个部分{-1,0,1}三种可能，n维，每个被加密为两个RGSWCipher
Bootstrapkey RGSWFunction::BootstrapkeyGen(LweSecretKey &lwesk, const NativePoly &skNTT, RLweParams &rlweparams)
{
    int n = rlweparams.Getn();
    vector<vector<RGSWCipher>> bsk(n, vector<RGSWCipher>(2)); //大小：n*2

    uint64_t q = rlweparams.Getq().ConvertToInt();

    int64_t qHalf = (q >> 1);
    for (int i = 0; i < n; i++)
    {
        int si = lwesk.GetLweSecretKey()[i].ConvertToInt();
        if (si > qHalf)
            si -= q;

        //对lwesk进行分离 = {1,0,-1}
        switch (si)
        {
        case 1: // 1->(1,0)
            bsk[i][0] = RGSWEncrypt(1, skNTT, rlweparams);
            bsk[i][1] = RGSWEncrypt(0, skNTT, rlweparams);
            break;
        case 0: // 0->(0,0)
            bsk[i][0] = RGSWEncrypt(0, skNTT, rlweparams);
            bsk[i][1] = RGSWEncrypt(0, skNTT, rlweparams);
            break;
        case -1: //-1 ->(0,1)
            bsk[i][0] = RGSWEncrypt(0, skNTT, rlweparams);
            bsk[i][1] = RGSWEncrypt(1, skNTT, rlweparams);
            break;
        default:
            // error
            break;
        }
    }

    return Bootstrapkey(bsk);
}
// result= X^{a}*source
void RGSWFunction::PolynomialMulByXai(NativePoly &out, const int &a, const NativePoly &in, const RLweParams &rlweparams)
{
    const int N = rlweparams.GetN();
    const NativeInteger Q = rlweparams.GetQ();
    assert(a >= 0 && a < 2 * N);
    //根据a的值来旋转系数
    if (a < N)
    {
        for (int i = 0; i < a; i++) // in的后a个系数提前，并变负
            out[i] = Q.ModSub(in[i - a + N], Q);

        for (int i = a; i < N; i++) // in的前n-a个系数后移a
            out[i] = in[i - a];
    }
    else
    {
        const int aa = a - N;
        for (int i = 0; i < aa; i++)
            out[i] = in[i - aa + N];
        for (int i = aa; i < N; i++)
            out[i] = Q.ModSub(in[i - aa], Q);
    }
}

// poly*(X^a - 1)
void RGSWFunction::PolynomialMulByXaiminuxone(NativePoly &out, int a, const RLweParams &rlweparams)
{
    const int N = rlweparams.GetN();
    assert(a >= 0 && a < 2 * N);
    const NativePoly in = out;
    // X^{a}*acc  //利用系数旋转
    PolynomialMulByXai(out, a, in, rlweparams);
    // -acc  //系数的减法
    out -= in;
}

// RGSW* RLWE = RLWE
RLweCipher RGSWFunction::ExternMult(const vector<vector<NativePoly>> &CT, vector<NativePoly> &dct, const RLweParams &rlweparams)
{

    shared_ptr<ILNativeParams> polyParams = rlweparams.GetPolyParams();
    int digitsG2 = 2 * rlweparams.GetDigitsG();

    usint N = rlweparams.GetN();

    NativePoly ax = NativePoly(polyParams, Format::EVALUATION, true);
    NativePoly bx = NativePoly(polyParams, Format::EVALUATION, true);

    //向量*矩阵
    for (int j = 0; j < digitsG2; j++)
    {
        ax += dct[j] * CT[j][0];
        bx += dct[j] * CT[j][1];
    }
    return RLweCipher(ax, bx);
}

// 外部乘法+ *(X^{a}-1)
RLweCipher RGSWFunction::ExternMultByXaiMinusOne(const RGSWCipher &CT, vector<NativePoly> &dct, int a, const RLweParams &rlweparams)
{

    shared_ptr<ILNativeParams> polyParams = rlweparams.GetPolyParams();
    int digitsG2 = 2 * rlweparams.GetDigitsG();

    usint N = rlweparams.GetN();

    NativePoly ax = NativePoly(polyParams, Format::EVALUATION, true);
    NativePoly bx = NativePoly(polyParams, Format::EVALUATION, true);

    //向量*矩阵 = RLWE密文
    for (int j = 0; j < digitsG2; j++)
    {
        ax += dct[j] * (CT.GetElements()[j][0]);
        bx += dct[j] * (CT.GetElements()[j][1]);
    }
    //转为系数表示
    ax.SetFormat(Format::COEFFICIENT);
    bx.SetFormat(Format::COEFFICIENT);

    //分别乘以 (X^{a}-1)
    PolynomialMulByXaiminuxone(ax, a, rlweparams);
    PolynomialMulByXaiminuxone(bx, a, rlweparams);

    return RLweCipher(ax, bx);
}

//版本2: acc * (X^ai-1) 系数表示实现： acc*X^{ai} - acc
void RGSWFunction::BlindRotation(RLweCipher &acc, const Bootstrapkey &bsk, int *a_2N, uint &n, const RLweParams &rlweparams, RLweFunction &f)
{

    NativeInteger Q = rlweparams.GetQ();
    shared_ptr<ILNativeParams> polyParams = rlweparams.GetPolyParams();
    usint N = rlweparams.GetN();
    usint m = 2 * N; // cycltomic order
    usint digitsG2 = rlweparams.GetDigitsG() * 2;

    std::vector<NativePoly> dct(digitsG2);
    // initialize dct to zeros

    for (int i = 0; i < n; i++)
    {
        // // initialize dct to zeros
        for (uint32_t i = 0; i < digitsG2; i++)
            dct[i] = NativePoly(polyParams, Format::COEFFICIENT, true);

        if (a_2N[i] == 0)
        {
            continue;
        }
        // acc + acc*bsk_0*{X^a-1} + acc*bsk_1*{x^{-a}-1}
        // 系数分解acc后，转为NTT形式
        f.RLWEDecompose(acc, dct, rlweparams); //系数表示下的分解

        // RLweCipher temp1; // temp1 = acc^{X^a-1}
        // 外部乘法1: 先做temp1 = dct* bsk_0  出来转系数表示, 再*(X^{ai}-1)
        RLweCipher temp1 = ExternMultByXaiMinusOne(bsk.getBoostrapkey()[i][0], dct, a_2N[i], rlweparams);
        acc.SetRLweCipher(acc.GetRLweCipher_a() + temp1.GetRLweCipher_a(), acc.GetRLweCipher_b() + temp1.GetRLweCipher_b());

        //外部乘法2: temp1 = dct* bsk_1  出来转系数表示, 再*(X^{-ai}-1)
        RLweCipher temp2 = ExternMultByXaiMinusOne(bsk.getBoostrapkey()[i][1], dct, m - a_2N[i], rlweparams);
        acc.SetRLweCipher(acc.GetRLweCipher_a() + temp2.GetRLweCipher_a(), acc.GetRLweCipher_b() + temp2.GetRLweCipher_b());

        //系数表示进入下一轮
    }
}

//一个外部乘法 (acc * (X^ai-1)) x (bsk_0-bsk_1 X^{-ai}) + acc
void RGSWFunction::BlindRotation1(RLweCipher &acc, const Bootstrapkey &bsk, int *a_2N, uint &n, const RLweParams &rlweparams, RLweFunction &f)
{

    NativeInteger Q = rlweparams.GetQ();
    shared_ptr<ILNativeParams> polyParams = rlweparams.GetPolyParams();
    usint N = rlweparams.GetN();
    usint m = 2 * N; // cycltomic order
    usint digitsG2 = rlweparams.GetDigitsG() * 2;

    std::vector<NativePoly> dct(digitsG2);
    // initialize dct to zeros

    for (int i = 0; i < n; i++)
    {
        // // initialize dct to zeros
        for (uint32_t i = 0; i < digitsG2; i++)
            dct[i] = NativePoly(polyParams, Format::COEFFICIENT, true);

        if (a_2N[i] == 0)
        {
            continue;
        }

        // acc * (X^ai-1)
        RLweCipher temp1 = acc;

        PolynomialMulByXaiminuxone(temp1.GetRLweCipher_a(), a_2N[i], rlweparams);
        PolynomialMulByXaiminuxone(temp1.GetRLweCipher_b(), a_2N[i], rlweparams);

        //分解
        f.RLWEDecompose(temp1, dct, rlweparams); //系数表示下的分解

        // (bsk_0- bsk_1* X^{-ai})
        // X^{-ai}的NTT
        NativePoly neg_xa = NativePoly(polyParams, Format::COEFFICIENT, true);
        if (a_2N[i] < N)
        {
            neg_xa[N - a_2N[i]] = Q.ModSub(1, Q);
        }
        else
        {
            neg_xa[2 * N - a_2N[i]] = 1;
        }

        neg_xa.SetFormat(Format::EVALUATION); //转成NTT形式

        // (bsk_0- bsk_1* X^{-ai}
        vector<vector<NativePoly>> temp(digitsG2, vector<NativePoly>(2));
        for (int j = 0; j < digitsG2; j++)
        {
            for (int k = 0; k < 2; k++)
            {
                temp[j][k] = NativePoly(polyParams, Format::EVALUATION, true);
                NativePoly temp2 = bsk.getBoostrapkey()[i][1].GetElements()[j][k] * neg_xa;
                temp[j][k] = bsk.getBoostrapkey()[i][0].GetElements()[j][k] - temp2;
            }
        }
        
        RLweCipher temp2 = ExternMult(temp, dct, rlweparams);
        temp2.SetFormat(COEFFICIENT); //系数
        // (acc * (X^ai-1)) x (bsk_0-bsk_1 X^{-ai}) + acc 系数表示
        acc.SetRLweCipher(acc.GetRLweCipher_a() + temp2.GetRLweCipher_a(), acc.GetRLweCipher_b() + temp2.GetRLweCipher_b());

        //系数表示进入下一轮
    }
}

// 版本1: 预计算所有的X^{ai}-1的NTT形式，使用ai来查表
void RGSWFunction::BlindRotationLi(RLweCipher &acc, const Bootstrapkey &bsk,
                                   vector<NativePoly> xa, vector<NativePoly> neg_xa,
                                   const RLweParams &rlweparams, RLweFunction &f)
{

    NativeInteger Q = rlweparams.GetQ();
    shared_ptr<ILNativeParams> polyParams = rlweparams.GetPolyParams();
    usint N = rlweparams.GetN();
    usint n = rlweparams.Getn();
    usint digitsG2 = rlweparams.GetDigitsG() * 2;

    //分解RLwe密文
    vector<NativePoly> dct(digitsG2); //长度是2*l

    for (uint32_t i = 0; i < n; i++)
    {
        for (uint32_t i = 0; i < digitsG2; i++)
        {
            dct[i] = NativePoly(polyParams, Format::COEFFICIENT, true);
        }

        // acc.SetFormat(COEFFICIENT);
        f.RLWEDecompose(acc, dct, rlweparams); //分解完dct是NTT形式

        // acc + acc*bsk_0*{X^a-1} + acc*bsk_1*{x^{-a}-1}
        // acc_i*bsk_0,i ntt
        RLweCipher temp1 = ExternMult(bsk.getBoostrapkey()[i][0].GetElements(), dct, rlweparams);
        // temp1*{X^a-1} ntt
        temp1.SetRLweCipher(temp1.GetRLweCipher_a() * xa[i], temp1.GetRLweCipher_b() * xa[i]);
        temp1.SetFormat(COEFFICIENT); //系数

        acc.SetRLweCipher(acc.GetRLweCipher_a() + temp1.GetRLweCipher_a(), acc.GetRLweCipher_b() + temp1.GetRLweCipher_b());

        // acc_i*bsk_1,i ntt
        RLweCipher temp2 = ExternMult(bsk.getBoostrapkey()[i][1].GetElements(), dct, rlweparams);
        // temp2*{x^{-a}-1} ntt
        temp2.SetRLweCipher(temp2.GetRLweCipher_a() * neg_xa[i], temp2.GetRLweCipher_b() * neg_xa[i]);
        temp2.SetFormat(COEFFICIENT); //系数

        acc.SetRLweCipher(acc.GetRLweCipher_a() + temp2.GetRLweCipher_a(),
                          acc.GetRLweCipher_b() + temp2.GetRLweCipher_b());
    }
}

LweCipher RGSWFunction::Bootstrap(const Bootstrapkey &bsk, LweCipher &ct, const RLweParams &rlweparams)
{
    NativeInteger q = rlweparams.Getq();
    NativeInteger Q = rlweparams.GetQ();
    uint n = rlweparams.Getn();
    uint N = rlweparams.GetN();
    const shared_ptr<ILNativeParams> polyParams = rlweparams.GetPolyParams();

    NativeInteger Q4 = Q / NativeInteger(4);
    // uint32_t qHalf = q.ConvertToInt() >> 1;

    // Since q | (2*N), we deal with a sparse embedding of Z_Q[x]/(X^{q/2}+1) to
    // Z_Q[x]/(X^N+1)
    uint32_t factor = (2 * N / q.ConvertToInt());

    NativeVector a(n, q);
    NativeInteger b;

    RLweFunction f;

    a = ct.GetLweCipher_a();
    b = ct.GetLweCipher_b().ModAddFast(q >> 3, q); // b = b+ q/8

    //切换模数 ai和 b mod 2N
    int a_2N[n];
    for (int i = 0; i < n; i++)
    {
        a_2N[i] = a[i].ConvertToInt() * factor;
    }
    int b_2N = b.ConvertToInt() * factor; // 2N /q

    // 测试多项式
    NativePoly testPoly = NativePoly(polyParams, Format::COEFFICIENT, true);
    // 初始化系数
    for (int i = 0; i < (q >> 1); i++)
    {
        if (i < (q >> 2))
        {
            testPoly[i * factor] = 0;
        }
        else
        {
            testPoly[i * factor] = Q4;
        }
    }

    NativePoly testPolyMulXb = NativePoly(polyParams, Format::COEFFICIENT, true);
    // X^{-b_2N} *testPoly
    PolynomialMulByXai(testPolyMulXb, 2 * N - b_2N, testPoly, rlweparams);

    NativePoly zeroPoly = NativePoly(polyParams, Format::COEFFICIENT, true);

    RLweCipher acc(zeroPoly, testPolyMulXb); //系数表示

    // //利用盲旋转累加
    BlindRotation(acc, bsk, a_2N, n, rlweparams, f);
    //盲选旋转的acc是系数表示

    //样本提取 modQ
    LweCipher cipherQ = f.SampleExtract(rlweparams, acc, 0);

    return cipherQ;
}

LweCipher RGSWFunction::BootstrapLi(const Bootstrapkey &bsk, const LweCipher &ct, const RLweParams &rlweparams)
{
    // NativeInteger q = params->GetLWEParams()->Getq();
    NativeInteger q = rlweparams.Getq();
    NativeInteger Q = rlweparams.GetQ();
    uint n = rlweparams.Getn();
    uint N = rlweparams.GetN();
    const shared_ptr<ILNativeParams> polyParams = rlweparams.GetPolyParams();

    NativeInteger Q4 = Q / NativeInteger(4);
    // uint32_t qHalf = q.ConvertToInt() >> 1;

    // Since q | (2*N), we deal with a sparse embedding of Z_Q[x]/(X^{q/2}+1) to
    // Z_Q[x]/(X^N+1)
    uint32_t factor = (2 * N / q.ConvertToInt());

    NativeVector a(n, q);
    NativeInteger b;

    RLweFunction f;

    a = ct.GetLweCipher_a();
    b = ct.GetLweCipher_b().ModAddFast(q >> 3, q); // b = b+ q/8

    //切换模数 ai和 b mod 2N
    int a_2N[n];
    for (int i = 0; i < n; i++)
    {
        a_2N[i] = a[i].ConvertToInt() * factor;
    }
    int b_2N = b.ConvertToInt() * factor; // 2N /q =2

    // 测试多项式
    NativePoly testPoly = NativePoly(polyParams, Format::COEFFICIENT, true);
    // 初始化系数
    for (int i = 0; i < N; i++)
    {
        if (i < N / 2)
        {
            testPoly[i] = 0;
        }
        else
        {
            testPoly[i] = Q4;
        }
    }
    NativePoly testPolyMulXb = NativePoly(polyParams, Format::COEFFICIENT, true);
    // X^{-b_2N} *testPoly
    PolynomialMulByXai(testPolyMulXb, 2 * N - b_2N, testPoly, rlweparams);

    NativePoly zeroPoly = NativePoly(polyParams, Format::COEFFICIENT, true);

    RLweCipher acc(zeroPoly, testPolyMulXb); //系数表示
    //(0,X^{-b_2N} *testPoly)

    vector<NativePoly> xa(n);
    vector<NativePoly> neg_xa(n);
    init(rlweparams, xa, neg_xa, ct);
    BlindRotationLi(acc, bsk, xa, neg_xa, rlweparams, f);

    //样本提取 modQ
    LweCipher cipherQ = f.SampleExtract(rlweparams, acc, 0);

    return cipherQ;
}

LweCipher RGSWFunction::EvalGateBootstrap(const Bootstrapkey &bsk, const LweSwitchingKey &keysw, const BINGATE gate, LweCipher &ct1, LweCipher &ct2,
                                    LweFunction &lwe_function, const LweParams &lweparams, const RLweParams &rlweparams)
{
    NativeInteger q = rlweparams.Getq();
    NativeInteger Q = rlweparams.GetQ();
    uint n = rlweparams.Getn();
    uint N = rlweparams.GetN();
    const shared_ptr<ILNativeParams> polyParams = rlweparams.GetPolyParams();

    NativeInteger Q8 = Q / NativeInteger(8) + 1; // Q/8
    NativeInteger Q8Neg = Q.ModSub(Q8, Q);       //-Q / 8

    // Since q | (2*N), we deal with a sparse embedding of Z_Q[x]/(X^{q/2}+1) to
    // Z_Q[x]/(X^N+1)
    uint32_t factor = (2 * N / q.ConvertToInt());
    NativeVector a(n, q);
    NativeInteger b;

    RLweFunction f;

    // the additive homomorphic operation for XOR/NXOR is different from the
    // other gates we compute 2*(ct1 - ct2) mod 4 for XOR, me map 1,2 -> 1 and
    // 3,0 -> 0
    if ((gate == XOR))
    {
        a = ct1.GetLweCipher_a() + ct2.GetLweCipher_a();
        a += a;
        b = ct1.GetLweCipher_b().ModAddFast(ct2.GetLweCipher_b(), q);
        b.ModAddFastEq(b, q);
    }
    else
    {
        // for all other gates, we simply compute (ct1 + ct2) mod 4
        // for AND: 0,1 -> 0 and 2,3 -> 1
        // for OR: 1,2 -> 1 and 3,0 -> 0
        a = ct1.GetLweCipher_a() + ct2.GetLweCipher_a();
        b = ct1.GetLweCipher_b().ModAddFast(ct2.GetLweCipher_b(), q).ModAddFast(rlweparams.GetGateConst()[static_cast<int>(gate)], q);
    }

    // for all other gates, we simply compute (ct1 + ct2) mod 4
    // for AND: 0,1 -> 0 and 2,3 -> 1
    // for OR: 1,2 -> 1 and 3,0 -> 0

    //切换模数 ai和 b mod 2N
    int a_2N[n];
    for (int i = 0; i < n; i++)
    {
        a_2N[i] = a[i].ConvertToInt() * factor;
    }
    int b_2N = b.ConvertToInt() * factor; // 2N /q

    // 测试多项式
    NativePoly testPoly = NativePoly(polyParams, Format::COEFFICIENT, true);
    // 初始化系数
    for (int i = 0; i < (q >> 1); i++)
    {
        if (i < (q >> 2))
        {
            testPoly[i * factor] = Q8Neg;
        }
        else
        {
            testPoly[i * factor] = Q8;
        }
    }

    NativePoly testPolyMulXb = NativePoly(polyParams, Format::COEFFICIENT, true);
    // X^{-b_2N} *testPoly
    PolynomialMulByXai(testPolyMulXb, 2 * N - b_2N, testPoly, rlweparams);

    NativePoly zeroPoly = NativePoly(polyParams, Format::COEFFICIENT, true);

    RLweCipher acc(zeroPoly, testPolyMulXb); //系数表示

    //利用盲旋转累加
    BlindRotation(acc, bsk, a_2N, n, rlweparams, f);

    //盲选旋转的acc是系数表示

    //样本提取 +Q8 ?
    LweCipher cipherQN = f.SampleExtract(rlweparams, acc, 1);
    // keyswitch
    LweCipher cipherQn = lwe_function.LweKeySwitchingV1(cipherQN, keysw, lweparams);
    // //modSwitch
    LweCipher ctq_n = lwe_function.LweModSwitching(cipherQn, lweparams);

    return ctq_n;
}
