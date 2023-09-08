/*
 * @Author: LiZhiHao
 * @Date: 2022-04-28 09:21:47
 * @LastEditTime: 2022-06-11 22:24:40
 * @Description:
 *
 * Copyright (c) 2022 by LLW, All Rights Reserved.
 */

// RLwe参数类

#include "rlwefunction.h"

// 利用Lwe_N的密钥 产生RLWE密钥 NTT形式
NativePoly RLweFunction::RLweTerKeyGen(const RLweParams &params, LweSecretKey &skN)
{
    //根据向量产生多项式密钥
    NativePoly skNPoly = NativePoly(params.GetPolyParams());
    skNPoly.SetValues(skN.GetLweSecretKey(), Format::COEFFICIENT);
    skNPoly.SetFormat(Format::EVALUATION);
    return skNPoly;
}

// RLWE密文的分解
void RLweFunction::RLWEDecompose(RLweCipher &sample, vector<NativePoly> &output, const RLweParams &rlweparams)
{
    usint N = rlweparams.GetN();
    usint baseG = rlweparams.GetBaseG();
    usint digitsG = rlweparams.GetDigitsG();
    NativePoly ct_0 = sample.GetRLweCipher_a();
    NativePoly ct_1 = sample.GetRLweCipher_b();
    // assume baseG is a power of 2
    usint bs_1 = baseG - 1;
    usint shift = log2(baseG);

    for (usint i = 0; i < digitsG; i++) //分解的长度
    {
        for (usint j = 0; j < N; j++) // 对每个系数处理
        {
            output[i][j] = NativeInteger(ct_0[j].ConvertToInt() & bs_1);
            output[i + digitsG][j] = NativeInteger(ct_1[j].ConvertToInt() & bs_1);
            ct_0[j] >>= shift; //依次除掉baseG
            ct_1[j] >>= shift;
        }
    }

    //转成NTT形式
    for (int i = 0; i < 2 * digitsG; i++)
    {
        output[i].SetFormat(EVALUATION);
    }
}

//提取常数项的lwe密文
LweCipher RLweFunction::SampleExtract(const RLweParams &rlweparams, RLweCipher &sample, bool flag)
{

    NativeInteger Q = rlweparams.GetQ();
    NativeInteger Q8 = Q / NativeInteger(8) + 1; // Q/8
    usint N = rlweparams.GetN();
    NativeInteger bNew = sample.GetRLweCipher_b()[0];
    if(flag == 1)
    {
        bNew = Q8.ModAddFast(bNew, Q);
    }

    NativeVector aNew(N, Q);
    aNew[0] = sample.GetRLweCipher_a()[0];
    for (usint j = 1; j < N; j++)
    {
        NativeInteger val = sample.GetRLweCipher_a()[N - j];
        aNew[j] = Q.ModSub(val, Q);
    }
    return LweCipher(aNew, bNew); //需要密钥切换和模切换
}