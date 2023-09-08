/*
 * @Author: LiZhiHao
 * @Date: 2022-04-28 09:21:47
 * @LastEditTime: 2022-06-11 22:24:03
 * @Description: rlwe的函数
 *
 * Copyright (c) 2022 by LLW, All Rights Reserved.
 */

// RLwe参数类
#ifndef RLWEPARAMS_H
#define RLWEPARAMS_H

#include "rlwe.h"
#include "math/backend.h"
#include "math/discretegaussiangenerator.h"

using namespace std;
using namespace lbcrypto;

class RLweFunction
{

public:
    RLweFunction(/* args */){}

    // 利用Lwe_N的密钥 产生RLWE密钥 NTT形式
    NativePoly RLweTerKeyGen(const RLweParams &params, LweSecretKey &skN);

    // 比特分解函数
    void RLWEDecompose(RLweCipher &sample, vector<NativePoly> &output, const RLweParams &rlweparams);

    //提取常数项的lwe密文
    LweCipher SampleExtract(const RLweParams &rlweparams, RLweCipher &sample, bool flag);

    ~RLweFunction() {}
};

#endif
