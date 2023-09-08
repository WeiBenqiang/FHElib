/*
 * @Author: WeiBeniang
 * @Date: 2022-04-19 15:49:42
 * @LastEditTime: 2022-06-19 16:46:17
 * @Description: LWE的函数
 *
 * Copyright (c) 2022 by LLW, All Rights Reserved.
 */

#ifndef LWEFUNCTION_H
#define LWEFUNCTION_H

#include "lwe.h"
#include "math/backend.h"

using namespace lbcrypto;

typedef int64_t LwePlaintext;

class LweFunction
{
private:
    /* data */
public:
    LweFunction(/* args */) {}

    // LweSecretKey LweBinKeyGen(LweParams lweparams)
    // {
    //     BinaryUniformGeneratorImpl<NativeInteger> bug;
    //     return LweSecretKey(bug.GenerateVector(lweparams.Getn(), lweparams.Getq()));
    // }

    // 三值均匀分布的私钥产生
    LweSecretKey LweTerKeyGen_n(const LweParams &lweparams);

    LweSecretKey LweTerKeyGen_N(const LweParams &lweparams);


    //加密
    LweCipher LweEncrypt(LwePlaintext &m, const  LweSecretKey &sk, const LweParams &lweparams);

    // LWE的解密函数
    LwePlaintext LweDecrypt(const LweCipher &sample,const  LweSecretKey &sk,const  LweParams &lweparams);
  
    // LWE对0的加密
    void LweEncryptZero();

    //生成密文切换的密钥
    LweSwitchingKey LweSwitchingKeyGenV1(const LweSecretKey &oldkey,const  LweSecretKey &newkey, const  LweParams &lweparams);

    // LWE的密钥切换功能
    LweCipher LweKeySwitchingV1(const  LweCipher &oldcipher,const LweSwitchingKey &switchkey,const  LweParams &lweparams);

    //模切换
    LweCipher LweModSwitching(const  LweCipher &oldcipher,const  LweParams &lweparams);

    ~LweFunction(){}
};

#endif
