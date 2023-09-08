/*
 * @Author: WeiBenqiang 
 * @Date: 2022-05-24 15:15:19
 * @LastEditors: WeiBenqiang
 * @LastEditTime: 2022-06-12 22:41:35
 * @Description: 自举
 */
#ifndef BOOTSTRAP_H
#define BOOTSTRAP_H

#include "lwe.h"
#include "lwefunction.h"
#include "rlwefunction.h"
#include "rgsw.h"
#include "assert.h"

//门自举参数
enum BINGATE
{
    OR,
    AND,
    NOR,
    NAND,
    XOR
};

class RGSWFunction
{

public:
    RGSWFunction(/* args */) {}

    //版本1：使用X^{ai}-1的NTT形式
    //该函数在这里只是根据ct.a来计算出来， 还需要X^-ai的，所以应该预计算所有的
    void init(const RLweParams &rlweparams, vector<NativePoly> &xa, vector<NativePoly> &neg_xa, const LweCipher &ct);

    // RGSW的加密函数  只加密1比特消息，对应rlwe的密钥  一堆0的密文+ mG,  m={-1,0,1}
    RGSWCipher RGSWEncrypt(const int &m, const NativePoly &skNTT, RLweParams &rlweparams);

    //生成自举密钥， 用RGSW加密基础方案lwe私钥的每个部分{-1,0,1}三种可能，n维，每个被加密为两个RGSWCipher
    Bootstrapkey BootstrapkeyGen(LweSecretKey &lwesk, const NativePoly &skNTT, RLweParams &rlweparams);

    // result= X^{a}*source
    void PolynomialMulByXai(NativePoly &out, const int &a, const NativePoly &in, const RLweParams &rlweparams);

    // poly*(X^a - 1)
    void PolynomialMulByXaiminuxone(NativePoly &out, int a, const RLweParams &rlweparams);

    // RGSW* RLWE = RLWE
    RLweCipher ExternMult(const vector<vector<NativePoly>> &CT, vector<NativePoly> &dct, const RLweParams &rlweparams);

    // 外部乘法+ *(X^{a}-1)
    RLweCipher ExternMultByXaiMinusOne(const RGSWCipher &CT, vector<NativePoly> &dct, int a, const RLweParams &rlweparams);

    //版本2: acc * (X^ai-1) 系数表示实现： acc*X^{ai} - acc
    void BlindRotation(RLweCipher &acc, const Bootstrapkey &bsk, int *a_2N, uint &n, const RLweParams &rlweparams, RLweFunction &f);

    //使用一个外部乘法
    void BlindRotation1(RLweCipher &acc, const Bootstrapkey &bsk, int *a_2N, uint &n, const RLweParams &rlweparams, RLweFunction &f);
    
    // 版本1: 预计算所有的X^{ai}-1的NTT形式，使用ai来查表
    void BlindRotationLi(RLweCipher &acc, const Bootstrapkey &bsk,
                         vector<NativePoly> xa, vector<NativePoly> neg_xa, const RLweParams &rlweparams, RLweFunction &f);

    //版本2: acc * (X^ai-1) 系数表示实现： acc*X^{ai} - acc
    LweCipher Bootstrap(const Bootstrapkey &bsk, LweCipher &ct, const RLweParams &rlweparams);

    // 版本1: 预计算所有的X^{ai}-1的NTT形式，使用ai来查表
    LweCipher BootstrapLi(const Bootstrapkey &bsk, const LweCipher &ct, const RLweParams &rlweparams);

    LweCipher EvalGateBootstrap(const Bootstrapkey &bsk, const LweSwitchingKey &keysw, const BINGATE gate, LweCipher &ct1, LweCipher &ct2,
                          LweFunction &lwe_function, const LweParams &lweparams, const RLweParams &rlweparams);

    ~RGSWFunction() {}
};

#endif