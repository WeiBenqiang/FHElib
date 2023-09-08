/*
 * @Author: LiZhiHao
 * @Date: 2022-04-28 09:21:47
 * @LastEditTime: 2022-06-12 16:02:39
 * @Description: rlwe密文
 *
 * Copyright (c) 2022 by LLW, All Rights Reserved.
 */

#ifndef RLWE_H
#define RLWE_H

#include "lwe.h"
#include "math/ternaryuniformgenerator.h"
#include "lattice/poly.h"
#include "lattice/backend.h"
#include "utils/inttypes.h"
#include "math/discreteuniformgenerator.h"

using namespace lbcrypto;

class RLweParams
{
private:
    // RLwe明文空间
    usint m_t;

    usint m_n;
    // RLwe维度
    usint m_N;
    //数字分解的基
    usint m_BaseG;
    //对应分解的个数
    uint32_t m_digitsG;
    // G^pows
    vector<NativeInteger> m_Gpower;

    //gate 参数
    vector<NativeInteger> m_gateConst;
    // lwe 模数
    NativeInteger m_q;
    // RLwe密文空间
    NativeInteger m_Q;
    // Error distribution generator
    DiscreteGaussianGeneratorImpl<NativeVector> m_dgg;
    // 多项式的参数
    shared_ptr<ILNativeParams> polyParams;

    
public:
    RLweParams(/* args */){}

    //带参数构造
    RLweParams(const LweParams& lweparams, const usint &BaseG);

    const DiscreteGaussianGeneratorImpl<NativeVector> &GetDgg() const;

    //返回RLweParams的t
    const usint &Gett() const;

    const usint &Getn() const;

    //返回RLweParams的Rlwe维度
    const usint &GetN() const;

    //返回RLwe分解的基
    const usint &GetBaseG() const;

    //返回分解的长度
    const usint &GetDigitsG() const;

    const NativeInteger &Getq() const;

    //返回RLweParams的密文空间
    const NativeInteger &GetQ() const;

    const vector<NativeInteger>& GetGPower() const;

    const vector<NativeInteger>& GetGateConst() const;

    const shared_ptr<ILNativeParams>& GetPolyParams() const;

    //重载=
    const RLweParams &operator=(const RLweParams &another);
    
    void PreCompute();

    ~RLweParams(){}
};

// LweCipher密文类的定义
class RLweCipher
{
private:
    NativePoly m_a;
    NativePoly m_b; // b=as+m+e

public:
    RLweCipher() {}
    //带参数构造
    RLweCipher(const NativePoly &a, const NativePoly &b)
    {
        this->m_a = a;
        this->m_b = b;
    }

    //拷贝构造函数
    RLweCipher(const RLweCipher &another)
    {
        this->m_a = another.m_a;
        this->m_b = another.m_b;
    }

    //获取RLweCipher的a
    NativePoly& GetRLweCipher_a()
    {
        return m_a;
    }

    //获取RLweCipher的b
    NativePoly& GetRLweCipher_b()
    {
        return m_b;
    }

    void SetRLweCipher(const NativePoly &aa, const NativePoly &bb)
    {
        this->m_a = aa;
        this->m_b = bb;
    }

    //重载=
    const RLweCipher &operator=(const RLweCipher &another)
    {
        this->m_a = another.m_a;
        this->m_b = another.m_b;
        return *this;
    }

    //设置 RLWE的表示形式，即设个每个多项式的表示形式： 系数 vs NTT
    void SetFormat(const Format format)
    {  
        m_a.SetFormat(format);
        m_b.SetFormat(format);            
    }

    ~RLweCipher(){}
};

class RLweSecretKey
{
private:
    NativePoly sk_N;

public:
    // 带参构造
    RLweSecretKey(const NativePoly &sk)
    {
        this->sk_N = sk;
    }

    //拷贝构造
    RLweSecretKey(const RLweSecretKey &another)
    {
        this->sk_N = another.sk_N;
    }

    //获取sk_N
    const NativePoly &GetRLweSecretKey() const
    {
        return sk_N;
    }

    ~RLweSecretKey(){}
};

#endif
