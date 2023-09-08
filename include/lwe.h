/*
 * @Author: WeiBeniang
 * @Date: 2022-04-18 19:24:17
 * @LastEditTime: 2022-06-11 22:37:21
 * @Description: LweCipher密文
 *
 * Copyright (c) 2022 by LLW, All Rights Reserved.
 */
#ifndef LWE_H
#define LWE_H
#include "math/ternaryuniformgenerator.h"
#include "math/binaryuniformgenerator.h"
#include "math/discreteuniformgenerator.h"
#include "math/discretegaussiangenerator.h"

using namespace lbcrypto;
using namespace std;
// LweCipher密文类的定义
class LweCipher
{
private:
    NativeVector m_a;
    NativeInteger m_b;

public:
    LweCipher(/* args */) {}

    //拷贝构造函数
    LweCipher(const LweCipher &another)
    {
        this->m_a = another.m_a;
        this->m_b = another.m_b;
    }

    //带参数构造
    LweCipher(const NativeVector &a, const NativeInteger &b)
    {
        this->m_a = a;
        this->m_b = b;
    }

    //获取LweCipher的a
    const NativeVector &GetLweCipher_a() const
    {
        return m_a;
    }

    //获取LweCipher的b
    const NativeInteger &GetLweCipher_b() const
    {
        return m_b;
    }

    //重载=
    const LweCipher &operator=(const LweCipher &another)
    {
        this->m_a = another.m_a;
        this->m_b = another.m_b;
        return *this;
    }

    ~LweCipher(){}
};

class LweSecretKey
{
private:
    NativeVector m_s;
public:
    //带参构造
    LweSecretKey(const NativeVector &sk_vector) : m_s(sk_vector) {}

    //拷贝构造
    LweSecretKey(const LweSecretKey &another)
    {
        this->m_s = another.m_s;
    }

    //设置sk
    void SetLweSecretKey(const NativeVector &sk_vector)
    {
        this->m_s = sk_vector;
    }

    const NativeVector &GetLweSecretKey() const
    {
        return m_s;
    }

    ~LweSecretKey()
    {
    }
};

class LweSwitchingKey
{
private:
    /* data 三维向量*/
    std::vector<std::vector<std::vector<LweCipher>>> m_key;

public:
    //有参构造函数
    LweSwitchingKey(std::vector<std::vector<std::vector<LweCipher>>> &vec)
    {
        this->m_key = vec;
    }

    //拷贝构造
    LweSwitchingKey(const LweSwitchingKey &another)
    {
        this->m_key = another.m_key;
    }

    const std::vector<std::vector<std::vector<LweCipher>>>& GetLweSwitchingKey() const
    {
        return m_key;
    }

    ~LweSwitchingKey() {}
};


class LweParams
{
private:
    //明文空间
    usint m_t;
    //lwe维度
    usint m_n;
    //lwe密文空间
    NativeInteger m_q;
    //Rlwe维度
    usint m_N;
    //Rlwe密文空间
    NativeInteger m_Q;
    //Rlwe to lwe keyswitch base
    usint m_ks_base;
    //keyswitch base 对应扩展的vector
    //NativeVector m_ks_baseG;
    vector<NativeInteger> m_ks_baseG;
    // Error distribution generator
    DiscreteGaussianGeneratorImpl<NativeVector> m_dgg;   //设置标准差

public:
    LweParams(/* args */);

    //拷贝构造函数
    LweParams(const LweParams &another);

    //带参数构造 //m_dgg呢
    LweParams(const usint &t, const usint &n, const NativeInteger &q,
                     const usint &N, const NativeInteger &Q, const usint &ks_base,
                     const double &std);

    //计算pow ks_base
    void ComputePow();

    const DiscreteGaussianGeneratorImpl<NativeVector> &GetDgg() const;

    //返回LweParams的t
    const usint &Gett() const;
   

    //返回LweParams的lwe维度
    const usint &Getn() const;

    //返回LweParams的密文空间
    const NativeInteger &Getq() const;

    //返回LweParams的Rlwe维度
    const usint &GetN() const;

    //返回RLwe的空间
    const NativeInteger &GetQ() const;

    //返回Rlwe to lwe keyswitch base
    const usint &Getks_base() const;

    //返回keyswitch base 对应扩展的vector
    const vector<NativeInteger> &Getks_baseG() const;

    //重载=
    const LweParams &operator=(const LweParams &another);

    // LweCipherEncrypt
    ~LweParams(){}
};


#endif
