/*
 * @Author: LiZhiHao
 * @Date: 2022-04-20 16:04:37
 * @LastEditTime: 2022-06-11 14:13:51
 * @Description:
 *
 * Copyright (c) 2022 by LLW, All Rights Reserved.
 */
#include "lwe.h"
using namespace std;

//带参数构造
LweParams::LweParams(const usint &t, const usint &n, const NativeInteger &q,
                     const usint &N, const NativeInteger &Q, const usint &ks_base,
                     const double &std)
{
    this->m_t = t;
    this->m_n = n;
    this->m_q = q;
    this->m_N = N;
    this->m_Q = Q;
    this->m_ks_base = ks_base;

    ComputePow(); //预计算power of base
    this->m_dgg.SetStd(std);
}

//拷贝构造函数
LweParams::LweParams(const LweParams &another)
{
    this->m_t = another.m_t;
    this->m_n = another.m_n;
    this->m_q = another.m_q;
    this->m_N = another.m_N;
    this->m_Q = another.m_Q;
    this->m_ks_base = another.m_ks_base;
    this->m_ks_baseG = another.m_ks_baseG;
    this->m_dgg = another.m_dgg;
    this->m_dgg.SetStd(another.m_dgg.GetStd());
}

void LweParams::ComputePow()
{
    uint32_t digitCount = (uint32_t)std::ceil(
        log(m_Q.ConvertToDouble()) / log(static_cast<double>(m_ks_base)));
    // Populate digits
    NativeInteger value = 1;
    for (uint32_t i = 0; i < digitCount; i++)
    {
        m_ks_baseG.push_back(value);
        value *= m_ks_base;
    }
}

//返回LweParams的t
const usint &LweParams::Gett() const
{
    return m_t;
}

//返回LweParams的lwe维度
const usint &LweParams::Getn() const
{
    return m_n;
}

//返回LweParams的密文空间
const NativeInteger &LweParams::Getq() const
{
    return m_q;
}

//返回LweParams的Rlwe维度
const usint &LweParams::GetN() const
{
    return m_N;
}

//返回RLwe的空间
const NativeInteger &LweParams::GetQ() const
{
    return m_Q;
}

//返回Rlwe to lwe keyswitch base
const usint &LweParams::Getks_base() const
{
    return m_ks_base;
}

//返回keyswitch base 对应扩展的vector
const vector<NativeInteger> &LweParams::Getks_baseG() const
{
    return m_ks_baseG;
}

const DiscreteGaussianGeneratorImpl<NativeVector> &LweParams::GetDgg() const
{
    return m_dgg;
}

//重载=
const LweParams &LweParams::operator=(const LweParams &another)
{
    this->m_t = another.m_t;
    this->m_n = another.m_n;
    this->m_q = another.m_q;
    this->m_N = another.m_N;
    this->m_Q = another.m_Q;
    this->m_ks_base = another.m_ks_base;
    this->m_ks_baseG = another.m_ks_baseG;
    this->m_dgg = another.m_dgg;
    return *this;
}
