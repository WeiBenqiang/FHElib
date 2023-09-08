/*
 * @Author: WeiBenqiang 
 * @Date: 2022-06-05 14:35:50
 * @LastEditors: WeiBenqiang 
 * @LastEditTime: 2022-06-10 22:01:04
 * @FilePath: /LLW_FHE/src/rlweparams.cpp
 * @Description: 
 */

#include "rlwe.h"

//带参数构造
RLweParams::RLweParams(const LweParams &lweparams, const usint &BaseG)
{
    this->m_BaseG = BaseG;
    this->m_t = lweparams.Gett();
    this->m_n = lweparams.Getn();
    this->m_N = lweparams.GetN();
    this->m_q = lweparams.Getq();
    this->m_Q = lweparams.GetQ();
    this->m_dgg = lweparams.GetDgg();

    PreCompute(); //预计算多项式的参数
}

const DiscreteGaussianGeneratorImpl<NativeVector> &RLweParams::GetDgg() const
{
    return m_dgg;
}

//返回RLweParams的t
const usint &RLweParams::Gett() const
{
    return m_t;
}

const usint &RLweParams::Getn() const
{ 
    return m_n;
}

//返回RLweParams的Rlwe维度
const usint &RLweParams::GetN() const
{
    return m_N;
}

//返回RLwe分解的基
const usint &RLweParams::GetBaseG() const
{
    return m_BaseG;
}

//返回分解的长度
const usint &RLweParams::GetDigitsG() const
{
    return m_digitsG;
}

//返回RLweParams的密文空间
const NativeInteger &RLweParams::Getq() const
{
    return m_q;
}

//返回RLweParams的密文空间
const NativeInteger &RLweParams::GetQ() const
{
    return m_Q;
}
const vector<NativeInteger> &RLweParams::GetGPower() const
{
    return m_Gpower;
}

const vector<NativeInteger> &RLweParams::GetGateConst() const
{
    return m_gateConst;
}

const shared_ptr<ILNativeParams> &RLweParams::GetPolyParams() const
{
    return polyParams;
}

//重载=
const RLweParams &RLweParams::operator=(const RLweParams &another)
{
    this->m_t = another.m_t;
    this->m_Q = another.m_Q;
    this->m_N = another.m_N;
    this->m_BaseG = another.m_BaseG;
    return *this;
}

void RLweParams::PreCompute()
{
    //找本原根
    NativeInteger rootOfUnity = RootOfUnity<NativeInteger>(2 * m_N, m_Q);
    //计算NTT参数
    ChineseRemainderTransformFTT<NativeVector>::PreCompute(rootOfUnity, 2 * m_N, m_Q);
    //多项式参数
    polyParams = make_shared<ILNativeParams>(2 * m_N, m_Q, rootOfUnity);
    //分解的基
    m_digitsG = (usint)ceil(log(m_Q.ConvertToDouble()) / log(static_cast<double>(m_BaseG)));
    // Computes baseG^i
    NativeInteger vTemp = NativeInteger(1);
    for (uint32_t i = 0; i < m_digitsG; i++)
    {
        m_Gpower.push_back(vTemp);
        vTemp = vTemp.ModMul(NativeInteger(m_BaseG), m_Q);
    }

    // Sets the gate constants for supported binary operations
    m_gateConst = {
        NativeInteger(1) * (m_q >> 3), // OR
        NativeInteger(7) * (m_q >> 3), // AND
        
        NativeInteger(5) * (m_q >> 3), // NOR
        NativeInteger(3) * (m_q >> 3), // NAND

    };                                
}