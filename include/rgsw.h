/*
 * @Author: WeiBeniang
 * @Date: 2022-04-19 19:24:17
 * @LastEditTime: 2022-05-11 22:37:21
 * @Description: RGSW密文
 *
 * Copyright (c) 2022 by LLW, All Rights Reserved.
 */
#ifndef RGSW_H
#define RGSW_H

#include "rlwe.h"
#include "math/ternaryuniformgenerator.h"
#include "lattice/poly.h"
#include "lattice/backend.h"
#include "utils/inttypes.h"
#include "math/discreteuniformgenerator.h"
#include "math/backend.h"

using namespace lbcrypto;
using namespace std;

class RGSWCipher
{
private:
    vector<vector<NativePoly>> m_elements;

public:
    RGSWCipher(/* args */) {}

    RGSWCipher(uint32_t rowSize, uint32_t colSize)
    {
        m_elements.resize(rowSize);
        for (uint32_t i = 0; i < rowSize; i++)
            m_elements[i].resize(colSize);
    }

    //带参数构造
    RGSWCipher(vector<vector<NativePoly>> &elements)
    {
        this->m_elements = elements;
    }

    //拷贝构造函数
    RGSWCipher(const RGSWCipher &another)
    {
        this->m_elements = another.m_elements;
    }

    //重载=
    const RGSWCipher &operator=(const RGSWCipher &another)
    {
        this->m_elements = another.m_elements;
        return *this;
    }

    //获取RGSW的元素
    const vector<vector<NativePoly>> &GetElements() const
    {
        return m_elements;
    }

    void SetElements(const vector<vector<NativePoly>> &elements)
    {
        m_elements = elements;
    }

    //设置 RGSW的表示形式，即设个每个多项式的表示形式： 系数 vs NTT
    void SetFormat(const Format format)
    {
        for (uint32_t i = 0; i < m_elements.size(); i++)
        {
            for (uint32_t j = 0; j < m_elements[i].size(); j++)
            {
                m_elements[i][j].SetFormat(format);
            }
        }
    }

    ~RGSWCipher() {}
};

class Bootstrapkey
{
private:
    vector<vector<RGSWCipher>> m_bsk;

public:
    Bootstrapkey(/* args */){}

    //带参构造
    Bootstrapkey(const vector<vector<RGSWCipher>> bsk)
    {
        this->m_bsk = bsk;
    }
    //拷贝构造函数
    Bootstrapkey(const Bootstrapkey &another)
    {
        this->m_bsk = another.m_bsk;
    }

    //获取bsk
    const vector<vector<RGSWCipher>> &getBoostrapkey() const
    {
        return m_bsk;
    }

    void SetBoostrapkey(vector<vector<RGSWCipher>> bsk)
    {
        m_bsk = bsk;
    }

    const Bootstrapkey &operator=(const Bootstrapkey &another)
    {
        this->m_bsk = another.m_bsk;
        return *this;
    }

    ~Bootstrapkey(){}
};


#endif
