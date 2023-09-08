/*
 * @Author: WeiBeniang
 * @Date: 2022-04-18 20:35:50
 * @LastEditTime: 2022-06-19 16:46:13
 * @Description:
 *
 * Copyright (c) 2022 by LLW, All Rights Reserved.
 */
#include "lwefunction.h"

// 三值均匀分布的私钥产生
LweSecretKey LweFunction::LweTerKeyGen_n(const LweParams &lweparams)
{
  TernaryUniformGeneratorImpl<NativeVector> tug;
  return LweSecretKey(tug.GenerateVector(lweparams.Getn(), lweparams.Getq()));
}
LweSecretKey LweFunction::LweTerKeyGen_N(const LweParams &lweparams)
{
  TernaryUniformGeneratorImpl<NativeVector> tug;
  return LweSecretKey(tug.GenerateVector(lweparams.GetN(), lweparams.GetQ()));
}

//加密
LweCipher LweFunction::LweEncrypt(LwePlaintext &m, const LweSecretKey &sk, const LweParams &lweparams)
{
  // 1.确定lwe参数,应该根据sk的参数来确定
  usint t = lweparams.Gett();
  usint n = sk.GetLweSecretKey().GetLength();
  NativeInteger q = sk.GetLweSecretKey().GetModulus();

  // 2.均匀选择a,高斯选择e
  DiscreteUniformGeneratorImpl<NativeVector> dug;
  dug.SetModulus(q);
  NativeVector a = dug.GenerateVector(n);
  NativeInteger b = (q / t) * (m % t) + lweparams.GetDgg().GenerateInteger(q);
  b.ModEq(q);

  // 3.预计算巴雷特乘法参数
  NativeInteger mu = q.ComputeMu();

  const NativeVector &key = sk.GetLweSecretKey();

  // 4.计算 a*s+m+e mod q
  for (size_t i = 0; i < n; i++)
  {
    b += a[i].ModMulFast(key[i], q, mu);
  }
  b.ModEq(q);

  return LweCipher(a, b);
}

// LWE的解密函数
LwePlaintext LweFunction::LweDecrypt(const LweCipher &sample, const LweSecretKey &sk, const LweParams &lweparams)
{
  // 1.确定lwe参数
  usint t = lweparams.Gett();
  usint n = sk.GetLweSecretKey().GetLength();
  NativeInteger q = sk.GetLweSecretKey().GetModulus();
  NativeVector a = sample.GetLweCipher_a();
  NativeInteger b = sample.GetLweCipher_b();

  NativeInteger mu = q.ComputeMu();

  const NativeVector &key = sk.GetLweSecretKey();

  NativeInteger innerProduct = 0;
  for (size_t i = 0; i < n; i++)
  {
    innerProduct += a[i].ModMulFast(key[i], q, mu);
  }
  innerProduct.ModEq(q);

  // b-as
  b.ModSubFastEq(innerProduct, q);

  // round((b-as)*(t/q))
  LwePlaintext message = (b.MultiplyAndRoundEq(NativeInteger(t), q)).ConvertToInt() % t;
  return message;
}

// LWE对0的加密
void LweFunction::LweEncryptZero() {}

//生成密文切换的密钥
LweSwitchingKey LweFunction::LweSwitchingKeyGenV1(const LweSecretKey &oldkey, const LweSecretKey &newkey, const LweParams &lweparams)
{
  usint n = lweparams.Getn();
  usint N = lweparams.GetN();

  NativeInteger Q = lweparams.GetQ();
  usint baseKS = lweparams.Getks_base();
  // cout << "baseKS = " << baseKS << endl;
  vector<NativeInteger> digitsKS = lweparams.Getks_baseG();
  usint expKS = digitsKS.size(); // Gadget的长度
  // cout << "expKS = " << expKS << endl;

  // 新私钥
  NativeVector new_sk = newkey.GetLweSecretKey();
  new_sk.SwitchModulus(Q); //切换到模数Q下

  NativeVector old_sk = oldkey.GetLweSecretKey(); //旧私钥

  //均匀分布
  DiscreteUniformGeneratorImpl<NativeVector> dug;
  dug.SetModulus(Q);

  //高斯噪声
  DiscreteGaussianGeneratorImpl<NativeVector> dgg = lweparams.GetDgg();

  NativeInteger mu = Q.ComputeMu();

  //密钥切换密钥是三维向量 z[i]*v*Bg^{j}的密文
  std::vector<std::vector<std::vector<LweCipher>>> result(N);
#pragma omp parallel for
  for (size_t i = 0; i < N; i++) //对旧私钥的每个进行处理z[i]
  {
    //该维度下是一个二维向量
    std::vector<std::vector<LweCipher>> vector1(baseKS);
    for (size_t j = 0; j < baseKS; j++) // 0，1，2， ... ，base
    {
      //该维度下是一维向量
      std::vector<LweCipher> vector2(expKS);
      for (size_t k = 0; k < expKS; k++) // base^{1,2, 3,...  }
      {
        NativeVector a = dug.GenerateVector(n);                                                   // a
        NativeInteger b = dgg.GenerateInteger(Q).ModAdd(old_sk[i].ModMul(j * digitsKS[k], Q), Q); // v*z[i]*B^{j}

        // b = a[i]s[i] + e
        for (size_t ii = 0; ii < n; ii++)
        {
          b += a[ii].ModMulFast(new_sk[ii], Q, mu);
        }

        b.ModEq(Q);
        vector2[k] = LweCipher(a, b);
      }
      // vector1[j].push_back(vector2);
      vector1[j] = std::move(vector2);
    }
    // result[i].push_back(vector1);
    result[i] = std::move(vector1);
  }
  return LweSwitchingKey(result);
}

// LWE的密钥切换功能

LweCipher LweFunction::LweKeySwitchingV1(const LweCipher &oldcipher, const LweSwitchingKey &switchkey, const LweParams &lweparams)
{
  usint n = lweparams.Getn();
  usint N = lweparams.GetN();
  NativeInteger Q = lweparams.GetQ();
  usint baseKS = lweparams.Getks_base();
  vector<NativeInteger> digitsKS = lweparams.Getks_baseG();
  usint expKS = digitsKS.size();

  // 新的密文(a,b)
  NativeVector a(n, Q);
  NativeInteger b = oldcipher.GetLweCipher_b();
  NativeVector aOld = oldcipher.GetLweCipher_a();
#pragma omp parallel for
  for (size_t i = 0; i < N; i++)
  {
    //对每个aOld[i]分解，分解的长度为expKS
    NativeInteger ai = aOld[i];
    for (size_t j = 0; j < expKS; j++, ai /= baseKS)
    {
      //找到当前的余数
      uint64_t aij = (ai % baseKS).ConvertToInt();
      //直接累加各个a[k]
      for (size_t k = 0; k < n; k++)
      {
        a[k].ModSubFastEq(switchkey.GetLweSwitchingKey()[i][aij][j].GetLweCipher_a()[k], Q);
      }
      b.ModSubFastEq(switchkey.GetLweSwitchingKey()[i][aij][j].GetLweCipher_b(), Q);
    }
  }

  return LweCipher(a, b);
}

NativeInteger Round(const NativeInteger &v, const NativeInteger &q, const NativeInteger &Q)
{
  return NativeInteger((uint64_t)std::floor(0.5 + v.ConvertToDouble() *
                                                      q.ConvertToDouble() /
                                                      Q.ConvertToDouble()))
      .Mod(q);
}

//模切换
LweCipher LweFunction::LweModSwitching(const LweCipher &oldcipher, const LweParams &lweparams)
{
  //模切换Q->q
  NativeInteger q = lweparams.Getq();
  NativeInteger Q = lweparams.GetQ();

  usint n = lweparams.Getn();

  //新的密文
  NativeVector a(n, q); // q下的密文
  for (size_t i = 0; i < n; i++)
  {
    a[i] = Round(oldcipher.GetLweCipher_a()[i], q, Q);
  }

  NativeInteger b = Round(oldcipher.GetLweCipher_b(), q, Q);

  return LweCipher(a, b);
}
