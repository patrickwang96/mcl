//
// Created by Ruochen WANG on 31/12/2019.
//

#include <mcl/bn256.hpp>
#include <iostream>

using namespace mcl::bn256;

void Hash(G1& P, const std::string& m)
{
    Fp t;
    t.setHashOf(m);
    mapToG1(P, t);
}

void KeyGen(Fr& s, G2& pub, const G2& Q)
{
    s.setRand();
    G2::mul(pub, Q, s); // pub = sQ
}

void Sign(G1& sign, const Fr& s, const std::string& m)
{
    G1 Hm;
    Hash(Hm, m);
    G1::mul(sign, Hm, s); // sign = s H(m)
}

bool Verify(const G1& sign, const G2& Q, const G2& pub1, const G2& pub2, const std::string& m)
{
    Fp12 e1, e2, e3;
    G1 Hm;
    Hash(Hm, m);
    pairing(e1, sign, Q); // e1 = e(sign, Q)
    pairing(e2, Hm, pub1); // e2 = e(Hm, sQ)
    pairing(e3, Hm, pub2);
    Fp12 aggregated_e;
    Fp12::mul(aggregated_e, e2, e3);
    return e1 == aggregated_e;
}

int main(int argc, char *argv[])
{
    std::string m = argc == 1 ? "hello mcl" : argv[1];

    // setup parameter
    initPairing();
    G2 Q;
    mapToG2(Q, 1);

    // generate secret key and public key
    Fr s1;
    G2 pub1;
    KeyGen(s1, pub1, Q);
    std::cout << "secret key " << s1 << std::endl;
    std::cout << "public key " << pub1 << std::endl;

    // generate another secrete key and public key set
    Fr s2;
    G2 pub2;
    KeyGen(s2, pub2, Q);
    std::cout << "secret key2 " << s2 << std::endl;
    std::cout << "public key2 " << pub2 << std::endl;

    // sign
    G1 aggregated_sign;
    G1 sign1;
    G1 sign2;
    Sign(sign1, s1, m);
    Sign(sign2, s2, m);
    std::cout << "msg " << m << std::endl;
    std::cout << "sign1 " << sign1 << std::endl;
    std::cout << "sign2 " << sign2 << std::endl;
    G1::add(aggregated_sign, sign1, sign2);

    // verify
    bool ok = Verify(aggregated_sign, Q, pub1, pub2, m);
    std::cout << "verify " << (ok ? "ok" : "ng") << std::endl;
}
