//
// Created by Ruochen WANG on 31/12/2019.
//

#include <mcl/bn256.hpp>
#include <ctime>
#include <vector>
#include <iostream>

using namespace mcl::bn256;

//const int num_of_keys = 10;

void Hash(G1 &P, const std::string &m) {
    Fp t;
    t.setHashOf(m);
    mapToG1(P, t);
}

void KeyGen(Fr &s, G2 &pub, const G2 &Q) {
    s.setRand();
    G2::mul(pub, Q, s); // pub = sQ
}

void Sign(G1 &sign, const Fr &s, const std::string &m) {
    G1 Hm;
    Hash(Hm, m);
    G1::mul(sign, Hm, s); // sign = s H(m)
}

bool Verify(const G1 &sign, const G2 &Q, const G2 &pub, const std::string &m) {
    Fp12 e1, e2;
    G1 Hm;
    Hash(Hm, m);
    pairing(e1, sign, Q); // e1 = e(sign, Q)
    pairing(e2, Hm, pub); // e2 = e(Hm, sQ)
    return e1 == e2;
}

void Aggregation(G1 &result, G1 &sign1, G1 &sign2) {
    G1::add(result, sign1, sign2);
}

bool
AggregateVerification(G1 &signs, const G2 &Q, const G2 &pub, const std::string &m1, const std::string &m2) {
    G1 Hm1, Hm2;
    Hash(Hm1, m1);
    Hash(Hm2, m2);

    Fp12 e_left, e_sum;
    pairing(e_left, signs, Q);

    Fp12 e1, e2;
    pairing(e1, Hm1, pub);
    pairing(e2, Hm2, pub);
    Fp12::mul(e_sum, e1, e2);

    return e_left == e_sum;
}

void run_exp2(const std::string m1, const std::string m2) {

    // setup parameter
    initPairing();
    G2 Q;
    mapToG2(Q, 1);

    // generate secret key and public key
    Fr s;
    G2 pub;
    KeyGen(s, pub, Q);

    // sign
    G1 sign1, sign2;
    Sign(sign1, s, m1);
    Sign(sign2, s, m2);

    // verify
    bool ok1 = Verify(sign1, Q, pub, m1);
    bool ok2 = Verify(sign2, Q, pub, m2);
    std::cout << "verify1 " << (ok1 ? "ok" : "ng") << std::endl;
    std::cout << "verify2 " << (ok2 ? "ok" : "ng") << std::endl;

    G1 signs;
    Aggregation(signs, sign1, sign2);
    bool ok3 = AggregateVerification(signs, Q, pub, m1, m2);
    std::cout << "verify3 " << (ok3 ? "ok" : "ng") << std::endl;

}

int main(int argc, char *argv[]) {
    std::string m1 = "str1 test";
    std::string m2 = "str2 for test";
    run_exp2(m1, m2);
}
