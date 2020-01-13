//
// Created by Ruochen WANG on 31/12/2019.
//

#include <mcl/bn256.hpp>
#include <ctime>
#include <vector>
#include <iostream>

using namespace mcl::bn256;

//const int num_of_keys = 10;

void Hash(G1 &P, const void *m, int size) {
    Fp t;
    t.setHashOf(m, size);
    mapToG1(P, t);
}

void KeyGen(Fr &s, G2 &pub, const G2 &Q) {
    s.setRand();
    G2::mul(pub, Q, s); // pub = sQ
}

void Sign(G1 &sign, const Fr &s, const void *m, int size) {
    G1 Hm;
    Hash(Hm, m, size);
    G1::mul(sign, Hm, s); // sign = s H(m)
}

bool Verify(const G1 &sign, const G2 &Q, const G2 &pub, const void *m, int size) {
    Fp12 e1, e2;
    G1 Hm;
    Hash(Hm, m, size);
    pairing(e1, sign, Q); // e1 = e(sign, Q)
    pairing(e2, Hm, pub); // e2 = e(Hm, sQ)
    return e1 == e2;
}

void Aggregation(G1 &result, std::vector<G1> sign_list) {
    G1::add(result, sign_list[0], sign_list[1]);
    for (int i = 2; i < (int) sign_list.size(); i++) {
        G1::add(result, result, sign_list[i]);
    }
}

bool
AggregateVerification(G1 &signs, const G2 &Q, const G2 &pub, std::vector<void *> chunks, std::vector<int> chunk_size) {
    std::vector<G1> hash_list;
    G1 Hm;
    for (int i = 0; i < (int) chunks.size(); i++) {
        Hash(Hm, chunks[i], chunk_size[i]);
        hash_list.push_back(Hm);
    }

    Fp12 e_left, e_sum;
    pairing(e_left, signs, Q);

    std::vector<Fp12> e_list;
    Fp12 e;
    for (int i = 0; i < (int) chunks.size(); i++) {
        pairing(e, hash_list[i], pub);
        e_list.push_back(e);
    }
    Fp12::mul(e_sum, e_list[0], e_list[1]);
    for (int i = 2; i < (int) chunks.size(); i++) {
        Fp12::mul(e_sum, e_list[i], e_sum);
    }

    return e_left == e_sum;
}

void run_exp2(std::vector<void *> chunks, std::vector<int> chunk_size) {

    // setup parameter
    initPairing();
    G2 Q;
    mapToG2(Q, 1);

    // generate secret key and public key
    Fr s;
    G2 pub;
    KeyGen(s, pub, Q);

    // sign
    G1 sign;
    std::vector<G1> sign_list;
    for (int i = 0; i < (int) chunks.size(); i++) {
        Sign(sign, s, chunks[i], chunk_size[i]);
        sign_list.push_back(sign);
    }

    // verify
//    bool ok1 = Verify(sign1, Q, pub, m1, 24);
//    std::cout << "verify1 " << (ok1 ? "ok" : "ng") << std::endl;

    G1 signs;
    Aggregation(signs, sign_list);
    bool ok3 = AggregateVerification(signs, Q, pub, chunks, chunk_size);
    std::cout << "verify3 " << (ok3 ? "ok" : "ng") << std::endl;

}

int main(int argc, char *argv[]) {
    std::string m = argc == 1 ? "hello mcl" : argv[1];

    std::string m1 = "str1 test";
    std::string m2 = "str2 for test";
    std::string m3 = "str 3 for test loops";

    std::vector<void *> chunks;
    std::vector<int> chunk_size;

    chunks.push_back(static_cast<void *> (&m1));
    chunks.push_back(static_cast<void *> (&m2));
    chunks.push_back(static_cast<void *> (&m3));

    chunk_size.push_back(sizeof(m1));
    chunk_size.push_back(sizeof(m2));
    chunk_size.push_back(sizeof(m3));

    run_exp2(chunks, chunk_size);
}
