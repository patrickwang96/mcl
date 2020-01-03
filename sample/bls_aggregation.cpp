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

bool Verify(const G1 &sign, const G2 &Q, const std::vector<G2> &pub, const std::string &m, int num_of_keys) {
    Fp12 e1, e2, e3;
    std::vector<Fp12> e;
    G1 Hm;
    Hash(Hm, m);
    pairing(e1, sign, Q); // e1 = e(sign, Q)
    for (int i = 0; i < num_of_keys; i++) {
        pairing(e2, Hm, pub[i]);
        e.push_back(e2);
    }
//    pairing(e2, Hm, pub1); // e2 = e(Hm, sQ)
//    pairing(e3, Hm, pub2);
    Fp12 aggregated_e;
    Fp12::mul(aggregated_e, e[0], e[1]);
    for (int i = 2; i < num_of_keys; i++) {
        Fp12::mul(aggregated_e, aggregated_e, e[i]);
    }
    return e1 == aggregated_e;
}

void run_exp(const std::string& m, int num_of_keys) {
    clock_t start_t, end_t;
    double total_t;

    // setup parameter
    initPairing();
    G2 Q;
    mapToG2(Q, 1);

    // generate secret key and public key
    Fr s1;
    std::vector<Fr> s;
    std::vector<G2> pub;
    G2 pub1;
    start_t = clock();
    for (int i = 0; i < num_of_keys; i++) {
        KeyGen(s1, pub1, Q);
        s.push_back(s1);
        pub.push_back(pub1);
    }
    end_t = clock();
    total_t = 1000 * (double) (end_t - start_t) / CLOCKS_PER_SEC;
    std::cout << "time used for generate " << num_of_keys << " secret keys and public keys are " << total_t <<
              " ms" << std::endl;


    // sign
    std::vector<G1> sign;
    G1 aggregated_sign;
    G1 sign1;
    start_t = clock();
    for (int i = 0; i < num_of_keys; i++) {
        Sign(sign1, s[i], m);
        sign.push_back(sign1);
    }
    end_t = clock();
    total_t = 1000 * (double) (end_t - start_t) / CLOCKS_PER_SEC;
    std::cout << "time used for sign with " << num_of_keys << " keys are " << total_t <<
              " ms" << std::endl;

    start_t = clock();
    G1::add(aggregated_sign, sign[0], sign[1]);
    for (int i = 2; i < num_of_keys; i++) {
        G1::add(aggregated_sign, sign[i], aggregated_sign);
    }
    end_t = clock();
    total_t = 1000 * (double) (end_t - start_t) / CLOCKS_PER_SEC;
    std::cout << "time used for aggregate " << num_of_keys << " keys are " << total_t <<
              " ms" << std::endl;


    // verify
    start_t = clock();
    bool ok = Verify(aggregated_sign, Q, pub, m, num_of_keys);
    end_t = clock();
    total_t = 1000 * (double) (end_t - start_t) / CLOCKS_PER_SEC;
    std::cout << "time used for verify " << num_of_keys << " keys are " << total_t <<
              " ms" << std::endl;

    std::cout << "verify " << (ok ? "ok" : "ng") << std::endl;
}

int main(int argc, char *argv[]) {
    std::string m = argc == 1 ? "hello mcl" : argv[1];
    std::string m1 (20, 'x');
    std::string m2 (1024, 'x');

    int candidates[] = {10, 20, 30, 50, 100, 200, 300, 500, 700, 1000, 2000, 3000, 5000, 10000};

    std::cout << "for message of length 20 bytes" << std::endl;
    for (int candidate : candidates) {
        run_exp(m1, candidate);
    }

    std::cout << "for message of length 1024 bytes" << std::endl;
    for (int candidate : candidates) {
        run_exp(m2, candidate);
    }

//    run_exp(m, 10);
}
