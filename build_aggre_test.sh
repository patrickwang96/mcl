
g++ -I/usr/local/opt/openssl/include -I/usr/local/opt/gmp/include -g3 -Wall -Wextra -Wformat=2 -Wcast-qual -Wcast-align -Wwrite-strings -Wfloat-equal -Wpointer-arith -m64 -I include -I test -fomit-frame-pointer -DNDEBUG -O3  -DMCL_DONT_USE_OPENSSL -fPIC -DMCL_USE_LLVM=1 sample/bls_aggregation.cpp -o bin/bls_aggregation.exe lib/libmclbn384_256.a lib/libmcl.a -L/usr/local/opt/openssl/lib -L/usr/local/opt/gmp/lib -lgmp -lgmpxx  -m64  -lstdc++

