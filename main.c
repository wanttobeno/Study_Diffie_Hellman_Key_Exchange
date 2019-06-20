//
//  main.c
//  Diffie-Hellman Key Exchange
//

// https://gist.github.com/cloudwu/8838724

// The biggest 64bit prime
// Public Keys available = P, G
#define P 0xffffffffffffffc5ull
#define G 5

#include <stdio.h>
#include <stdint.h>
#include <assert.h>
#include <stdlib.h>

// calc a * b % p , avoid 64bit overflow
static inline uint64_t
mul_mod_p(uint64_t a, uint64_t b) {
    uint64_t m = 0;
    while(b) {
        if(b&1) {
            uint64_t t = P-a;
            if ( m >= t) {
                m -= t;
            } else {
                m += a;
            }
        }
        if (a >= P - a) {
            a = a * 2 - P;
        } else {
            a = a * 2;
        }
        b>>=1;
    }
    return m;
}

static inline uint64_t
pow_mod_p(uint64_t a, uint64_t b) {
    if (b==1) {
        return a;
    }
    uint64_t t = pow_mod_p(a, b>>1);
    t = mul_mod_p(t,t);
    if (b % 2) {
        t = mul_mod_p(t, a);
    }
    return t;
}

// calc a^b % p
uint64_t
powmodp(uint64_t a, uint64_t b) {
    if (a > P)
        a%=P;
    return pow_mod_p(a,b);
}

uint64_t
randomint64() {
    uint64_t a = rand();
    uint64_t b = rand();
    uint64_t c = rand();
    uint64_t d = rand();
    return a << 48 | b << 32 | c << 16 | d;
}

static void
test() {
    // ALICE Private Key Selected = a
    uint64_t a = randomint64();
    // BOB Private Key Selected = b
    uint64_t b = randomint64();
    // ALICE Generated Secret Key = A,Send it to BOB
    uint64_t A = powmodp(G, a);
    // BOB Generated Secret Key = B,Send it to Alice
    uint64_t B = powmodp(G, b);
    
    // Alice Calculate out the secret number
    uint64_t secret1 = powmodp(B,a);
    
    // BOB Calculate out the secret number
    uint64_t secret2 = powmodp(A,b);
    assert(secret1 == secret2);

    // Now ALICE and BOB has the same secret number
    printf("a=%llu b=%llu s=%llu\n", a,b,secret1);
}

int
main() {
    int i;
    for (i=0;i<100;i++) {
        test();
    }
    
    return 0;
}
