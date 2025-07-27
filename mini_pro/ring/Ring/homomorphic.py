import numpy as np
from numpy.polynomial import polynomial as poly
import time

def polymul(x, y, modulus, poly_mod):
    return np.int64(
        np.round(poly.polydiv(poly.polymul(x, y) % modulus, poly_mod)[1] % modulus)
    )

def polyadd(x, y, modulus, poly_mod):
    return np.int64(
        np.round(poly.polydiv(poly.polyadd(x, y) % modulus, poly_mod)[1] % modulus)
    )
# generates a polynomial with binary coefficients (0 or 1).
def gen_binary_poly(size):
    return np.random.randint(0, 2, size, dtype=np.int64)

# generates a polynomial where each coefficient is randomly chosen from the range {0, ..., modulus-1}.

def gen_uniform_poly(size, modulus):
    return np.random.randint(0, modulus, size, dtype=np.int64)

def gen_normal_poly(size):
    return np.int64(np.random.normal(0, 2, size=size))

def keygen(size, modulus, poly_mod):
    sk = gen_binary_poly(size) #private key
    a = gen_uniform_poly(size, modulus) # random var
    e = gen_normal_poly(size) #noise
    # b=(−a⋅sk+(−e))modq
    b = polyadd(polymul(-a, sk, modulus, poly_mod), -e, modulus, poly_mod)
    return (b, a), sk

def encrypt(pk, size, q, t, poly_mod, pt):
    #pk public key,pt=plain text
    # message is spread out over a larger range so that noise doesn't corrupt it too much.
    m = np.array([pt] + [0] * (size - 1), dtype=np.int64) % t
    delta = q // t
    scaled_m = delta * m  % q
    e1 = gen_normal_poly(size)
    e2 = gen_normal_poly(size)
    u = gen_binary_poly(size)
    # ct0=b.u+e1+scaled_m mod q(b is first part of public key)
    # u is a small random binary polynomial 
    ct0 = polyadd(polyadd(polymul(pk[0], u, q, poly_mod), e1, q, poly_mod), scaled_m, q, poly_mod)
    # c1=a.u+e2 modq
    # a is sceond part of public key
    ct1 = polyadd(polymul(pk[1], u, q, poly_mod), e2, q, poly_mod)
    return (ct0, ct1)

def decrypt(sk, size, q, t, poly_mod, ct):
    #m1=c0+f.c1 modq f(private key)
    scaled_pt = polyadd(polymul(ct[1], sk, q, poly_mod), ct[0], q, poly_mod)
    # m=m1.t/q mot t
    #t is pt modulus
    decrypted_poly = np.round(scaled_pt * t / q) % t
    return int(decrypted_poly[0])

def add_plain(ct, pt, q, t, poly_mod):
    size = len(poly_mod) - 1
    m = np.array([pt] + [0] * (size - 1), dtype=np.int64) % t
    delta = q // t
    scaled_m = delta * m  % q
    new_ct0 = polyadd(ct[0], scaled_m, q, poly_mod)
    return (new_ct0, ct[1])

def mul_plain(ct, pt, q, t, poly_mod):
    size = len(poly_mod) - 1
    m = np.array([pt] + [0] * (size - 1), dtype=np.int64) % t
    new_c0 = polymul(ct[0], m, q, poly_mod)
    new_c1 = polymul(ct[1], m, q, poly_mod)
    return (new_c0, new_c1)
