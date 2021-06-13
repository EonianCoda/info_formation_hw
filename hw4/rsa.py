import random 
import math
import argparse

def fast_exp_mod(x, h, n):
    """fast exponentiation and modular
    
    use square and multiply algorithm to fasten the big number exponentiation
    
    Args:
        x: base
        h: power
        n: moduler
    Returns:
        the result of ((x^h) mod n)
    """
    y = 1
    while h != 0:
        if h & 1:
            y = (y * x) % n
        x = (x * x) % n
        h >>= 1
    return y
     
def miller_rabin_test(a, s, d, n):
    cur = pow(a, d, n)
    if cur == n - 1 or cur == 1:
        return True
    for _ in range(s - 1):
        cur = (cur * cur) % n
        if cur == n - 1:
            return True
    return False
def miller_rabin(n):
    """test whether n is a prime
    
    use miller rabin test algorithm
    """
    confidence = 30
    d = n - 1
    s = 0
    while d % 2 == 0:
        d >>= 1
        s += 1
    for _ in range(confidence):
        a = random.randrange(1, n)
        if not miller_rabin_test(a, s, d, n):
            return False
    return True

def ext_euclid(a,b):
    """extended euclidean algorithm
    
    It is used to calculate the inverse mod 
    """
    if b == 0:
        return 1, 0, a
    else:
        x, y, gcd = ext_euclid(b,a % b)
        return y, x-y*(a//b), gcd

def inverse_mod(a,n):
    x, y, gcd = ext_euclid(a,n)
    if gcd == 1:
        return x % n
    else:
        return None

class RSA(object):
    def __init__(self, key_len = 1024):
        def gen_prime(key_len):
            """generate the prime
            """
            key_bit = int(key_len / 2)
            while True:
                p = random.getrandbits(key_bit)
                if miller_rabin(p):
                    break
            while True:
                q = random.getrandbits(key_bit)
                if miller_rabin(q):
                    break
            return p ,q
        def gen_key(phi):
            """generate the rsa key
            """
            e = 3
            while True:
                if math.gcd(e, phi) == 1:
                    d = inverse_mod(e, phi)
                    if d != None:
                        break
                e += 1
            return e, d
            
            
        self.p, self.q = gen_prime(key_len)
        self.n = self.p * self.q
        self.phi = (self.p - 1)*(self.q - 1)
        self.e, self.d = gen_key(self.phi)
        
        self.inverse_p = inverse_mod(self.p, self.q)
        
        self.d_p = self.d % (self.p - 1)
        self.d_q = self.d % (self.q - 1)
    
    def encrypt(self, plain):
        return fast_exp_mod(plain, self.e, self.n)

    def decrypt(self, cipher):
        x_p = fast_exp_mod(cipher, self.d_p, self.p)
        x_q = fast_exp_mod(cipher, self.d_q, self.q)
        u = ((x_q - x_p) * self.inverse_p) % self.q
        plain = x_p + self.p * u
        return plain
def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("plain", type=int, help="the plain ,which is used to encrypt")
    args = parser.parse_args()
    return args
def main():
    args = get_args()
    rsa = RSA()
    cipher = rsa.encrypt(args.plain)
    plain = rsa.decrypt(cipher)
    
    print("Origin Plain =", args.plain)
    print("Cipher =", cipher)
    print("Plain decrypted from cipher =", plain)
    print("Whether it is same as origin plain = ", plain == args.plain)

if __name__=="__main__":
    main()
    