from typing import Optional
import pandas as pd
import csv

def xor(a, b):
    ans = ""

    for i in range(len(a)):
        if (a[i] == b[i]):
            ans += "0"
        else:
            ans += "1"

    return ans

class PRG:
    def __init__(self, security_parameter: int, generator: int,
                 prime_field: int, expansion_factor: int):
        """
        Initialize values here
        :param security_parameter: n (from 1ⁿ)
        :type security_parameter: int
        :param generator: g
        :type generator: int
        :param prime_field: p
        :type prime_field: int
        :param expansion_factor: l(n)
        :type expansion_factor: int
        """
        self.security_parameter = security_parameter
        self.generator = generator
        self.prime_field = prime_field
        self.expansion_factor = expansion_factor
        pass

    def generate(self, seed: int) -> str:
        """
        Generate the pseudo-random bit-string from `seed`
        :param seed: uniformly sampled seed
        :type seed: int
        """
        self.seed=seed
        ans = ""
        for i in range(self.expansion_factor):
            if(self.seed<(self.prime_field-1)/2):
                ans+="0"
            else:
                ans+="1"
            self.seed = pow(self.generator,self.seed,self.prime_field)#((self.generator**self.seed)%self.prime_field)
        return ans
        pass


class PRF:
    def __init__(self, security_parameter: int, generator: int,
                 prime_field: int, key: int):
        """
        Initialize values here
        :param security_parameter: 1ⁿ
        :type security_parameter: int
        :param generator: g
        :type generator: int
        :param prime_field: p
        :type prime_field: int
        :param key: k, uniformly sampled key
        :type key: int
        """
        self.security_parameter = security_parameter
        self.generator = generator
        self.prime_field = prime_field
        self.key = key
        pass

    def evaluate(self, x: int) -> int:
        """
        Evaluate the pseudo-random function at `x`
        :param x: input for Fₖ
        :type x: int
        """
        self.x= x
        self.key= int(self.key)
        self.x = bin(self.x).replace('0b','').zfill(self.security_parameter)
        out_len = 2*len(self.x)
        block_len = len(self.x)
        seed = self.key
        prg = PRG(security_parameter=self.security_parameter, generator=self.generator,
                  prime_field=self.prime_field,
                  expansion_factor=out_len)
        
        for i in range(len(self.x)):
            bits = prg.generate(seed)
            if((self.x)[i]=="0"):
                seed = int(bits[:block_len],2)
            else:
                seed = int(bits[block_len:],2)
        return seed
        pass


class Eavesdrop:
    def __init__(self, security_parameter: int, key: int, expansion_factor: int,
                 generator: int, prime_field: int):
        """
        Initialize values here
        :param security_parameter: 1ⁿ
        :type security_parameter: int
        :param key: k, uniformly sampled key
        :type key: int
        :param expansion_factor: l(n)
        :type expansion_factor: int
        :param generator: g
        :type generator: int
        :param prime_field: p
        :type prime_field: int
        """
        self.security_parameter = security_parameter
        self.generator = generator
        self.prime_field = prime_field
        self.expansion_factor = expansion_factor
        self.key = key
        prg = PRG(security_parameter=self.security_parameter, generator=self.generator,
                  prime_field=self.prime_field,
                  expansion_factor=self.expansion_factor)
        # print(type(self.key))
        self.key = prg.generate(int(self.key))
        pass

    def enc(self, message: str) -> str:
        """
        Encrypt Message against Eavesdropper Adversary
        :param message: message encoded as bit-string
        :type message: str
        """
        ans=""
        for i in range(len(message)):
            ans+=str(int(self.key[i])^int(message[i]))
        return ans
        pass

    def dec(self, cipher: str) -> str:
        """
        Decipher ciphertext
        :param cipher: ciphertext encoded as bit-string
        :type cipher: str
        """
        ans=""
        for i in range(len(cipher)):
            ans+=str(int(self.key[i])^int(cipher[i]))
        return ans
        pass


class MAC:
    def __init__(self, security_parameter: int, prime_field: int,
                 generator: int, seed: int):
        """
        Initialize the values here
        :param security_parameter: 1ⁿ
        :type security_parameter: int
        :param prime_field: q
        :type prime_field: int
        :param generator: g
        :type generator: int
        :param seed: k
        :type seed: int
        """
        self.security_parameter = security_parameter
        self.generator = generator
        self.prime_field = prime_field
        self.seed = seed
        pass

    def mac(self, message: str, random_identifier: int) -> str:
        """
        Generate tag t
        :param random_identifier: r
        :type random_identifier: int
        :param message: message encoded as bit-string
        :type message: str
        """
        prf = PRF(security_parameter=self.security_parameter, generator=self.generator,
                  prime_field=self.prime_field,
                  key=self.seed)
        ans=bin(random_identifier).replace('0b','').zfill(self.security_parameter//4)
        r=bin(random_identifier).replace('0b','').zfill(self.security_parameter//4)
        blocks=len(message)//(self.security_parameter//4)
        # print(blocks)
        for i in range (blocks):
            m = message[:int(self.security_parameter/4)]
            message = message[(self.security_parameter//4):]
            # print(i,m)
            jj = prf.evaluate(int(r+bin(blocks).replace('0b','').zfill(self.security_parameter//4)+bin(i+1).replace('0b','').zfill(self.security_parameter//4)+m,2))
            # r = bin(r).replace('0b','').zfill(self.security_parameter)
            # print("---",jj)
            ans+=bin(jj).replace('0b','').zfill(self.security_parameter)
            # print("---",r)
            # for j in range(0,self.security_parameter):
            #     k=int(r[j])
            #     ans+=str(k^int(message[self.security_parameter*i+j]))
        return ans
        pass

    def vrfy(self, message: str, tag: str) -> bool:
        """
        Verify whether the tag commits to the message
        :param message: m
        :type message: str
        :param tag: t
        :type tag: str
        """
        prf = PRF(self.security_parameter, self.generator, self.prime_field, self.seed)
        
        r = tag[:self.security_parameter//4]
        tags = tag[self.security_parameter//4:]

        n = len(tags)
        
        block_size = self.security_parameter//4
        d = len(message) // (self.security_parameter//4)

    
        d = bin(d).replace('0b','').zfill(self.security_parameter//4)
        
        
        for i in range(n // (self.security_parameter)):
            block = message[i*block_size: (i+1)*block_size]

            i1 = bin(i+1).replace('0b','').zfill(self.security_parameter//4)

            x = r + d + i1 + block
            t = prf.evaluate(int(x,2))

            t = bin(t).replace('0b','').zfill(self.security_parameter)
            l = len(t)
            
            if(t != tags[i*l: (i+1)*l]):
                return False

        return True
        pass


class CBC_MAC:
    def __init__(self, security_parameter: int, generator: int,
                 prime_field: int, keys: list[int]):
        """
        Initialize the values here
        :param security_parameter: 1ⁿ
        :type security_parameter: int
        :param generator: g
        :type generator: int
        :param prime_field: q
        :type prime_field: int
        :param keys: k₁, k₂
        :type keys: list[int]
        """
        self.security_parameter = security_parameter
        self.generator = generator
        self.prime_field = prime_field
        self.keys = keys
        pass

    def mac(self, message: str) -> int:
        """
        Message Authentication code for message
        :param message: message encoded as bit-string m
        :type message: str
        """
        t = ""
        t = t.zfill(self.security_parameter)
        # print(t)
        blocks=len(message)//(self.security_parameter)
        prf = PRF(security_parameter=self.security_parameter, generator=self.generator,
                  prime_field=self.prime_field,
                  key=self.keys[0])
        prf1 = PRF(security_parameter=self.security_parameter, generator=self.generator,
                  prime_field=self.prime_field,
                  key=self.keys[1])
        for i in range (blocks):
            m = message[:int(self.security_parameter)]
            message = message[(self.security_parameter):]
            ans=""
            for j in range(0,self.security_parameter):
                km=int(m[j])
                kt=int(t[j])
                ans+=str(km^kt)
            t=prf.evaluate(int(ans,2))
            t=bin(t).replace('0b','').zfill(self.security_parameter)
        t=prf1.evaluate(int(t,2))
        return t
        pass

    def vrfy(self, message: str, tag: int) -> bool:
        """
        Verify if the tag commits to the message
        :param message: m
        :type message: str
        :param tag: t
        :type tag: int
        """
        t = ""
        t = t.zfill(self.security_parameter)
        n = len(message)
        block_size = self.security_parameter
        d = n // block_size

        prf1 = PRF(self.security_parameter, self.generator, self.prime_field, self.keys[0])
        prf2 = PRF(self.security_parameter, self.generator, self.prime_field, self.keys[1])

        for i in range(d):
            block = message[i*block_size: (i+1)*block_size]
            ans = ""
            ans = xor(block, t)
            # print(i, ans)
            t = prf1.evaluate(int(ans, 2))
            t=bin(t).replace('0b','').zfill(self.security_parameter)
        
        t = prf2.evaluate(int(t,2))
        print("t: ", bin(t).replace('0b','').zfill(self.security_parameter))

        # return t
        if(t == tag):
            return True
        return False
        pass


class CPA:
    def __init__(self, security_parameter: int, prime_field: int,
                 generator: int, key: int, mode="CTR"):
        """
        Initialize the values here
        :param security_parameter: 1ⁿ
        :type security_parameter: int
        :param prime_field: q
        :type prime_field: int
        :param generator: g
        :type generator: int
        :param key: k
        :type key: int
        :param mode: Block-Cipher mode of operation
            - CTR
            - OFB
            - CBC
        :type mode: str
        """
        self.security_parameter = security_parameter
        self.generator = generator
        self.prime_field = prime_field
        self.mode = mode
        self.key = key
        pass

    def enc(self, message: str, random_seed: int) -> str:
        """
        Encrypt message against Chosen Plaintext Attack using randomized ctr mode
        :param message: m
        :type message: int
        :param random_seed: ctr
        :type random_seed: int
        """
        prf = PRF(security_parameter=self.security_parameter, generator=self.generator,
                  prime_field=self.prime_field,
                  key=self.key)
        ans=bin(random_seed).replace('0b','').zfill(self.security_parameter)
        for i in range (int(len(message)/self.security_parameter)):
            r = prf.evaluate(random_seed+i+1)
            r = bin(r).replace('0b','').zfill(self.security_parameter)
            # print("---",r)
            for j in range(0,self.security_parameter):
                k=int(r[j])
                ans+=str(k^int(message[self.security_parameter*i+j]))
        return ans
        pass

    def dec(self, cipher: str) -> str:
        """
        Decrypt ciphertext to obtain plaintext message
        :param cipher: ciphertext c
        :type cipher: str
        """
        c = cipher[self.security_parameter:]
        random_seed=int(cipher[:self.security_parameter],2)
        # print(random_seed)
        ans=""
        prf = PRF(security_parameter=self.security_parameter, generator=self.generator,
                  prime_field=self.prime_field,
                  key=self.key)
        for i in range (int(len(c)/self.security_parameter)):
            r = prf.evaluate(random_seed+i+1)
            r = bin(r).replace('0b','').zfill(self.security_parameter)
            # print("---",r)
            for j in range(0,self.security_parameter):
                k=int(r[j])
                ans+=str(k^int(c[self.security_parameter*i+j]))
        return ans
        pass


class CCA:
    def __init__(self, security_parameter: int, prime_field: int,
                 generator: int, key_cpa: int, key_mac: list[int],
                 cpa_mode="CTR"):
        """
        Initialize the values here
        :param security_parameter: 1ⁿ
        :type security_parameter: int
        :param prime_field: q
        :type prime_field: int
        :param generator: g
        :type generator: int
        :param key_cpa: k1
        :type key_cpa: int
        :param key_mac: k2
        :type key_mac: list[int]
        :param cpa_mode: Block-Cipher mode of operation for CPA
            - CTR
            - OFB
            - CBC
        :type cpa_mode: str
        """
        self.security_parameter = security_parameter
        self.generator = generator
        self.prime_field = prime_field
        self.mode = cpa_mode
        self.key_cpa = key_cpa
        self.key_mac = key_mac
        pass

    def enc(self, message: str, cpa_random_seed: int) -> str:
        """
        Encrypt message against Chosen Ciphertext Attack
        :param message: m
        :type message: str
        :param cpa_random_seed: random seed for CPA encryption
        :type cpa_random_seed: int
        """
        cpa = CPA(security_parameter=self.security_parameter, generator=self.generator,
                  prime_field=self.prime_field,
                  key=self.key_cpa)
        mac = CBC_MAC(security_parameter=self.security_parameter, generator=self.generator,
                  prime_field=self.prime_field,
                  keys=self.key_mac)
        cipher = cpa.enc(message,cpa_random_seed)
        tag = mac.mac(cipher)
        # print(tag,cipher)
        return cipher+bin(tag).replace('0b','').zfill(self.security_parameter)
        pass

    def dec(self, cipher: str) -> Optional[str]:
        """
        Decrypt ciphertext to obtain message
        :param cipher: <c, t>
        :type cipher: str
        """
        tag = cipher[-1*self.security_parameter:]
        c = cipher[:len(cipher)-self.security_parameter]
        cpa = CPA(self.security_parameter, self.prime_field, self.generator, self.key_cpa)
        p = cpa.dec(c)
        return p
        pass


with open("./inputs/mac.csv", 'r') as file:
  heading = next(file)
  csvreader = csv.reader(file)
  ofile = open('./output/mac.txt','r')
  out = ofile.read().split('\n')
  i=1
  for col in csvreader:
    a = MAC(int(col[0]),int(col[1]),int(col[2]),int(col[3]))
    temp = a.mac(col[4],int(col[5]))
    # print(temp,col[5])
    print(a.vrfy(col[4], temp))
    # if(temp == col[5]):
    #     print("True")
    # print(a.dec(temp)==col[4])
    i+=1

