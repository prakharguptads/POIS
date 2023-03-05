from typing import Optional
import pandas as pd
import csv

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

with open("./inputs/cpa.csv", 'r') as file:
  heading = next(file)
  csvreader = csv.reader(file)
  ofile = open('./output/cpa.txt','r')
  out = ofile.read().split('\n')
  i=1
  for col in csvreader:
    a = CPA(int(col[0]),int(col[1]),int(col[2]),int(col[3]))
    temp = a.enc(col[4],int(col[5]))
    print(temp,out[i])
    if(temp == out[i]):
        print("True")
    print(a.dec(temp)==col[4])
    i+=1