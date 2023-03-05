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

with open("./inputs/eav.csv", 'r') as file:
  heading = next(file)
  csvreader = csv.reader(file)
  ofile = open('./output/eav.txt','r')
  out = ofile.read().split('\n')
  i=1
  for col in csvreader:
    a = Eavesdrop(int(col[0]),int(col[1]),int(col[2]),int(col[3]),int(col[4]))
    temp = a.enc(col[5])
    # print(temp,out[i])
    if(temp == out[i]):
        print("True")
    # print(a.dec(temp)==col[5])
    i+=1