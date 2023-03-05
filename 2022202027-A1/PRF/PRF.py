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

with open("./inputs/prf.csv", 'r') as file:
  heading = next(file)
  csvreader = csv.reader(file)
  ofile = open('./output/prf.txt','r')
  out = ofile.read().split('\n')
  i=0
  for col in csvreader:
    a = PRF(int(col[0]),int(col[2]),int(col[1]),int(col[3]))
    temp = a.evaluate(int(col[4]))
    print(temp,out[i])
    if(temp == out[i]):
        print("True")
    i+=1