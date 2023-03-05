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

with open("./inputs/cbc_mac.csv", 'r') as file:
  heading = next(file)
  csvreader = csv.reader(file)
  ofile = open('./output/cbc_mac.txt','r')
  out = ofile.read().split('\n')
  i=1
  for col in csvreader:
    a = CBC_MAC(int(col[0]),int(col[1]),int(col[2]),[int(col[3]),int(col[4])])
    temp = a.mac(col[5])
    print(temp,out[i])
    print(a.vrfy(col[5], temp))
    # if(temp == out[i]):
    #     print("True")
    i+=1