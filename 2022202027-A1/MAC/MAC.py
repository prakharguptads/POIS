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

with open("./inputs/mac.csv", 'r') as file:
  heading = next(file)
  csvreader = csv.reader(file)
  ofile = open('./output/mac.txt','r')
  out = ofile.read().split('\n')
  i=1
  for col in csvreader:
    a = MAC(int(col[0]),int(col[1]),int(col[2]),int(col[3]))
    temp = a.mac(col[4],int(col[5]))
    print(temp,out[i])
    print(a.vrfy(col[4], temp))
    if(temp == out[i]):
        print("True")
    i+=1