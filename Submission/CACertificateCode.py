#!/usr/bin/env python
# coding: utf-8


import gmpy2
import random
from gmpy2 import mpz,is_strong_prp,is_strong_lucas_prp
import math
import sys


letterMap={}
letterMap['a']=0

reverseMap={}
reverseMap[0]='a'

for i in range(1,26):
    letterMap[chr(97+i)]=i
    reverseMap[i]=chr(97+i)

for i in range(0,10):
    reverseMap[26+i]=str(i)
    letterMap[str(i)] = 26+i



def generateTwoStrongPrimes():
    numberOfPrimes = 2
    strongPrimes=[]
    while numberOfPrimes>0:
        initial="1"
        count = 5
        for i in range(0,510):
            initial+=str(random.randint(0,1))
        initial+="1"
        first=int(initial,2)

        while not gmpy2.is_prime(first):
            first = gmpy2.next_prime(first)
        second = gmpy2.next_prime(first)
        while not gmpy2.is_prime(second):
            second = gmpy2.next_prime(second)
        while True:
            third = gmpy2.next_prime(second)
            while not gmpy2.is_prime(third):
                third = gmpy2.next_prime(third)
            if (first+third)/2 < second and gmpy2.is_prime((second-1)//2):
                strongPrimes.append(second)
                numberOfPrimes-=1
                break
            else:
                count-=1
                if count==0:
                    break
                first = second
                second=third
    return strongPrimes


def encryption(text,e,n,base):
    blockSize=int(math.floor(math.log(int(n),36)))
    for i in range(0,blockSize-len(text)%blockSize):
        text+='q'
    flag=0
    a=0
    cipherText1 = ""
    out = ""
    bs = []
    for i in range(0,len(text),blockSize):
        bs.append(text[i:i+blockSize])
    for j in bs:
        #print(j)
        a=0
        for i in range(len(j)-1,-1,-1):
            a += letterMap[str(j[i])]*pow(36,i)
            flag+=1
        cipherText = gmpy2.powmod(a,int(e),int(n))
        back = cipherText
        ab = []
        for i in range(blockSize,-1,-1):
            ab.append(math.floor(back/pow(base,i)))
            back = back % pow(base,i)

        for i in ab:
            cipherText1 +=reverseMap[i]


    return cipherText1[::-1]

def decryption(text,d,n,base):

    cipherText1 = ""
    bs=[]

    blockSize=int(math.floor(math.log(int(n),36)))+1
    for i in range(0,len(text),blockSize):
        bs.append(text[i:i+blockSize])
    for j in bs:
        a=0
        for i in range(len(j)-1,-1,-1):
            a += letterMap[j[i]]*pow(36,i)
        ab=[]

        it = pow(a,int(d),int(n))
        back = it
        for i in range(blockSize-2,-1,-1):
            ab.append(math.floor(back/pow(base,i)))
            back = back % pow(base,i)

        for i in ab:
            cipherText1 +=reverseMap[int(i)%36]

    return cipherText1[::-1]

def removeQa(text):
    text1=""

    for i in range(len(text)-1,-1,-1):
        if text[i]!='q':
            text = text[0:i+1]
            break
    return text

def saveForUser(userId,CAn,CAPrivateKey,a,e1):

    strongPrimes = a
    p = strongPrimes[0]
    q = strongPrimes[1]
    n = p*q
    phin = (p-1)*(q-1)
    while True:
        initialNo=""
        for i in range(0,156):
            initialNo+=str(random.randint(1,9))

        e  = int(initialNo)
        if gmpy2.gcd(e,phin)==1:
            break
    d = gmpy2.invert(e,phin)
    pubKeyEnc = encryption(str(e),CAPrivateKey,CAn,36)
    NEnc = encryption(str(n),CAPrivateKey,CAn,36)
    priKeyEnc = encryption(str(d),CAPrivateKey,CAn,36)
    pEnc = encryption(str(p),CAPrivateKey,CAn,36)
    qEnc = encryption(str(q),CAPrivateKey,CAn,36)

    toSaveInPrivateFile = str(priKeyEnc)+"|"+str(pEnc)+"|"+str(qEnc)+"|"+str(NEnc)
    toSaveInPublicFile = str(userId)+"|"+str(pubKeyEnc)+"|"+str(NEnc)


    with open("publicKeys.txt", "a") as myfile:
        myfile.write(toSaveInPublicFile+"|\n")
    with open("privateKeyFor"+str(userId)+".txt", "w") as myfile:
        myfile.write(toSaveInPrivateFile+"|\n")


def main(a,userId):
#     userId = sys.argv[1]
    fp = open("CAPublicKey","r")
    publicKey = fp.readlines()
    fp.close()
    fp = open("CAPrivateKey","r")
    privateKey = fp.readlines()
    fp.close()
    n = int(publicKey[0].replace("\n",""))
    e = int(publicKey[1].replace("\n",""))
    d = int(privateKey[2].replace("\n",""))
    saveForUser(userId,n,d,a,e)


# In[16]:


if __name__=="__main__":
    userId = sys.argv[1]
    a = generateTwoStrongPrimes()
    main(a,userId)
    #print("Public Key Stored in publickeys.txt and Private Key stored in privatekeyFor<userid>.txt")
