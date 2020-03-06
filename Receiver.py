#!/usr/bin/env python
# coding: utf-8

# In[1]:


import numpy as np
from gmpy2 import mpz
import gmpy2
import sys
import math

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



def VigEncryption(key,plainText):

    lengthOfKey = len(key)
    cipherText = ""
    for i in range(len(plainText)):
        cipherText+=reverseMap[(letterMap[plainText[i]]+letterMap[key[i%lengthOfKey]])%36]
    return cipherText

def VigDecryption(key,text):
    cipherText = text
    lengthOfKey = len(key)
    plainText = ""
    for i in range(len(cipherText)):
        plainText+=reverseMap[(letterMap[cipherText[i]]-letterMap[key[i%lengthOfKey]])%36]

    return plainText


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

def ReceiveMessage(message,senderPublicKey,senderN,receiverPrivateKey,receiverN):
    decryptedByRSA = removeQa(decryption(message,receiverPrivateKey,receiverN,36))
    verifySignature = removeQa(decryption(decryptedByRSA,senderPublicKey,senderN,36))
    length = ""
    rest=""
    for i in verifySignature:
        if i.isdigit():
            length+=i
        else:
            rest+=i
    #print(rest)
    vignereKey = ""
    cipher = ""
    flag = 0
    for i in range(len(rest)):
        if flag<=int(length)-1:
            vignereKey+=rest[i]
        else:
            cipher+=rest[i]
        flag+=1
    #print(cipher)
    decryptionByVignere = VigDecryption(vignereKey,cipher)


    return decryptionByVignere

def main(message,userId,userFromSend):
    fp = open("publicKeys.txt","r")
    keys  = fp.readlines()
    fp.close()
    e=""
    n=""
    for i in keys:
        i = i.split("|")
        if i[0]==str(userFromSend):
            e = i[1]
            n = i[2]
            break
    fp = open("CAPublicKey","r")
    keys = fp.readlines()
    CAn = keys[0]
    CAe = keys[1]
    n = removeQa(decryption(n,CAe,CAn,36))
    e = removeQa(decryption(e,CAe,CAn,36))
    fp = open("privateKeyFor"+str(userId)+".txt","r")
    keys = fp.readlines()
    keys = keys[0].split("|")
    myD = removeQa(decryption(keys[0],CAe,CAn,36))
    myP = removeQa(decryption(keys[1],CAe,CAn,36))
    myQ = removeQa(decryption(keys[2],CAe,CAn,36))
    myN = removeQa(decryption(keys[3],CAe,CAn,36))
    #print(message)
    decryptedText = ReceiveMessage(message,int(e),int(n),int(myD),int(myN))
    #print("dec",decryptedText)
    fp = open("DecryptedMessage.txt","w")
    fp.write(str(decryptedText))
    fp.close()

if __name__=="__main__":
    userId = sys.argv[1]
    userFromSend = sys.argv[2]
    cipherText = sys.argv[3]
    fp = open(cipherText,"r")
    a = fp.read()
    #print(a)
    fp.close()
    main(a,userId,userFromSend)
