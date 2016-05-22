import random
import binascii
from math import sqrt
from math import pow
from array import array
PMINBITS = 100
PMAXBITS = 1000


# funcao que gera um numero primo aleatorio muito grande 
def randomPrimeNumber():
	#PROBLEMA PARTE1
	number = random.randint(PMINBITS,PMAXBITS)
	
	while True:
		if (int(number%2) == 0):
			number = number + 1

		i = 2		
		while int(i<=(sqrt(number)+1)): 
			if (int(number%i) == 0):
				number +=1
				break
			i += 1	
		
		if (i > sqrt(number)):
			break

	return number




def MDC(a, b):
    """returns the Greatest Common Divisor of a and b"""
    a = abs(a)
    b = abs(b)
    if a < b:
        a, b = b, a
    while b != 0:
        a, b = b, a % b
    return a

def randomKeyPublic(FI):
	while True:
		# depois ver como fica o role da chave
		# 65537,(FI-1)
		eKeyPublic = random.randint(2,20);
		if (MDC(FI,eKeyPublic) == 1):
			break
	
	return eKeyPublic


def encryptRSA(text,e,n):
	textEncrypted = []
	for i in xrange(0,len(text)):
		
		textEncrypted.append(text[i])
		

		k = 1

		for j in xrange(0,e):
			k = k*textEncrypted[i]
			k = k%n
			
		textEncrypted[i] = k

	return textEncrypted	

def mod(a,b):
	rest = a%b
	if (rest < 0 and b>0):
		return (b+rest)
	if (rest > 0 and b<0):
		return (b+rest)

	return rest		

def privateKey(e,FI,const):
   
  rest = mod(FI,e) 

  if(rest == 0):
  	return mod((const/e),(FI/e))

  return ((privateKey(rest,e,-const)*FI + const) / mod(e,FI))


def decryptedRSA(privateKey,textEncrypted,n):
	aux = []
	
	for i in xrange(0,len(textEncrypted)):
		
		aux.append(textEncrypted[i])
		k = 1
		j = 1
		while (j<=privateKey):
			k = k*aux[i]
			k = k%n
			j += 1

		aux[i] = int(k) 
		
	return aux

def calculateW(w):
	resultW = 0
	for i in xrange(0,8):
		resultW += w[i]
	return resultW	

def BetaPublicKey(w,q,r):
	Bkey = []
	for i in xrange(0,8):
		Bkey.append(mod(w[i]*r,q))

	return Bkey



def tobits(s):
    result = []
    for c in s:
        bits = bin(ord(c))[2:]
        bits = '00000000'[len(bits):] + bits
        result.extend([int(b) for b in bits])
    return result

def frombits(bits):
    chars = []
    for b in range(len(bits) / 8):
        byte = bits[b*8:(b+1)*8]
        chars.append(chr(int(''.join([str(bit) for bit in byte]), 2)))
    return ''.join(chars)
	
def encryptKnapSack (keyB,text):
	binary = []
	sumBinary = 0
	textEncrypted = []
	for i in xrange(0,len(text)):
		b = tobits(text[i])
		sumBinary = 0
		for j in xrange(0,8):
			sumBinary += keyB[j]*int(b[j])
		textEncrypted.append(sumBinary)
	return textEncrypted

def maxPosition (vecW,num):
	pos = 0
	for i in xrange(0,8):
		if (vecW[i] <= num and vecW[i]>vecW[pos]): 
			pos = i
	return pos		

def decryptKnapSack (r,q,textEncrypted,w):
	pK = privateKey(r,q,1)
	textDecrypted = []
	for i in xrange(0,len(textEncrypted)):
		aux = mod(textEncrypted[i]*pK,q)
		print aux
		b = tobits(chr(0))
		while (aux > 0):
			pos = maxPosition(w,aux)
			print "pos: ",pos
			b[pos] = 1
			aux = aux-w[pos]
			
		textDecrypted.append(frombits(b))

	return textDecrypted

def main():
    text = 'Allan Turing'
    primeP = randomPrimeNumber()
    primeQ = randomPrimeNumber()

    nKeyPublic = primeP*primeQ
    functionFI = (primeP - 1)*(primeQ -1)
 	
    keyW = [2,7,11,21,42,89,180,354]
    
    sumW = calculateW(keyW)

    #keyQ = random.randint((sumW+1),sumW*10)
    keyQ = 881
    #keyR = random.randint(1,(sumW-1))
    keyR = 588
    keyB = BetaPublicKey(keyW,keyQ, keyR)

    print keyB

    eKeyPublic = randomKeyPublic(functionFI)
    textEncryptedKnapSack = encryptKnapSack (keyB,text)

    print textEncryptedKnapSack
    print privateKey(keyR,keyQ,1)

    
    textEncrypted = encryptRSA(textEncryptedKnapSack,eKeyPublic,nKeyPublic)
    
    dprivateKey = privateKey(eKeyPublic,functionFI,1)

  
    textDecrypted = decryptedRSA(dprivateKey,textEncrypted,nKeyPublic)
    
    textDecryptedKnapSack = decryptKnapSack (keyR,keyQ,textDecrypted,keyW)

    print textDecryptedKnapSack

    
main()	