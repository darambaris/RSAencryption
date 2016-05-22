import random
from math import sqrt
from math import pow
from array import array
PMINBITS = pow(10,6);
PMAXBITS = pow(10,8);


# funcao que gera um numero primo aleatorio muito grande 
def randomPrimeNumber():
	#PROBLEMA PARTE1
	number = random.randint(100,1000)
	
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
		eKeyPublic = random.randint(65537,(FI-1));
		if (MDC(FI,eKeyPublic) == 1):
			break
	
	return eKeyPublic


def encryptRSA(text,e,n):
	textEncrypted = []
	for i in xrange(0,len(text)):
		
		textEncrypted.append(ord(text[i]))
		

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
	textDecrypted = []
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
		textDecrypted.append(chr(aux[i])) 
		
	return textDecrypted
"""
def calculateW(w):
	for (i in range(0,7)):
		resultW = keyW[i]
	return resultW	

def BetaPublicKey(w,q,r):
	Bkey = []
	for (i in range(0,7)):
		Bkey[i] = mod(w[i]*r,q)

	return Bkey
"""	
""" 
    keyW = [2,7,11,21,42,89,180,354]
    
    sumW = calculateW(keyW)

    keyQ = random.randint((sumW+1),sumW*10)
    keyR = random.randint(1,(sumW-1))
    keyB = BetaPublicKey(keyW,keyQ, keyR)
"""

def main():
    text = 'the first time that i program in python'
    primeP = randomPrimeNumber()
    primeQ = randomPrimeNumber()

    nKeyPublic = primeP*primeQ
    functionFI = (primeP - 1)*(primeQ -1)

  
    eKeyPublic = randomKeyPublic(functionFI)

	#textEncryptedKnapSack = encryptKnapSack (keyB,text)

    textEncrypted = encryptRSA(text,eKeyPublic,nKeyPublic)
    
    dprivateKey = privateKey(eKeyPublic,functionFI,1)

  
    textDecrypted = decryptedRSA(dprivateKey,textEncrypted,nKeyPublic)
   

    print textDecrypted 
main()	