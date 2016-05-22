''' **************************************************************************************************************************
	Nome: Jessika Darambaris Oliveira NUSP: 7961026
	Professora: Kalinka Regina Lucas Jaquie Castelo Branco
	Disciplina: Engenharia de Seguranca  Ano: 2016
	Trabalho: Consiste na implementacao hibrida do algoritmo RSA juntamente com o algoritmo  
	Merkle-Hellman Knapsack baseado no problema da mochila (knapsack)

	Passos:	
		Dado um arquivo texto de entrada e uma chave no intervalo de [1,706] temos:
		Texto encriptado pelo algoritmo baseado no problema da mochila (snapback) 
		O texto encriptado pelo knapsack eh encriptado pelo algoritmo RSA
		Esse novo texto encriptado eh salvo em um arquivo binario
		O texto desse arquivo eh recuperado e desencriptado pelo algoritmo RSA
		O resultado da desencriptacao do algoritmo RSA eh desencriptado pelo algoritmo knapsack
		O resultado da segunda desencriptacao eh o texto plano que eh salvo em outro arquivo

	Chaves do algoritmo knapsack:

		privadas: 
			vetor de 8 posicoes w com valores fixos que representa os pesos de cada bit do char
			r, sendo 1 < r < 706 (soma dos valores de w), essa chave eh definida pelo usuario na entrada
			q, sendo 706 < q < 7060, essa chave eh definida aleatoriamente dentro desse intervalo

		publicas:
			vetor de 8 posicoes B que eh obtido a partir de Bi = wi*r mod q

	Chaves do algoritmo RSA:
	
		privadas:
			p e q, numeros primos gerados aleatoriamente que definem a funcao FI
			d, obtido a a partir do inverso modular de = 1 mod FI
		publicas:
			n, n = p*q
			e,  1<e<FI tal que e, n sejam primos entre si	
*************************************************************************************************************************** ''' 
import random
from math import sqrt
from array import array
import sys
import codecs
#definir aqui a grandeza dos numeros p e q primos gerados aleatoriamente
# obs: quanto maior esses numeros, menor eh o desempenho, e consequentemente, mais demorado fica o algoritmo
PMINBITS = 100
PMAXBITS = 1000

#chave privada fixa para o algoritmo knapsack  
KEYW = [2,7,11,21,42,89,180,354]

''' *************************************************************************************************************************** 
As funcoes abaixo sao funcoes auxiliares para o desenvolvimento dos algoritmos de criptografia
*************************************************************************************************************************** '''

# funcao que retorna o MDC entre dois numeros, obtida pela base do algoritmo de Euclides  
def MDC(a, b):
    a = abs(a)
    b = abs(b)
    if a < b:
        a, b = b, a
    while b != 0:
        a, b = b, a % b
    return a

# funcao que retorna o resto de uma divisao, levando em consideracao os numeros negativos 
def mod(a,b):
	rest = a%b
	if (rest < 0 and b>0):
		return (b+rest)
	if (rest > 0 and b<0):
		return (b+rest)
	return rest	

# funcao que aplica o metodo de Euclides extendido para encontrar o inverso modular de dois numeros
def privateKey(a,b,const): 
  rest = mod(b,a) 
  if(rest == 0):
  	return mod((const/a),(b/a))
  return ((privateKey(rest,a,-const)*b + const) / mod(a,b))

''' *************************************************************************************************************************** 
As funcoes abaixo sao para encriptar e desencriptar o algoritmo knapsack
*************************************************************************************************************************** '''
# funcao que converte no Python um caracter em bits (utilizado para o algoritmo knapsack)
def tobits(s):
    result = []
    for c in s:
        bits = bin(ord(c))[2:] # converte para binario tirando os dois primeiros caracteres '0b'
        bits = '00000000'[len(bits):] + bits # aplica mascara de 8 bits para char
        result.extend([int(b) for b in bits])
    return result

# funcao que converte uma sequencia de bits em char (utilizado para o algoritmo knapsack)
def frombits(bits):
    chars = []
    for b in range(len(bits) / 8):
        byte = bits[b*8:(b+1)*8] # calculo para obter um caracter de 8 bits
        chars.append(chr(int(''.join([str(bit) for bit in byte]), 2))) # conversao para char
    return ''.join(chars)

# determina a posicao do maior numero contido no vetor w que seja menor do que 'num" (utilizado pelo algorimto knapsack)
def maxPosition (vecW,num):
	pos = 0
	for i in xrange(0,8):
		if (vecW[i] <= num and vecW[i]>vecW[pos]): 
			pos = i
	return pos	  

#calcula a soma dos valores do vetor W
def calculateW(w):
	resultW = 0
	for i in xrange(0,8):
		resultW += w[i]
	return resultW	

# define a chave publica B 
def BetaPublicKey(w,q,r):
	Bkey = []
	for i in xrange(0,8):
		# Bi = wi*r mod q
		Bkey.append(mod(w[i]*r,q))

	return Bkey

#encripta o texto com o algoritmo knapsack	
def encryptKnapSack (keyB,text):
	binary = []
	sumBinary = 0
	textEncrypted = []
	print "encrypting text by KnapSack.... \n"
	# pega caracter por caracter do texto
	for i in xrange(0,len(text)):
		b = tobits(text[i]) #transforma o caracter em binario
		sumBinary = 0
		# multiplica cada bit pela posicao correspondente no vetor B
		for j in xrange(0,8):
			sumBinary += keyB[j]*int(b[j])  #soma todos os valores 
		textEncrypted.append(sumBinary) # o caracter encriptado eh a soma dos valores onde o bit eh 1 * posicao_do_vetor B
	return textEncrypted 
	
#decripta um texto encriptado pelo KnapSack
def decryptKnapSack (r,q,textEncrypted,w):
	# calcula a private key, pelo mesmo metodo RSA do inverso modular, pelo algoritmo extendido de Euclides
	pK = privateKey(r,q,1)
	textDecrypted = []
	print "decrypting text by Knapsack.... \n"
	for i in xrange(0,len(textEncrypted)):
		# aux = c*(r^-1) mod q - onde r^-1 eh o inverso modular
		aux = mod(textEncrypted[i]*pK,q)
		b = tobits(chr(0)) #transforma b em uma variavel de 8 bits preenchida de zeros
		while (aux > 0):
			# para decifrarmos a mensagem, dividimos o valor de aux sempre pelo maior valor encontrado em w que seja menor do que aux
			# a posicao desse valor tem seu bit mudado para 1 na variavel b
			# retira-se esse valor de aux ateh que aux fique 0, entao temos todos os bits que deveriam ser 1  
			pos = maxPosition(w,aux) 
			b[pos] = 1
			aux = aux-w[pos]		
		textDecrypted.append(frombits(b))
	return textDecrypted	 

''' *************************************************************************************************************************** 
As funcoes abaixo sao para encriptar e desencriptar o algoritmo RSA
*************************************************************************************************************************** ''' 
 # -*- coding: cp860 -*-
# funcao que gera um numero primo aleatorio
def randomPrimeNumber():
	#gera numero no intervalo definido pelas constantees PMINBITS/PMAXBITS
	number = random.randint(PMINBITS,PMAXBITS)
	
	while True:
		if (int(number%2) == 0): #verifica se eh par
			number = number + 1

		i = 2		
		# crivo de aristotenes: se um numero nao for divisivel ateh sua raiz quadrada ele eh primo 
		while int(i<=(sqrt(number)+1)): 
			if (int(number%i) == 0):  # se for divisivel por algum numero, escolhemos o numero posterior
				number +=1			  # ate encontrar um primo 
				break
			i += 1	
		
		if (i > sqrt(number)):	#caso n tenha encontrado numero divisivel, retorne
			break

	return number

#funcao que define a chave publica e 
def randomKeyPublic(FI):
	while True:
		# depois ver como fica o role da chave
		# 65537,(FI-1)
		eKeyPublic = random.randint(2,20);
		if (MDC(FI,eKeyPublic) == 1): #chama a funcao de euclides, caso o MDC seja 1, eles sao primos entre si
			break
	
	return eKeyPublic

# funcao que devolve uma mensagem cifrada pelo algoritmo RSA, a partir de um texto passado por parametro 
def encryptRSA(text,e,n):
	textEncrypted = []
	print "encrypting text by RSA.... \n"
	for i in xrange(0,len(text)):
		# nao convertemos text[i] para int, pois ele ja esta encriptado pelo algoritmo knapsack
		textEncrypted.append(text[i])
		k = 1
		# c = m^e mod n
		for j in xrange(0,e):
			k = k*textEncrypted[i]
			k = k%n			
		textEncrypted[i] = k
	return textEncrypted	
	
# funcao que devolve uma mensagem decriptada pelo algotimo RSA
def decryptedRSA(privateKey,textEncrypted,n):
	aux = []
	print "decrypting text by RSA.... \n"
	for i in xrange(0,len(textEncrypted)):
		# textEncrypted temos o texto cifrado em RSA
		aux.append(textEncrypted[i])
		k = 1
		j = 1
		# m = c^d mod n
		while (j<=privateKey):
			k = k*aux[i]
			k = k%n
			j += 1
		aux[i] = int(k) 	
	return aux

''' *************************************************************************************************************************** 
As funcoes abaixo sao para manipulacoes com arquivo
*************************************************************************************************************************** ''' 
#escreve em um arquivo, um texto passado por parametro
def writeFile(text,filename,mode):
	f = open(filename,mode)
	i = 0
	while (i<len(text)):
		if(mode == 'wb'):
			f.write(str(len(str(text[i]))))
		f.write(str(text[i]))
		i+=1
	f.close()

#le um arquivo ja existente
def readFile(filename,mode):
	# para textos binarios que estao criptografados
	if (mode == "rb"):
		textEncrypted = []
		f = open(filename,mode)
		j = 0
		f.seek(0,2)
		sizetam = f.tell()
		f.seek(0,0)
		while (f.tell()<sizetam):
			size = int(f.read(1))
			j+=1	
			textEncrypted.append(int(f.read(size)))
			j+=size
	# para textos planos de entrada
	else: 
		f = open(filename,mode)
		textEncrypted = str(f.read())
	
	f.close()
	
	return textEncrypted

''' *************************************************************************************************************************** 
MAIN()
*************************************************************************************************************************** ''' 

def main():
	sumW = calculateW(KEYW) #soma dos valores contidos no vetor chave privada w
	#verifica parametros de entrada
	if (len(sys.argv) < 3):
		sys.stderr.write('Usage: filename.extention key')
    	#sys.exit(1)

	if ((int(sys.argv[2]) > sumW)or((int(sys.argv[2]) < 1))):
		sys.stderr.write('The key must be range [1,%d]' %sumW)
    	#sys.exit(1)
    
	
	text = str(readFile(sys.argv[1],"r"))

	#para executar o algoritmo RSA calculamos:
	primeP = randomPrimeNumber() # primo P
	primeQ = randomPrimeNumber() # primo Q
	nKeyPublic = primeP*primeQ # chave publica n
	functionFI = (primeP - 1)*(primeQ -1) # funcao FI
	eKeyPublic = randomKeyPublic(functionFI) # chave publica e
	dprivateKey = privateKey(eKeyPublic,functionFI,1) #chave privada d

	#para executar o algoritmo KnapSack calculamos:
	keyR = int(sys.argv[2]) #chave privada r definida na entrada 
	keyQ = random.randint((sumW+1),sumW*10) #chave privada q
	keyB = BetaPublicKey(KEYW,keyQ, keyR) #vetor chave publica B

	#encripta o texto plano com o algoritmo KnapSack    
	textEncryptedKnapSack = encryptKnapSack (keyB,text)
	#encripta o texto cifrado pelo KnapSack com o algoritmo RSA
	textEncrypted = encryptRSA(textEncryptedKnapSack,eKeyPublic,nKeyPublic)
	#grava no arquivo o texto criptado pelos dois algoritmos
	writeFile(textEncrypted,"encrypt_"+sys.argv[1].split(".")[0]+".enc","wb")
	#le no arquivo o texto criptado pelos dois algoritmos
	textEncrypted = readFile("encrypt_"+sys.argv[1].split(".")[0]+".enc","rb")
	#decripta o texto primeiro com o algoritmo RSA
	textDecrypted = decryptedRSA(dprivateKey,textEncrypted,nKeyPublic)
	#decripta o texto com o algoritmo KnapSack
	textDecryptedKnapSack = decryptKnapSack (keyR,keyQ,textDecrypted,KEYW)
	#escreve em um segundo arquivo o texto plano decriptado
	writeFile(textDecryptedKnapSack,"decrypt_"+sys.argv[1],"w")
	print "Finished!! :)"
main()	