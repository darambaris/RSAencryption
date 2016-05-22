/***********************************************************************************************************
Nome: Jéssika Darambaris Oliveira NUSP: 7961026
Professora: Kalinka
Criptografia com base no algoritmo RSA
Engenharia de Segurança - 2016
************************************************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <string.h>


/* constantes mínimas para geração dos números primos */
#define PNUMBERMIN 10
#define KPUBLICMIN 100

/* função que gera um número primo aleatório muito grande */
long long unsigned int randomPrimeNumber (){
	long long unsigned int number;
	long long unsigned int i;
	int isPrime = 0;

	/* utiliza a função rand() para C, desloca o valor mínimo em 5 para direita, para dar uma 'embaralhada" */
	number = (long long unsigned int) rand() + (PNUMBERMIN >> (5));
	
	/* verifica se o número gerado é um número primo */
	do {

		/* se o número for par forçamos ele a ser ímpar (já que pares muito grandes não são primos) */
		if (!number%2) number++;

		/* crivo de aristótenes - para verificar se um número é primo basta ver se é divisível por algum número 
		   até a sua raiz quadrada arredondando para cima */
		for (i=2; i<=(long long unsigned int)(sqrt(number)+1);i++){
			if (!(number%i)){
				number++; /* caso seja divisível, adicionamos 1 e verificamos o número seguinte */
				break;	
			} 
		}		
	} while (i <= ((long long unsigned int)(sqrt(number)+1))); // se o i foi até a raiz quadrada o número é primo.
		
	return number;
}

/* cálculo do MDC entre dois números passados por parâmetro */
long long unsigned int MDC(long long unsigned int dividend, long long unsigned int divisor){
	long long unsigned int mdc,aux;

	/* verifica o resto da divisão até que seja igual a zero */
	do {
		aux = dividend%divisor;
		dividend = divisor;
		divisor = aux;
	} while (aux != 0);

	return dividend;
}

/* gera uma chave pública, chamada de "e", onde  1 < e < fi, MDC(FI,e) = 1 */
long long unsigned int randomKeyPublic (long long unsigned int FI){
	long long unsigned int keyPublic;
	do {
		/* como FI é um número muito grande, para não existir overflow limitamos seu valor para no máximo 20 */
		keyPublic = (long long unsigned int) (rand() % 10);
	} while (MDC(FI, keyPublic) != 1); //executa até que o MDC(função fi, e) seja igual a 1
	return keyPublic;
}

/* função que encripta uma mensagem (text), a partir de uma chave pública (e,n) gerada aleatoriamente seguindo o 
algoritmo RSA e retorna um vetor de long long unsigned int, onde cada posição do vetor é um caracter */
void encryptRSA(char *text, long long unsigned int *intEncrypted, long long unsigned int e, long long unsigned int n, long long unsigned int size){
	int i,j;
	long long unsigned int *aux,k;
	aux = (long long unsigned int*) malloc (sizeof(long long unsigned int)*size);
	printf("size: %llu",size);
	for (i=0; text[i] != '\0'; i++){
		
		aux[i] = (long long unsigned int) text[i];
		aux[i] -= 48;
		//printf("%llu\n",(long long unsigned int)aux);	
		//printf("código letra:%llu\n",(long long unsigned int)aux[i]);
		
		k = 1;
		for (j=0;j<e;j++){
			k = aux[i]*k;
			k = k%n;
		}
		aux[i] = k;
		intEncrypted[i] = aux[i];
		//printf("código codificado letra:%llu\n",aux[i]);
	}
	free(aux);
}

/* função que calcula a privateKey para decriptar uma mensagem enviada, a partir da função FI e a chave pública e */ 
long long unsigned int privateKey(long long unsigned int e, long long unsigned int FI){
	long long unsigned int aux,rest,dividend;
	/* parte tradicional do algoritmo de Euclides */
	rest = FI;
	
	while (rest != 1) {
		aux = rest;
		dividend = (long long unsigned) e/rest;
		rest = (long long unsigned) e%rest;
		if (rest != 1) e = aux;
	} 

	//printf("\n private key: %llu %llu %llu %llu\n",(long long unsigned int)((1/e) + ((FI/e) * dividend))/e,dividend,e,rest);

	return((long long unsigned int)(1 + (FI * dividend))/e);
}

/* função que decripta uma mensagem em forma de vetor de long long unsigned int,
 a partir de uma chave privada (d,n) gerada a partir da função FI e da chave pública seguindo o 
algoritmo RSA e retorna uma string que representa o texto inicial, onde cada caracter equivale a uma posição do vetor decriptada. */
void decryptRSA(long long unsigned int privateKey, long long unsigned int *intEncrypted, char *textDecrypted, long long unsigned int n,long long unsigned int size){
	int i,j;
	long long unsigned int k;
	long long unsigned int *aux = (long long unsigned int*) malloc (sizeof(long long unsigned int)*size);

	printf("%llu",privateKey);
	
	for (i=0; i<size; i++){
		
		aux[i] = intEncrypted[i];
		//printf("%llu\n",(long long unsigned int)aux);
		
		printf("dec:código codificado letra:%llu\n",(long long unsigned int)aux[i]);
		
		k = 1;

		for (j=0;j<privateKey;j++){
			k = aux[i]*k;
			k = k%n;
		}
		aux[i] = k;
		// /aux += 65;
		textDecrypted[i] = (char) aux[i] + 48;
		printf("dec: código decodificado letra: %llu\n",(long long unsigned int)aux[i]);
	}
	textDecrypted[i] = '\0'; 
	free(aux);
}

void printaString (char *string){
	int i;
	printf("\n");
	for (i=0;string[i]!='\0';i++)
		printf("%c",string[i]);

}

int main (int argc, char **argv){
	long long unsigned int size, primeP, primeQ, nKeyPublic, ekeyPublic, functionFI, dprivateKey;
	char text[30], *textDecrypted;
	long long unsigned int *textEncrypted;
	srand(time(NULL));
		
	primeP = randomPrimeNumber();
	primeQ = randomPrimeNumber();
	
	printf("%llu %llu \n",randomPrimeNumber(),randomPrimeNumber());

	nKeyPublic = primeQ*primeP;

	functionFI = (primeP - 1)*(primeQ - 1);

	ekeyPublic = randomKeyPublic(functionFI);

	printf("%llu\n",ekeyPublic);

	scanf("%s",text);
	fflush(stdin);

	size = strlen(text);
	textEncrypted = (long long unsigned int *) malloc (sizeof(long long unsigned int)*size);
	textDecrypted = (char *) malloc (sizeof(char)*(size+1));
	
	encryptRSA(text,textEncrypted,ekeyPublic,nKeyPublic,size);

	dprivateKey = privateKey(ekeyPublic,functionFI);

	decryptRSA(dprivateKey,textEncrypted,textDecrypted,nKeyPublic,size);

	printaString(textDecrypted);
	
	free(textEncrypted);
	free(textDecrypted);

	return 0;
}