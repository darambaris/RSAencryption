#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <string.h>


/* gera número aleatório na ordem de */

#define PNUMBERMIN 1000000000000
#define KPUBLICMIN 100

long long unsigned int randomPrimeNumber (){
	long long unsigned int number;
	long long unsigned int i;
	int isPrime = 0;

	number = (long long unsigned int) rand() + (PNUMBERMIN >> (5));
	
	do {

		/* se o número for par forçamos ele a ser ímpar */
		if (!number%2) number++;

		for (i=2; i<=(long long unsigned int)(sqrt(number)+1);i++){
			if (!(number%i)){
				number++;
				break;	
			} 
		}

		/* crivo de aristótenes */
	}while (i <= ((long long unsigned int)(sqrt(number)+1)));
		
	return number;
}

long long unsigned int MDC(long long unsigned int dividend, long long unsigned int divisor){
	long long unsigned int mdc,aux;
	
	do {
		aux = dividend%divisor;
		dividend = divisor;
		divisor = aux;
	} while (aux != 0);

	return dividend;
}

long long unsigned int randomKeyPublic (long long unsigned int FI){
	long long unsigned int keyPublic;

	do {
		keyPublic = (rand() % 20);
	} while (MDC(FI, KPUBLICMIN + rand() % FI) != 1);

	return keyPublic;
}

void encryptRSA(char *text, char *textEncrypted, long long unsigned int e, long long unsigned int n){
	int i,j;
	long long unsigned int aux,k;
	
	for (i=0; text[i] != '\0'; i++){
		
		aux = (int) text[i];
		aux -= 48;
		k = 1;
		for (j=1;j<e;j++){
			k = aux*k;
			k = k%n;
		}
		aux = k;
		aux += 48;
		textEncrypted[i] = (char) aux;
	}
	textEncrypted[i] = '\0';
}


int main (int argc, char **argv){
	long long unsigned int primeP, primeQ, nKeyPublic, ekeyPublic, functionFI;
	char text[30];
	char *textEncrypted;
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

	textEncrypted = malloc(sizeof(char)*strlen(text));

	encryptRSA(text,textEncrypted,ekeyPublic,nKeyPublic);

	printf("%llu \n",(long long unsigned int)textEncrypted);
	return 0;
}