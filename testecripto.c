#include <stdio.h>

#include <stdlib.h>
#include <math.h>
#include <string.h>

void encryptRSA(char *text, long long unsigned int *intEncrypted, long long unsigned int e, long long unsigned int n){
	int i,j;
	long long unsigned int aux[strlen(text)],k;
	
	for (i=0; text[i] != '\0'; i++){
		
		aux[i] = (long long unsigned int) text[i];
		aux[i] -= 65;
		//printf("%llu\n",(long long unsigned int)aux);	
		printf("código letra:%llu\n",(long long unsigned int)aux[i]);
		
		k = 1;
		for (j=0;j<e;j++){
			k = aux[i]*k;
			k = k%n;
		}
		aux[i] = k;
		intEncrypted[i] = aux[i];
		printf("código codificado letra:%llu\n",aux[i]);
	}
}


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

	printf("%llu %llu %llu %llu\n",FI,dividend,e,rest);

	return((long long unsigned int)(1 + (FI * dividend))/e);
}

void decryptRSA(long long unsigned int privateKey, long long unsigned int *intEncrypted, char *textDecrypted, long long unsigned int n,unsigned int size){
	int i,j;
	long long unsigned int k;
	printf("size: %u",size);
	long long unsigned int *aux = malloc (sizeof(long long unsigned int)*size);

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
		textDecrypted[i] = (char) aux[i] + 65;
		printf("dec: código decodificado letra: %llu\n",(long long unsigned int)aux[i]);
	}
	textDecrypted[i] = '\0';

}

void printaString (char *string){
	int i;
	for (i=0;string[i]!='\0';i++)
		printf("%c",string[i]);

}
int main(int argc, char **argv){
	long long unsigned int e,FI,n;

	e = 13;
	FI =640;
	n = 697;
	char text[20]={'T','U','R','I','N','G','\0'};
	char decr[20];
	long long unsigned int *cifra;
	unsigned int size = strlen(text);
	cifra = malloc (sizeof (long long unsigned int)*strlen(text));
	encryptRSA(text,cifra,e,n);
	decryptRSA(privateKey(e,FI),cifra,decr,n,size);
	printf("%llu",privateKey(e,FI));	
	printaString(decr);
	return 0;
}