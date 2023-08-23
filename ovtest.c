#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void overflow(const char * input){
	char buf[256];
	printf("vadr buf = 0x%p\n",buf);
	strcpy(buf,input);

}

void attack(){
	printf("ovf works\n");
}

/*
TESTED TO WORK ON KALI LINUX
..........████████████████......
........█████████████████████...
......████████████████████████..
......█████████████████████████.
....████████████████████████████
....████████████████████████████
....████████▒▒██▒▒██▒▒██████████
....██████▒▒░░██░░██░░██▒▒██ █ █
.....███▒▒░░░░░░░░░░░░░░░░███ ██
......██▒▒░░░░░░░░░░░░░░░░██ █ █
.......███░░████░░░░████▒▒██████
........██▒▒░░░░░░░░░░▒▒▒▒██████
............▓▓████████▓▓...████.
.........▒▒▒▓▓▓▓▓▓▓▓▓▓▓▒▒▒..██..
........▒▒▒▒▒▒▒▒██▒▒▒▒▒▒▒▒......
........▓▓▓▓██▒▒▒▒▒▒▒▒▓▓▓▓▓▓....
........▓▓▓▓▒▒██████▒▒▓▓▓▓▓▓....
......▓▓▓▓▓▓▒▒██▒▒▒▒▒▒▓▓▓▓▓▓▓▓..
......▓▓▓▓▒▒▒▒▒▒██▒▒▒▒▒▒▒▒▓▓▓▓..
....░░▒▒▒▒▒▒▒▒██▒▒▒▒▒▒▒▒▒▒▒▒▒▒░░
....░░░░▒▒▒▒▒▒▒▒██▒▒▒▒▒▒▒▒▒▒░░░░
........▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒....
......████░░░░░░████░░░░░░████..
....██░░░░░░░░░░████░░░░░░░░░░██
....████░░░░░░████████░░░░░░████
......████████████████████████..

*/

int main(int argc, char *argv[]){
	printf("ovf vadr = %p\n",overflow);
	printf("att vadr = %p\n",attack);
	
	// convert from address to string
	// 0x55 55 55 55 51 f9 = 14 chars long
	char conv[14];
	sprintf(conv,"%p",attack);
	printf("conv = %s\n",conv);
	printf("char1 = %c\n",conv[2]);

	// conversion string -> shellcode
	char scc;
	
	char *convsum = (char *) malloc(sizeof(char)*6);  // we use the malloc method instead of array, thus it will not have a null terminator?
	// 12 / 2 -> 6, we only need 6 chars: '\x55' ... '\xf9' 
	int cht2 = 5; // convsum[5 to 0] is 6 chars
	
	for(int cht =2; cht < 13; cht+=2){ // cutoff '0x'start so: 0x55 55 55 55 51 f9 -> 55 55 55 55 51 f9
	// 'convsum' values will be configured from "end to start" with "start to end" values of 'conv' resulting in: f9 51 55 55 55 55
	// \/ does ie: convert '5','5' to '\x55'
	switch(conv[cht]){
		case '0':
			switch(conv[cht+1]){
				case '0':
					scc = '\x00';
					break;
				case '1':
					scc = '\x01';
					break;
				case '2':
					scc = '\x02';
					break;
				case '3':
					scc = '\x03';
					break;
				case '4':
					scc = '\x04';
					break;
				case '5':
					scc = '\x05';
					break;
				case '6':
					scc = '\x06';
					break;
				case '7':
					scc = '\x07';
					break;
				case '8':
					scc = '\x08';
					break;
				case '9':
					scc = '\x09';
					break;
				case 'a':
					scc = '\x0a';
					break;
				case 'b':
					scc = '\x0b';
					break;
				case 'c':
					scc = '\x0c';
					break;
				case 'd':
					scc = '\x0d';
					break;
				case 'e':
					scc = '\x0e';
					break;
				case 'f':
					scc = '\x0f';
					break;
				
				default :
					break;
			}
			break;
		case '1':
			switch(conv[cht+1]){
				case '0':
					scc = '\x10';
					break;
				case '1':
					scc = '\x11';
					break;
				case '2':
					scc = '\x12';
					break;
				case '3':
					scc = '\x13';
					break;
				case '4':
					scc = '\x14';
					break;
				case '5':
					scc = '\x15';
					break;
				case '6':
					scc = '\x16';
					break;
				case '7':
					scc = '\x17';
					break;
				case '8':
					scc = '\x18';
					break;
				case '9':
					scc = '\x19';
					break;
				case 'a':
					scc = '\x1a';
					break;
				case 'b':
					scc = '\x1b';
					break;
				case 'c':
					scc = '\x1c';
					break;
				case 'd':
					scc = '\x1d';
					break;
				case 'e':
					scc = '\x1e';
					break;
				case 'f':
					scc = '\x1f';
					break;
				
				default :
					break;
			}
			break;
		case '2':
			switch(conv[cht+1]){
				case '0':
					scc = '\x20';
					break;
				case '1':
					scc = '\x21';
					break;
				case '2':
					scc = '\x22';
					break;
				case '3':
					scc = '\x23';
					break;
				case '4':
					scc = '\x24';
					break;
				case '5':
					scc = '\x25';
					break;
				case '6':
					scc = '\x26';
					break;
				case '7':
					scc = '\x27';
					break;
				case '8':
					scc = '\x28';
					break;
				case '9':
					scc = '\x29';
					break;
				case 'a':
					scc = '\x2a';
					break;
				case 'b':
					scc = '\x2b';
					break;
				case 'c':
					scc = '\x2c';
					break;
				case 'd':
					scc = '\x2d';
					break;
				case 'e':
					scc = '\x2e';
					break;
				case 'f':
					scc = '\x2f';
					break;
				
				default :
					break;
			}
			break;
		case '3':
			switch(conv[cht+1]){
				case '0':
					scc = '\x30';
					break;
				case '1':
					scc = '\x31';
					break;
				case '2':
					scc = '\x32';
					break;
				case '3':
					scc = '\x33';
					break;
				case '4':
					scc = '\x34';
					break;
				case '5':
					scc = '\x35';
					break;
				case '6':
					scc = '\x36';
					break;
				case '7':
					scc = '\x37';
					break;
				case '8':
					scc = '\x38';
					break;
				case '9':
					scc = '\x39';
					break;
				case 'a':
					scc = '\x3a';
					break;
				case 'b':
					scc = '\x3b';
					break;
				case 'c':
					scc = '\x3c';
					break;
				case 'd':
					scc = '\x3d';
					break;
				case 'e':
					scc = '\x3e';
					break;
				case 'f':
					scc = '\x3f';
					break;
				
				default :
					break;
			}
			break;
		case '4':
			switch(conv[cht+1]){
				case '0':
					scc = '\x40';
					break;
				case '1':
					scc = '\x41';
					break;
				case '2':
					scc = '\x42';
					break;
				case '3':
					scc = '\x43';
					break;
				case '4':
					scc = '\x44';
					break;
				case '5':
					scc = '\x45';
					break;
				case '6':
					scc = '\x46';
					break;
				case '7':
					scc = '\x47';
					break;
				case '8':
					scc = '\x48';
					break;
				case '9':
					scc = '\x49';
					break;
				case 'a':
					scc = '\x4a';
					break;
				case 'b':
					scc = '\x4b';
					break;
				case 'c':
					scc = '\x4c';
					break;
				case 'd':
					scc = '\x4d';
					break;
				case 'e':
					scc = '\x4e';
					break;
				case 'f':
					scc = '\x4f';
					break;
				
				default :
					break;
			}
			break;
		case '5':
			switch(conv[cht+1]){
				case '0':
					scc = '\x50';
					break;
				case '1':
					scc = '\x51';
					break;
				case '2':
					scc = '\x52';
					break;
				case '3':
					scc = '\x53';
					break;
				case '4':
					scc = '\x54';
					break;
				case '5':
					scc = '\x55';
					break;
				case '6':
					scc = '\x56';
					break;
				case '7':
					scc = '\x57';
					break;
				case '8':
					scc = '\x58';
					break;
				case '9':
					scc = '\x59';
					break;
				case 'a':
					scc = '\x5a';
					break;
				case 'b':
					scc = '\x5b';
					break;
				case 'c':
					scc = '\x5c';
					break;
				case 'd':
					scc = '\x5d';
					break;
				case 'e':
					scc = '\x5e';
					break;
				case 'f':
					scc = '\x5f';
					break;
				
				default :
					break;
			}
			break;
			
		case '6':
			switch(conv[cht+1]){
				case '0':
					scc = '\x60';
					break;
				case '1':
					scc = '\x61';
					break;
				case '2':
					scc = '\x62';
					break;
				case '3':
					scc = '\x63';
					break;
				case '4':
					scc = '\x64';
					break;
				case '5':
					scc = '\x65';
					break;
				case '6':
					scc = '\x66';
					break;
				case '7':
					scc = '\x67';
					break;
				case '8':
					scc = '\x68';
					break;
				case '9':
					scc = '\x69';
					break;
				case 'a':
					scc = '\x6a';
					break;
				case 'b':
					scc = '\x6b';
					break;
				case 'c':
					scc = '\x6c';
					break;
				case 'd':
					scc = '\x6d';
					break;
				case 'e':
					scc = '\x6e';
					break;
				case 'f':
					scc = '\x6f';
					break;
				
				default :
					break;
			}
			break;
		case '7':
			switch(conv[cht+1]){
				case '0':
					scc = '\x70';
					break;
				case '1':
					scc = '\x71';
					break;
				case '2':
					scc = '\x72';
					break;
				case '3':
					scc = '\x73';
					break;
				case '4':
					scc = '\x74';
					break;
				case '5':
					scc = '\x75';
					break;
				case '6':
					scc = '\x76';
					break;
				case '7':
					scc = '\x77';
					break;
				case '8':
					scc = '\x78';
					break;
				case '9':
					scc = '\x79';
					break;
				case 'a':
					scc = '\x7a';
					break;
				case 'b':
					scc = '\x7b';
					break;
				case 'c':
					scc = '\x7c';
					break;
				case 'd':
					scc = '\x7d';
					break;
				case 'e':
					scc = '\x7e';
					break;
				case 'f':
					scc = '\x7f';
					break;
				
				default :
					break;
			}
			break;
		case '8':
			switch(conv[cht+1]){
				case '0':
					scc = '\x80';
					break;
				case '1':
					scc = '\x81';
					break;
				case '2':
					scc = '\x82';
					break;
				case '3':
					scc = '\x83';
					break;
				case '4':
					scc = '\x84';
					break;
				case '5':
					scc = '\x85';
					break;
				case '6':
					scc = '\x86';
					break;
				case '7':
					scc = '\x87';
					break;
				case '8':
					scc = '\x88';
					break;
				case '9':
					scc = '\x89';
					break;
				case 'a':
					scc = '\x8a';
					break;
				case 'b':
					scc = '\x8b';
					break;
				case 'c':
					scc = '\x8c';
					break;
				case 'd':
					scc = '\x8d';
					break;
				case 'e':
					scc = '\x8e';
					break;
				case 'f':
					scc = '\x8f';
					break;
				
				default :
					break;
			}
			break;
		case '9':
			switch(conv[cht+1]){
				case '0':
					scc = '\x90';
					break;
				case '1':
					scc = '\x91';
					break;
				case '2':
					scc = '\x92';
					break;
				case '3':
					scc = '\x93';
					break;
				case '4':
					scc = '\x94';
					break;
				case '5':
					scc = '\x95';
					break;
				case '6':
					scc = '\x96';
					break;
				case '7':
					scc = '\x97';
					break;
				case '8':
					scc = '\x98';
					break;
				case '9':
					scc = '\x99';
					break;
				case 'a':
					scc = '\x9a';
					break;
				case 'b':
					scc = '\x9b';
					break;
				case 'c':
					scc = '\x9c';
					break;
				case 'd':
					scc = '\x9d';
					break;
				case 'e':
					scc = '\x9e';
					break;
				case 'f':
					scc = '\x9f';
					break;
				
				default :
					break;
			}
			break;
		
		case 'a':
			switch(conv[cht+1]){
				case '0':
					scc = '\xa0';
					break;
				case '1':
					scc = '\xa1';
					break;
				case '2':
					scc = '\xa2';
					break;
				case '3':
					scc = '\xa3';
					break;
				case '4':
					scc = '\xa4';
					break;
				case '5':
					scc = '\xa5';
					break;
				case '6':
					scc = '\xa6';
					break;
				case '7':
					scc = '\xa7';
					break;
				case '8':
					scc = '\xa8';
					break;
				case '9':
					scc = '\xa9';
					break;
				case 'a':
					scc = '\xaa';
					break;
				case 'b':
					scc = '\xab';
					break;
				case 'c':
					scc = '\xac';
					break;
				case 'd':
					scc = '\xad';
					break;
				case 'e':
					scc = '\xae';
					break;
				case 'f':
					scc = '\xaf';
					break;
				
				default :
					break;
			}
			break;
		case 'b':
			switch(conv[cht+1]){
				case '0':
					scc = '\xb0';
					break;
				case '1':
					scc = '\xb1';
					break;
				case '2':
					scc = '\xb2';
					break;
				case '3':
					scc = '\xb3';
					break;
				case '4':
					scc = '\xb4';
					break;
				case '5':
					scc = '\xb5';
					break;
				case '6':
					scc = '\xb6';
					break;
				case '7':
					scc = '\xb7';
					break;
				case '8':
					scc = '\xb8';
					break;
				case '9':
					scc = '\xb9';
					break;
				case 'a':
					scc = '\xba';
					break;
				case 'b':
					scc = '\xbb';
					break;
				case 'c':
					scc = '\xbc';
					break;
				case 'd':
					scc = '\xbd';
					break;
				case 'e':
					scc = '\xbe';
					break;
				case 'f':
					scc = '\xbf';
					break;
				
				default :
					break;
			}
			break;
		case 'c':
			switch(conv[cht+1]){
				case '0':
					scc = '\xc0';
					break;
				case '1':
					scc = '\xc1';
					break;
				case '2':
					scc = '\xc2';
					break;
				case '3':
					scc = '\xc3';
					break;
				case '4':
					scc = '\xc4';
					break;
				case '5':
					scc = '\xc5';
					break;
				case '6':
					scc = '\xc6';
					break;
				case '7':
					scc = '\xc7';
					break;
				case '8':
					scc = '\xc8';
					break;
				case '9':
					scc = '\xc9';
					break;
				case 'a':
					scc = '\xca';
					break;
				case 'b':
					scc = '\xcb';
					break;
				case 'c':
					scc = '\xcc';
					break;
				case 'd':
					scc = '\xcd';
					break;
				case 'e':
					scc = '\xce';
					break;
				case 'f':
					scc = '\xcf';
					break;
				
				default :
					break;
			}
			break;
		
		case 'd':
			switch(conv[cht+1]){
				case '0':
					scc = '\xd0';
					break;
				case '1':
					scc = '\xd1';
					break;
				case '2':
					scc = '\xd2';
					break;
				case '3':
					scc = '\xd3';
					break;
				case '4':
					scc = '\xd4';
					break;
				case '5':
					scc = '\xd5';
					break;
				case '6':
					scc = '\xd6';
					break;
				case '7':
					scc = '\xd7';
					break;
				case '8':
					scc = '\xd8';
					break;
				case '9':
					scc = '\xd9';
					break;
				case 'a':
					scc = '\xda';
					break;
				case 'b':
					scc = '\xdb';
					break;
				case 'c':
					scc = '\xdc';
					break;
				case 'd':
					scc = '\xdd';
					break;
				case 'e':
					scc = '\xde';
					break;
				case 'f':
					scc = '\xdf';
					break;
				
				default :
					break;
			}
			break;
		
		case 'e':
			switch(conv[cht+1]){
				case '0':
					scc = '\xe0';
					break;
				case '1':
					scc = '\xe1';
					break;
				case '2':
					scc = '\xe2';
					break;
				case '3':
					scc = '\xe3';
					break;
				case '4':
					scc = '\xe4';
					break;
				case '5':
					scc = '\xe5';
					break;
				case '6':
					scc = '\xe6';
					break;
				case '7':
					scc = '\xe7';
					break;
				case '8':
					scc = '\xe8';
					break;
				case '9':
					scc = '\xe9';
					break;
				case 'a':
					scc = '\xea';
					break;
				case 'b':
					scc = '\xeb';
					break;
				case 'c':
					scc = '\xec';
					break;
				case 'd':
					scc = '\xed';
					break;
				case 'e':
					scc = '\xee';
					break;
				case 'f':
					scc = '\xef';
					break;
				
				default :
					break;
			}
			break;
		case 'f':
			switch(conv[cht+1]){
				case '0':
					scc = '\xf0';
					break;
				case '1':
					scc = '\xf1';
					break;
				case '2':
					scc = '\xf2';
					break;
				case '3':
					scc = '\xf3';
					break;
				case '4':
					scc = '\xf4';
					break;
				case '5':
					scc = '\xf5';
					break;
				case '6':
					scc = '\xf6';
					break;
				case '7':
					scc = '\xf7';
					break;
				case '8':
					scc = '\xf8';
					break;
				case '9':
					scc = '\xf9';
					break;
				case 'a':
					scc = '\xfa';
					break;
				case 'b':
					scc = '\xfb';
					break;
				case 'c':
					scc = '\xfc';
					break;
				case 'd':
					scc = '\xfd';
					break;
				case 'e':
					scc = '\xfe';
					break;
				case 'f':
					scc = '\xff';
					break;
				
				default :
					break;
			}
			break;
		
		default:
			break;


	}
	
	printf("conv sc = %c\n",scc);
	
	
	convsum[cht2] = scc; // after conversion, add to the back of convsum, as shellcode requires reversed address due to little endian?
	// 0x55 55 55 55 51 f9 -> '\xf9\x51\x55\x55\x55\x55'
	// ^ ignore spaces, but we can see f9 went from the last to first
	
	cht2--;// decrement to work from changing values convsum[5]  to convsum[0]
	}
	printf("conv full = %s\n",convsum);
	


	

	


	char input[264]; // 256 + 8 
			 // (8 = base pointer register of previous stack frame)
			 // (8 bytes as 8 bytes = 64 bits, and we have 64 bits for address)
			 // (this is the 8 byte padding between 'buf' char array and our target return address

	for(int ctr = 0; ctr < 264; ctr++){
		input[ctr] = '\x90'; // nop in intel proc
	}
	
	//char conv[] = "\xf9\x51\x55\x55\x55\x55";

	strcat(input, convsum);
	printf("full item = %s\n",input);
	overflow(input);

 
	return 0;
}
