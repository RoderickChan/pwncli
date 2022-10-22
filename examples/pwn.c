#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

void backdoor()
{
	system("/bin/sh");
}

void vuln()
{
	char buf[0x10];
	puts("please input: ");
	read(0, buf, 0x200);
	return;
}

void main()
{
	setbuf(stdout, 0);
	malloc(0x100);
	char name[0x10] = {0};
	puts("read your name: ");
	read(0, name, 0x10);
	printf("welcome to the game, %s\n", name);
	vuln();
}
