#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

void main()
{
	setbuf(stdout, 0);
	malloc(0x100);
	char name[0x20] = {0};
	puts("read your name: ");
	read(0, name, 0x10);
    if (strncmp(name, "admin", 5) == 0) {
        int fd = open("flag", 0);
        char buf[0x60] = {0};
        read(fd, buf, 0x40);
        printf("Your flag: %s\n", buf);
    } else 
    {
    printf("Your flag: flag{test_flag}\n");
    }

}
