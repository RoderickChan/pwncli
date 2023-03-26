all: pwn

pwn: pwn.c
	gcc pwn.c -o pwn -fno-stack-protector -no-pie -z noexecstack -z lazy -O0 -g -w

clean:
	rm -rf pwn