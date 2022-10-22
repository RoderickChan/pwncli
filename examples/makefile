all: stackoverflow_nopie stackoverflow_pie

stackoverflow_nopie: pwn.c
	gcc pwn.c -o stackoverflow_nopie -fno-stack-protector -no-pie -z noexecstack -z lazy -O0 -g

stackoverflow_pie: pwn.c
	gcc pwn.c -o stackoverflow_pie -fno-stack-protector -pie -z noexecstack -z lazy -O0 -g

clean:
	rm -rf stackoverflow_pie stackoverflow_nopie