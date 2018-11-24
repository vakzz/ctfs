pwn.gz: pwn.c
	musl-gcc pwn.c -o pwn -nostartfiles -static -O0 && gzip -k -f --best pwn


writeup.gz: writeup.c
	gcc writeup.c -o writeup -nostartfiles -static -O0 && gzip -k -f --best writeup

writeup2.gz: writeup2.c
	gcc writeup2.c -o writeup2 -nostartfiles -static -O0 && gzip -k -f --best writeup2