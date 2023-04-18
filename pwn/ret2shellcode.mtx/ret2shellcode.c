#include <stdio.h>

void func() {
    char func_buf[100];
    printf("this is ret2shellcode.mtx! gets: ");
    gets(func_buf);
    puts("goodbye");
}

int main() {
    char main_buf[100] = {0};
    func();
    return 0;
}