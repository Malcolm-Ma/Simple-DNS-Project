#include <stdio.h>
#include <string.h>

int main()
{
    unsigned char buf[] = "Hello";
    int a =4;
    int* b = &a;
    *b = 10;
    printf("%lu",sizeof(buf));
}