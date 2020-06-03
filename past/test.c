#include <stdio.h>
#include <string.h>

int main ()
{
    struct Books
    {
    char  title[50];
    char  author[50];
    char  subject[100];
    int   book_id;
    };
    unsigned short a =10;
   struct Books book1;
   struct Books* p = &book1;
   strcpy(p->title, "hello");
   printf("%d", strlen(a));
}