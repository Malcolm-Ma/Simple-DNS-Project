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
   struct Books book1;
   struct Books* p = &book1;
   strcpy(p->title, "hello");
   printf("%lu", sizeof(p->title));
   printf("%d", ntohs("0x0080"));
}