#include <stdio.h>
#include <string.h>

char *slice(char *flag)
{
    static char ip[16];

    FILE *fp;
    char buffer[32][256] = {0};
    fp = fopen("past/codes/root.txt", "r");
    int len, i = 0;
    if (fp != NULL)
    {
        while (fgets(buffer[i], 256, fp) != NULL)
        {
            len = strlen(buffer[i]);
            buffer[i][len - 1] = '\0';
            i++;
        }
        fclose(fp);
    }

    for (int j = 1; j <= i; j++)
    {
        const char s[2] = " ";
        char *token;
        char str[32];
        strcpy(str, buffer[j]);

        char line[6][16];
        int p = 0;

        token = strtok(str, s);
        while (token != NULL)
        {
            strcpy(line[p], token);
            token = strtok(NULL, s);
            p++;
        }
        if (strcmp(line[0], flag) == 0)
        {
            for (int q = 0; q < 16; q++)
            {
                ip[q] = line[3][q];
            }
            printf("\nFind ip in root: %s\n", ip);
        }
    }

    return ip;
}

int main(int argc, char const *argv[])
{
    char *str = "com";
    char *ip = slice(str);
    printf("%s\n", ip);

    return 0;
}
