#include <stdio.h>

int main()
{
    char buf[5];
    strncpy(buf, "testing", 4);
    printf(buf);
    return 0;
}
