#include <stdlib.h>
#include <stdio.h>

int main() {
    printf("RAND IS %d\n", arc4random_uniform(100));
    return 0;
}
