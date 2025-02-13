#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wall_e_t.h>

int main() {
    ssize_t error = 0;
    error = address_balance("bc1q40thsjx4k84gdmx2aynwqygmxwxpnsrjzzs4jv");

    printf("Satoshis: %ld\n", error);
    
    exit(error);    
}
