#include "test_c_header.h"

int test_c_func(int a, int b) {
    printf("test: %d + %d = %d", a, b, a+b);
    return a+b;
}
