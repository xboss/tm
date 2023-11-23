#include <stdio.h>
#include <uv.h>

int main(int argc, char const *argv[]) {
    const char *ver = uv_version_string();
    printf("%s\n", ver);
    return 0;
}
