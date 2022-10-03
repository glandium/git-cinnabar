#ifdef _WIN32
#define winansi_init(...)
#define main cinnabar_main
extern int cinnabar_main(int argc, const char *argv[]);
#include "compat/mingw.c"
#endif
