#include "run-command.c"

#ifdef _WIN32
#include "compat/mingw.c"

char *which(const char *file) {
	return path_lookup(file, 0);
}

#else

char *which(const char *file) {
	return locate_in_PATH(file);
}
#endif
