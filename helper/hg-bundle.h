#ifndef BUNDLE_H
#define BUNDLE_H

#include "strbuf.h"
#include <stdio.h>

extern void copy_bundle(FILE *in, FILE *out);
extern void copy_bundle_to_strbuf(FILE *in, struct strbuf *out);

#endif
