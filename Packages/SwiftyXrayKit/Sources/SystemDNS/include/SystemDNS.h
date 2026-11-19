#ifndef SIMPLE_SYSTEM_DNS_H
#define SIMPLE_SYSTEM_DNS_H
#include <stddef.h>
// Returns newline-separated numeric DNS endpoints from the current system resolver.
size_t simple_copy_system_dns(char *output, size_t capacity);
#endif
