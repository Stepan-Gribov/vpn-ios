#include "SystemDNS.h"
#include <arpa/inet.h>
#include <netdb.h>
#include <resolv.h>
#include <stdio.h>
#include <string.h>

size_t simple_copy_system_dns(char *output, size_t capacity) {
    if (!output || capacity == 0) return 0;
    output[0] = '\0';
    struct __res_state state;
    memset(&state, 0, sizeof(state));
    if (res_ninit(&state) != 0) return 0;
    union res_sockaddr_union servers[MAXNS];
    memset(servers, 0, sizeof(servers));
    int count = res_getservers(&state, servers, MAXNS);
    size_t used = 0;
    for (int i = 0; i < count && i < MAXNS; i++) {
        const struct sockaddr *address = (const struct sockaddr *)&servers[i];
        if (address->sa_family != AF_INET && address->sa_family != AF_INET6) continue;
        char host[NI_MAXHOST], service[NI_MAXSERV];
        socklen_t length = address->sa_family == AF_INET ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6);
        if (getnameinfo(address, length, host, sizeof(host), service, sizeof(service), NI_NUMERICHOST | NI_NUMERICSERV) != 0) continue;
        if (!strcmp(host, "0.0.0.0") || !strncmp(host, "127.", 4) || !strcmp(host, "::") || !strcmp(host, "::1") || strchr(host, '%')) continue;
        char endpoint[NI_MAXHOST + NI_MAXSERV + 8];
        int lengthWritten = snprintf(endpoint, sizeof(endpoint), address->sa_family == AF_INET6 ? "[%s]:%s\n" : "%s:%s\n", host, service);
        if (lengthWritten <= 0 || (size_t)lengthWritten >= sizeof(endpoint) || used + (size_t)lengthWritten >= capacity) continue;
        memcpy(output + used, endpoint, (size_t)lengthWritten);
        used += (size_t)lengthWritten;
        output[used] = '\0';
    }
    res_ndestroy(&state);
    return used;
}
