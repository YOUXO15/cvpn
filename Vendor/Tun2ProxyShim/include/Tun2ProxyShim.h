#ifndef TUNNEL_PROXY_SHIM_H
#define TUNNEL_PROXY_SHIM_H

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

int32_t TunnelProxyRun(
    const char *cli_args,
    uint16_t tun_mtu,
    bool packet_information
);
int32_t TunnelProxyStop(void);
bool TunnelProxyIsRunning(void);

#ifdef __cplusplus
}
#endif

#endif
