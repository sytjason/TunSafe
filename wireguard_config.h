// SPDX-License-Identifier: AGPL-1.0-only
// Copyright (C) 2018 Ludvig Strigeus <info@tunsafe.com>. All Rights Reserved.
#ifndef TINYVPN_TINYVPN_H_
#define TINYVPN_TINYVPN_H_

#include <string>

class DnsResolver;
class WireguardProcessor;

class WgConfig {
public:
#if !defined(__clang__) && __cplusplus < 201103L
  static bool HandleConfigurationProtocolMessage(WireguardProcessor *proc, const std::string &message, std::string *result);
#else
  static bool HandleConfigurationProtocolMessage(WireguardProcessor *proc, const std::string &&message, std::string *result);
#endif
private:
  static void HandleConfigurationProtocolGet(WireguardProcessor *proc, std::string *result);
};

bool ParseWireGuardConfigString(WireguardProcessor *wg, const char *buf, size_t buf_size, DnsResolver *dns_resolver);
bool ParseWireGuardConfigFile(WireguardProcessor *wg, const char *filename, DnsResolver *dns_resolver);


#endif  // TINYVPN_TINYVPN_H_
