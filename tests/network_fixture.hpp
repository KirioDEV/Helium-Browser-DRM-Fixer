#pragma once

#ifndef FIXER_NETWORK_TESTING
#error This header belongs only to the isolated network test executable.
#endif

#include <optional>

#include "fixer.hpp"

namespace fixer::testing {
struct NetworkSettings {
  unsigned short port = 0;
  long total_ms = 5000;
  long connect_ms = 1500;
  long idle_ms = 1500;
  long low_speed_seconds = 1;
  std::string ca_file;
  std::string peer_sha256;
  bool dns_failure = false;
  std::optional<std::vector<std::vector<std::string>>> dns_answers;
};

Bytes network_request(const NetworkSettings &settings, const std::string &url,
                      const std::string &body, std::size_t limit,
                      bool update = false);
}  // namespace fixer::testing
