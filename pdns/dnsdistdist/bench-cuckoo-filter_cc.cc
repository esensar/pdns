/*
 * This file is part of PowerDNS or dnsdist.
 * Copyright -- PowerDNS.COM B.V. and its contributors
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * In addition, for the avoidance of any doubt, permission is granted to
 * link this program with OpenSSL and to (re)distribute the binaries
 * produced as the result of such linking.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
#define CATCH_CONFIG_NO_MAIN
#include <catch2/catch_test_macros.hpp>
#include <catch2/benchmark/catch_benchmark.hpp>

#include "generic-cache.hh"
#include "gettime.hh"

static std::vector<std::string> prepareData(uint32_t count)
{
  std::vector<std::string> items;
  for (uint32_t i = 0; i < count; ++i) {
    items.emplace_back("item_" + std::to_string(i));
  }
  return items;
}

auto configurations = std::vector<CuckooFilter::CuckooSettings>{
  {.d_maxEntries = 100},
  {.d_maxEntries = 100000},
  {.d_maxKicks = 0, .d_maxEntries = 100000},
  {.d_maxEntries = 100000, .d_ttlEnabled = true, .d_ttl = 100},
  {.d_maxEntries = 100000, .d_lruEnabled = true},
  {.d_maxEntries = 100000, .d_ttlEnabled = true, .d_ttl = 100, .d_lruEnabled = true},
  {.d_maxEntries = 100000, .d_fingerprintBits = 32},
  {.d_maxEntries = 100000, .d_bucketSize = 100, .d_fingerprintBits = 32},
};

TEST_CASE("CuckooFilter")
{
  for (auto const& config : configurations) {
    const size_t count = config.d_maxEntries;
    std::vector<std::string> data = prepareData(count);
    CuckooFilter cuckooFull{config};
    CuckooFilter cuckooEmpty{config};

    for (uint32_t i = 0; i < count; ++i) {
      cuckooFull.insertKey("prepopulated_" + std::to_string(i));
    }

    string benchName = "entries=" + std::to_string(config.d_maxEntries) + ",ttlEnabled=" + std::to_string(config.d_ttlEnabled) + ",lruEnabled=" + std::to_string(config.d_lruEnabled) + ",fingerprintBits=" + std::to_string(config.d_fingerprintBits) + ",bucketSize=" + std::to_string(config.d_bucketSize) + ",maxKicks=" + std::to_string(config.d_maxKicks);
    string benchNameFull = "Full/" + benchName;
    string benchNameEmpty = "Empty/" + benchName;
    timespec now;
    if (config.d_ttlEnabled) {
      gettime(&now);
    }

    BENCHMARK((benchNameFull + "/insertKey").c_str(), i)
    {
      return cuckooFull.insertKey(data[i % count]);
    };
    BENCHMARK((benchNameFull + "/contains").c_str(), i)
    {
      return cuckooFull.contains(data[i % count]);
    };
    BENCHMARK((benchNameFull + "/remove").c_str(), i)
    {
      return cuckooFull.remove(data[i % count]);
    };

    if (config.d_ttlEnabled) {
      BENCHMARK((benchNameFull + "/purgeExpired").c_str())
      {
        return cuckooFull.purgeExpired(0, now.tv_sec);
      };
    }

    BENCHMARK((benchNameEmpty + "/insertKey").c_str(), i)
    {
      return cuckooEmpty.insertKey(data[i % count]);
    };
    BENCHMARK((benchNameEmpty + "/contains").c_str(), i)
    {
      return cuckooEmpty.contains(data[i % count]);
    };
    BENCHMARK((benchNameEmpty + "/remove").c_str(), i)
    {
      return cuckooEmpty.remove(data[i % count]);
    };
    if (config.d_ttlEnabled) {
      BENCHMARK((benchNameEmpty + "/purgeExpired").c_str())
      {
        return cuckooEmpty.purgeExpired(0, now.tv_sec);
      };
    }
  }
}
