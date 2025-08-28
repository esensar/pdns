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
#pragma once

#include <atomic>
#include <boost/multi_index/hashed_index.hpp>
#include <boost/multi_index/indexed_by.hpp>
#include <boost/multi_index/member.hpp>
#include <boost/multi_index_container.hpp>
#include <boost/multi_index/ordered_index.hpp>
#include <boost/multi_index/sequenced_index.hpp>
#include <boost/multi_index/key_extractors.hpp>
#include <boost/multi_index/tag.hpp>
#include <type_traits>
#include <unordered_map>
#include <vector>

#include "dolog.hh"
#include "lock.hh"

template <typename K, typename V>
class GenericCacheInterface
{
public:
  virtual ~GenericCacheInterface() {};
  virtual void insert(const K& key, V value) = 0;
  virtual bool getValue(const K& key, V& value) = 0;
  virtual bool contains(const K& key) = 0;
  virtual size_t purgeExpired(size_t upTo, time_t now) = 0;
  virtual size_t expunge(size_t upTo = 0) = 0;
};

template <typename K, typename V, bool hasTtl, bool hasLru, typename Hash = std::hash<K>, typename = std::enable_if_t<!hasTtl || !hasLru>>
class GenericCache : public GenericCacheInterface<K, V>, boost::noncopyable
{
private:
  struct BasicCacheValue
  {
    V value;
  };
  struct CacheValueWithTtl
  {
    V value;
    time_t validity;
  };

  using CacheValue = std::conditional_t<hasTtl, CacheValueWithTtl, BasicCacheValue>;

public:
  struct CacheSettings
  {
    unsigned int d_ttl;
    uint32_t d_shardCount{1};
    uint32_t d_maxEntries{0};
  };

  GenericCache(CacheSettings settings) :
    d_settings(settings), d_shards(settings.d_shardCount)
  {
  }
  virtual ~GenericCache() {};

  void insert(const K& key, V value)
  {
    size_t hash = Hash{}(key);
    size_t shardIndex = hash % d_settings.d_shardCount;

    if (d_settings.d_maxEntries > 0 && d_shards.at(shardIndex).d_entriesCount >= (d_settings.d_maxEntries / d_settings.d_shardCount)) {
      if constexpr (hasTtl) {
        time_t now = time(nullptr);
        purgeExpired(0, now);
      }
      else {
        expunge(d_settings.d_maxEntries - 1);
      };

      if (d_shards.at(shardIndex).d_entriesCount >= (d_settings.d_maxEntries / d_settings.d_shardCount)) {
        return;
      }
    }

    CacheValue cacheValue;
    if constexpr (hasTtl) {
      time_t now = time(nullptr);
      cacheValue = CacheValueWithTtl{
        .value = value,
        .validity = now + d_settings.d_ttl};
    }
    else {
      cacheValue = BasicCacheValue{
        .value = value};
    }

    auto& shard = d_shards.at(shardIndex);

    auto map = shard.d_map.write_lock();

    // check again now that we hold the lock to prevent a race
    if (d_settings.d_maxEntries > 0 && map->size() >= (d_settings.d_maxEntries / d_settings.d_shardCount)) {
      return;
    }

    typename std::unordered_map<K, CacheValue, Hash>::iterator mapIt;
    bool result{false};
    std::tie(mapIt, result) = map->insert({key, cacheValue});

    if (result) {
      ++shard.d_entriesCount;
      return;
    }

    // Replace old value
    mapIt->second.value = value;
  }

  bool getValue(const K& key, V& value)
  {
    size_t hash = Hash{}(key);
    size_t shardIndex = hash % d_settings.d_shardCount;
    auto& shard = d_shards.at(shardIndex);
    {
      auto map = shard.d_map.read_lock();

      auto mapIt = map->find(key);
      if (mapIt == map->end()) {
        return false;
      }
      else {
        if constexpr (hasTtl) {
          time_t now = time(nullptr);
          if (mapIt->second.validity > now) {
            value = mapIt->second.value;
            return true;
          }
        }
        else {
          value = mapIt->second.value;
          return true;
        }
      }
    }

    if constexpr (hasTtl) {
      erase_key(shard, key);
      return false;
    }
  }

  bool contains(const K& key)
  {
    size_t hash = Hash{}(key);
    size_t shardIndex = hash % d_settings.d_shardCount;
    auto& shard = d_shards.at(shardIndex);
    {
      auto map = shard.d_map.read_lock();

      auto mapIt = map->find(key);
      if constexpr (hasTtl) {
        if (mapIt == map->end()) {
          return false;
        }

        time_t now = time(nullptr);
        if (mapIt->second.validity > now) {
          return true;
        }
      }
      else {
        return mapIt != map->end();
      }
    }

    if constexpr (hasTtl) {
      erase_key(shard, key);
      return false;
    }
  }

  size_t purgeExpired(size_t upTo, const time_t now)
  {
    if constexpr (hasTtl) {
      const size_t maxPerShard = upTo / d_settings.d_shardCount;

      size_t removed = 0;
      for (auto& shard : d_shards) {
        auto map = shard.d_map.write_lock();
        if (map->size() <= maxPerShard) {
          continue;
        }

        size_t toRemove = map->size() - maxPerShard;

        for (auto it = map->begin(); toRemove > 0 && it != map->end();) {
          const CacheValue& value = it->second;

          if (value.validity <= now) {
            it = map->erase(it);
            --toRemove;
            --shard.d_entriesCount;
            ++removed;
          }
          else {
            ++it;
          }
        }
      }

      return removed;
    }
    else {
      return expunge(upTo);
    }
  }

  size_t expunge(size_t upTo = 0)
  {
    const size_t maxPerShard = upTo / d_settings.d_shardCount;

    size_t removed = 0;

    for (auto& shard : d_shards) {
      auto map = shard.d_map.write_lock();

      if (map->size() <= maxPerShard) {
        continue;
      }

      size_t toRemove = map->size() - maxPerShard;

      auto beginIt = map->begin();
      auto endIt = beginIt;

      if (map->size() >= toRemove) {
        std::advance(endIt, toRemove);
        map->erase(beginIt, endIt);
        shard.d_entriesCount -= toRemove;
        removed += toRemove;
      }
      else {
        removed += map->size();
        map->clear();
        shard.d_entriesCount = 0;
      }
    }

    return removed;
  }

private:
  struct HashedTag
  {
  };
  struct SequencedTag
  {
  };

  class CacheShard
  {
  public:
    CacheShard()
    {
    }
    CacheShard(const CacheShard& /* old */)
    {
    }

    void setSize(size_t maxSize)
    {
      d_map.write_lock()->reserve(maxSize);
    }

    SharedLockGuarded<std::unordered_map<K, CacheValue, Hash>> d_map;
    std::atomic<uint64_t> d_entriesCount{0};
  };

  void erase_key(CacheShard& shard, const K& key)
  {
    auto map = shard.d_map.write_lock();
    auto mapIt = map->find(key);
    if (mapIt != map->end()) {
      map->erase(mapIt);
    }
  }

  CacheSettings d_settings;
  std::vector<CacheShard> d_shards;
};
