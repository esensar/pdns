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
#include <unordered_map>
#include <vector>

#include "lock.hh"
#include "misc.hh"

template <typename K, typename V>
class GenericCacheInterface
{
public:
  virtual void insert(const K& key, V value) = 0;
  virtual bool getValue(const K& key, V& value) const = 0;
  virtual bool contains(const K& key) const = 0;
  virtual size_t purgeExpired(size_t upTo, const time_t now) = 0;
  virtual size_t expunge(size_t upTo = 0) = 0;
};

template <typename K, typename V>
class GenericCache : public GenericCacheInterface<K, V>, boost::noncopyable
{
public:
  struct CacheSettings
  {
  };

  GenericCache(CacheSettings settings);

private:
  struct CacheValue
  {
    V value;
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

    SharedLockGuarded<std::unordered_map<K, CacheValue>> d_map;
    std::atomic<uint64_t> d_entriesCount{0};
  };

  std::vector<CacheShard> d_shards;
  CacheSettings d_settings;
};

template <typename K, typename V>
class BasicCache : public GenericCacheInterface<K, V>, boost::noncopyable
{
  void insert(const K& key, V value) override
  {
    auto map = d_map.write_lock();
    map->emplace(key, value);
  }
  bool getValue(const K& key, V& value) const override
  {
    auto map = d_map.read_lock();

    auto entry = map->find(key);
    if (entry != map->end()) {
      value = entry->second;
      return true;
    }

    return false;
  }
  bool contains(const K& key) const override
  {
    auto map = d_map.read_lock();
    return map->find(key) != map->end();
  }
  size_t purgeExpired([[maybe_unused]] size_t upTo, [[maybe_unused]] const time_t now) override
  {
    return 0;
  }
  size_t expunge([[maybe_unused]] size_t upTo = 0) override
  {
    return 0;
  }

private:
  // Mutable to be able to lock in const methods
  mutable SharedLockGuarded<std::unordered_map<K, V>> d_map;
};
