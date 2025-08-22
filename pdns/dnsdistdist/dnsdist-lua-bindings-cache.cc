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
#include "dnsdist.hh"
#include "dnsdist-lua.hh"
#include "generic-cache.hh"
#include <memory>

using cache_t = GenericCacheInterface<std::string, std::string>;

void setupLuaBindingsCache(LuaContext& luaCtx)
{
  luaCtx.writeFunction("newBasicCache", []() {
    return std::shared_ptr<cache_t>(new BasicCache<std::string, std::string>());
  });

  luaCtx.registerFunction<boost::optional<std::string> (std::shared_ptr<cache_t>::*)(const std::string&)>("get", [](std::shared_ptr<cache_t>& cache, const std::string& key) {
    boost::optional<std::string> result{boost::none};
    if (!cache) {
      return result;
    }

    std::string value;
    if (cache->getValue(key, value)) {
      result = value;
    }

    return result;
  });

  luaCtx.registerFunction<bool (std::shared_ptr<cache_t>::*)(const std::string&)>("contains", [](std::shared_ptr<cache_t>& cache, const std::string& key) {
    if (!cache) {
      return false;
    }

    return cache->contains(key);
  });

  luaCtx.registerFunction<void (std::shared_ptr<cache_t>::*)(const std::string&, std::string)>("insert", [](std::shared_ptr<cache_t>& cache, const std::string& key, std::string value) {
    if (!cache) {
      return;
    }

    cache->insert(key, value);
  });

  luaCtx.registerFunction<void (std::shared_ptr<cache_t>::*)(const int&)>("purgeExpired", [](std::shared_ptr<cache_t>& cache, const int& upTo) {
    if (!cache) {
      return;
    }

    auto time = time_t(nullptr);
    cache->purgeExpired(upTo, time);
  });

  luaCtx.registerFunction<void (std::shared_ptr<cache_t>::*)(boost::optional<int>)>("expunge", [](std::shared_ptr<cache_t>& cache, boost::optional<int> upTo) {
    if (!cache) {
      return;
    }

    if (upTo) {
      cache->expunge(upTo.get());
    }
    else {
      cache->expunge();
    }
  });
}
