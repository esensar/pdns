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
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef HAVE_REDIS
#include "gettime.hh"
#include <memory>
#include <stdexcept>

#include "redis.hh"
#include "dolog.hh"
#include <hiredis/hiredis.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

std::unique_ptr<RedisReplyInterface<std::string>> RedisGetCommand::operator()(const RedisClient& client, const std::string& key) const
{
  return std::make_unique<RedisStringReply>(client.executeCommand("GET %b", key.data(), key.length()));
}

std::unique_ptr<RedisReplyInterface<bool>> RedisExistsCommand::operator()(const RedisClient& client, const std::string& key) const
{
  return std::make_unique<RedisIntAsBoolReply>(std::make_unique<RedisIntReply>(client.executeCommand("EXISTS %b", key.data(), key.length())));
}

std::unique_ptr<RedisReplyInterface<std::string>> RedisHGetCommand::operator()(const RedisClient& client, const std::string& hash_key, const std::string& key) const
{
  return std::make_unique<RedisStringReply>(client.executeCommand("HGET %b %b", hash_key.data(), hash_key.length(), key.data(), key.length()));
}

std::unique_ptr<RedisReplyInterface<std::unordered_map<std::string, std::string>>> RedisHGetAllCommand::operator()(const RedisClient& client, const std::string& hash_key) const
{
  return std::make_unique<RedisHashReply>(client.executeCommand("HGETALL %b", hash_key.data(), hash_key.length()));
}

std::unique_ptr<RedisReplyInterface<bool>> RedisHExistsCommand::operator()(const RedisClient& client, const std::string& hash_key, const std::string& key) const
{
  return std::make_unique<RedisIntAsBoolReply>(std::make_unique<RedisIntReply>(client.executeCommand("HEXISTS %b %b", hash_key.data(), hash_key.length(), key.data(), key.length())));
}

std::unique_ptr<RedisReplyInterface<std::string>> RedisGetLookupAction::getValue(const RedisClient& client, const std::string& key) const
{
  return d_getCommand(client, d_prefix + key);
}

std::unique_ptr<RedisReplyInterface<bool>> RedisGetLookupAction::keyExists(const RedisClient& client, const std::string& key) const
{
  return d_existsCommand(client, d_prefix + key);
}

std::unordered_map<std::string, std::string> RedisGetLookupAction::generateCopyCache([[maybe_unused]] const RedisClient& client) const
{
  return {};
}

bool RedisGetLookupAction::getFromCopyCache([[maybe_unused]] GenericCacheInterface<std::string, std::optional<LuaAny>>& cache, [[maybe_unused]] const std::string& key, [[maybe_unused]] std::string& value) const
{
  return false;
}

std::unique_ptr<RedisReplyInterface<std::string>> RedisHGetLookupAction::getValue(const RedisClient& client, const std::string& key) const
{
  return d_getCommand(client, d_hash_key, key);
}

std::unique_ptr<RedisReplyInterface<bool>> RedisHGetLookupAction::keyExists(const RedisClient& client, const std::string& key) const
{
  return d_existsCommand(client, d_hash_key, key);
}

std::unordered_map<std::string, std::string> RedisHGetLookupAction::generateCopyCache(const RedisClient& client) const
{
  return d_getAllCommand(client, d_hash_key)->getValue();
}

bool RedisHGetLookupAction::getFromCopyCache(GenericCacheInterface<std::string, std::optional<LuaAny>>& cache, const std::string& key, std::string& value) const
{
  std::optional<LuaAny> ret;

  if (cache.getValue(key, ret)) {
    value = boost::get<std::string>(*ret);
    return true;
  }
  return false;
}

redisReply* RedisClient::executeCommand(const char* format, ...) const
{
  va_list ap;
  va_start(ap, format);
  auto connection = d_connection.getConnection();
  auto result = static_cast<redisReply*>(redisvCommand(connection->get(), format, ap));
  if (connection->get()->err != 0) {
    vinfolog("Redis connection error %s", connection->get()->errstr);
  }
  va_end(ap);
  return result;
};

redisReply* RedisClient::executeCommandArgv(std::vector<std::string> args) const
{
  std::vector<const char*> argv;
  std::vector<size_t> argvlen;
  for (auto& arg : args) {
    argv.push_back(arg.data());
    argvlen.push_back(arg.length());
  }
  auto connection = d_connection.getConnection();
  auto result = static_cast<redisReply*>(redisCommandArgv(connection->get(), args.size(), argv.data(), argvlen.data()));
  if (connection->get()->err != 0) {
    vinfolog("Redis connection error %s", connection->get()->errstr);
  }
  return result;
};

bool ResultCachingRedisClient::getValue(const std::string& key, std::string& value)
{
  std::optional<LuaAny> ret;
  if (d_resultCache->getValue(key, ret)) {
    value = boost::get<std::string>(*ret);
    return true;
  }

  auto found = d_client->getValue(key, value);
  if (found) {
    d_resultCache->insert(key, value);
  }
  return found;
}

std::unordered_map<std::string, std::string> ResultCachingRedisClient::generateCopyCache()
{
  return d_client->generateCopyCache();
}

bool ResultCachingRedisClient::keyExists(const std::string& key)
{
  if (d_resultCache->contains(key)) {
    return true;
  }

  // No value to store in the cache here, so just return
  return d_client->keyExists(key);
}

bool NegativeCachingRedisClient::getValue(const std::string& key, std::string& value)
{
  if (d_negativeCache->contains(key)) {
    return false;
  }

  auto found = d_client->getValue(key, value);
  if (!found) {
    d_negativeCache->insertKey(key);
  }
  return found;
}

std::unordered_map<std::string, std::string> NegativeCachingRedisClient::generateCopyCache()
{
  return d_client->generateCopyCache();
}

bool NegativeCachingRedisClient::keyExists(const std::string& key)
{
  if (d_negativeCache->contains(key)) {
    return false;
  }

  auto found = d_client->keyExists(key);
  if (!found) {
    d_negativeCache->insertKey(key);
  }
  return found;
}

void CopyCache::insert(const std::string& key, std::optional<LuaAny> value, [[maybe_unused]] const std::function<bool(const std::optional<LuaAny>&)>& replaceCondition)
{
  auto map = d_map.write_lock();
  if (value.has_value() && value->type() == typeid(std::string)) {
    auto& stringValue = boost::get<std::string>(*value);
    map->emplace(key, stringValue);
    d_stats.d_entriesCount += 1;
    d_stats.d_memoryUsed += stringValue.size() + key.size();
  }
};

void CopyCache::insertKey([[maybe_unused]] const std::string& key)
{
  throw std::runtime_error("Unsupported insertKey operation for copy cache.");
};

bool CopyCache::getValue(const std::string& key, std::optional<LuaAny>& value, bool recordMiss, [[maybe_unused]] uint32_t allowExpired)
{
  if (needsUpdate()) {
    if (recordMiss) {
      d_stats.d_misses += 1;
    }
    return false;
  }

  auto map = d_map.read_lock();

  auto entry = map->find(key);
  if (entry != map->end()) {
    value = entry->second;
    d_stats.d_hits += 1;
    return true;
  }

  if (recordMiss) {
    d_stats.d_misses += 1;
  }
  return false;
};

bool CopyCache::contains(const std::string& key, bool recordMiss)
{
  auto map = d_map.read_lock();
  auto result = map->find(key) != map->end();
  if (result) {
    d_stats.d_hits += 1;
  }
  else {
    if (recordMiss) {
      d_stats.d_misses += 1;
    }
  }

  return result;
};

uint64_t CopyCache::getSize() const
{
  return d_stats.d_entriesCount;
}

bool CopyCache::hasCapacityFor([[maybe_unused]] const std::string& key)
{
  return true;
}

bool CopyCache::remove(const std::string& key)
{
  auto map = d_map.write_lock();
  auto mapIt = map->find(key);
  if (mapIt == map->end()) {
    return false;
  }

  d_stats.d_entriesCount -= 1;
  d_stats.d_memoryUsed -= (mapIt->second).size() + key.size();

  map->erase(mapIt);
  return true;
};

bool CopyCache::needsUpdate() const
{
  // TODO: count number of full refreshes too?
  struct timespec now;
  gettime(&now);
  return d_lastInsert + d_ttl < now.tv_sec;
};

void CopyCache::insertBatch(std::unordered_map<std::string, std::string> batch)
{
  // TODO: if this turns out slow or blocks too much, try atomic replacement, since whole cache is replaced anyways
  auto map = d_map.write_lock();

  map->clear();
  d_stats.d_entriesCount = 0;
  d_stats.d_memoryUsed = sizeof(*this);
  for (auto entry : batch) {
    map->emplace(entry);
    d_stats.d_memoryUsed += entry.first.size() + entry.second.size();
  }
  d_stats.d_entriesCount = batch.size();
  d_stats.d_memoryUsed += batch.size() * 2 * sizeof(std::string);
  struct timespec now;
  gettime(&now);
  d_lastInsert = now.tv_sec;
};

size_t CopyCache::purgeExpired([[maybe_unused]] size_t upTo, const time_t now)
{
  if (d_lastInsert < now - d_ttl) {
    auto removed = expunge(upTo);
    d_stats.d_expiredItems += removed;
    return removed;
  }

  return 0;
};

size_t CopyCache::expunge([[maybe_unused]] size_t upTo)
{
  auto map = d_map.write_lock();
  size_t toRemove = map->size() - upTo;

  auto beginIt = map->begin();
  auto endIt = beginIt;

  if (map->size() >= toRemove) {
    std::advance(endIt, toRemove);
    map->erase(beginIt, endIt);
    // TODO: memory usage recalculation
    d_stats.d_kickedItems += toRemove;
    d_stats.d_entriesCount -= toRemove;
    return toRemove;
  }

  auto removed = map->size();
  map->clear();
  d_stats.d_kickedItems += removed;
  d_stats.d_entriesCount -= removed;
  return removed;
};

size_t CopyCache::expungeByCondition(const std::function<bool(const std::optional<LuaAny>&)>& condition, size_t upTo)
{
  auto map = d_map.write_lock();
  size_t toRemove = map->size() - upTo;
  size_t removed = 0;

  auto it = map->begin();

  while (toRemove > 0 && it != map->end()) {
    if (condition(it->second)) {
      d_stats.d_memoryUsed -= sizeof(*it);
      it = map->erase(it);
      --toRemove;
      ++removed;
      ++d_stats.d_kickedItems;
      --d_stats.d_entriesCount;
    }
    else {
      ++it;
    }
  }
  return removed;
}

[[nodiscard]] const GenericCacheInterface<std::string, std::optional<LuaAny>>::Stats& CopyCache::getStats() const
{
  return d_stats;
};

bool CopyCachingRedisClient::getValue(const std::string& key, std::string& value)
{
  std::optional<LuaAny> ret;
  if (d_copyCache->getValue(key, ret)) {
    value = boost::get<std::string>(*ret);
    return true;
  }

  auto found = d_client->getValue(key, value);
  if (d_copyCache->needsUpdate()) {
    d_copyCache->insertBatch(d_client->generateCopyCache());
  }
  return found;
}

std::unordered_map<std::string, std::string> CopyCachingRedisClient::generateCopyCache()
{
  return d_client->generateCopyCache();
}

bool CopyCachingRedisClient::keyExists(const std::string& key)
{
  if (d_copyCache->contains(key)) {
    return true;
  }

  // No value to store in the cache here, so just return
  return d_client->keyExists(key);
}

bool FilteringCopyCachingRedisClient::getValue(const std::string& key, std::string& value)
{
  struct timespec now;
  gettime(&now);
  bool needsUpdate = d_lastInsert + d_ttl < now.tv_sec;

  if (needsUpdate) {
    auto copyCache = d_client->generateCopyCache();
    for (auto const& entry : copyCache) {
      d_copyCacheFilter->insertKey(entry.first);
    }
  }

  if (!d_copyCacheFilter->contains(key)) {
    return false;
  }

  return d_client->getValue(key, value);
}

std::unordered_map<std::string, std::string> FilteringCopyCachingRedisClient::generateCopyCache()
{
  return d_client->generateCopyCache();
}

bool FilteringCopyCachingRedisClient::keyExists(const std::string& key)
{
  if (!d_copyCacheFilter->contains(key)) {
    return false;
  }

  // We generally expect filters to be correct for negative cases
  return d_client->keyExists(key);
}

bool RedisKVClient::getValue(const std::string& key, std::string& value)
{
  auto reply = d_lookupAction->getValue(*d_client, key);

  if (reply->ok()) {
    value = reply->getValue();
    d_stats->d_successfulRequests += 1;
    return true;
  }

  vinfolog("Error while looking up key '%s' from Redis: %s", key, reply->getError());
  d_stats->d_errors += 1;
  return false;
}

std::unordered_map<std::string, std::string> RedisKVClient::generateCopyCache()
{
  // d_stats->d_copyCacheRefreshes += 1;
  return d_lookupAction->generateCopyCache(*d_client);
}

bool RedisKVClient::keyExists(const std::string& key)
{
  auto reply = d_lookupAction->keyExists(*d_client, key);
  if (reply->ok()) {
    d_stats->d_successfulRequests += 1;
    return reply->getValue();
  }

  vinfolog("Error while looking up key '%s' from Redis: %s", key, reply->getError());
  d_stats->d_errors += 1;
  return false;
}

namespace
{
void validateRedisUrl(const YaHTTP::URL& parsed, const std::string& url)
{
  if (parsed.protocol.empty() || (parsed.protocol != "redis" && parsed.protocol != "rediss")) {
    throw std::runtime_error("Invalid redis URL: " + url + " - Invalid protocol! Use redis or rediss.");
  }
  else if (parsed.host.empty()) {
    throw std::runtime_error("Invalid redis URL: " + url + " - Host empty.");
  }
}
}

RedisClient::RedisConnection::RedisConnection(const std::string& url)
{
  auto parsed = YaHTTP::URL();
  if (!parsed.parse(url)) {
    validateRedisUrl(parsed, url);
  }

  validateRedisUrl(parsed, url);
  d_url = parsed;

  if (parsed.port == 0) {
    parsed.port = 6379;
  }
  auto context = std::unique_ptr<redisContext, decltype(&redisFree)>(redisConnect(parsed.host.c_str(), parsed.port), redisFree);
  // Check if the context is null or if a specific
  // error occurred.
  if (context == nullptr || context->err) {
    if (context != nullptr) {
      warnlog("Error connecting to redis: %s", context->errstr);
    }
    else {
      warnlog("Can't allocate redis context");
    }
  }

  *(d_context.lock()) = std::move(context);
}

bool RedisClient::RedisConnection::reconnect()
{
  {
    auto context = d_context.read_only_lock();
    if (*context != nullptr) {
      int result = redisReconnect(context->get());
      return result == REDIS_OK;
    }
  }

  auto context = std::unique_ptr<redisContext, decltype(&redisFree)>(redisConnect(d_url.host.c_str(), d_url.port), redisFree);
  // Check if the context is null or if a specific
  // error occurred.
  if (context == nullptr || context->err) {
    if (context != nullptr) {
      warnlog("Error connecting to redis: %s", context->errstr);
      return false;
    }
    else {
      warnlog("Can't allocate redis context");
      return false;
    }
  }

  *(d_context.lock()) = std::move(context);
  return true;
}
#endif
