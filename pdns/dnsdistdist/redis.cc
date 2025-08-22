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

#include "redis.hh"
#include "dolog.hh"
#include <hiredis/hiredis.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

std::unique_ptr<RedisReplyInterface<std::string>> RedisGetCommand::operator()(redisContext* context, const std::string& key) const
{
  redisReply* reply = static_cast<redisReply*>(redisCommand(context, "GET %b", key.data(), key.length()));
  return std::make_unique<RedisStringReply>(reply);
}

std::unique_ptr<RedisReplyInterface<bool>> RedisExistsCommand::operator()(redisContext* context, const std::string& key) const
{
  redisReply* reply = static_cast<redisReply*>(redisCommand(context, "EXISTS %b", key.data(), key.length()));
  return std::make_unique<RedisIntAsBoolReply>(std::make_unique<RedisIntReply>(reply));
}

std::unique_ptr<RedisReplyInterface<std::string>> RedisHGetCommand::operator()(redisContext* context, const std::string& hash_key, const std::string& key) const
{
  redisReply* reply = static_cast<redisReply*>(redisCommand(context, "HGET %b %b", hash_key.data(), hash_key.length(), key.data(), key.length()));
  return std::make_unique<RedisStringReply>(reply);
}

std::unique_ptr<RedisReplyInterface<std::unordered_map<std::string, std::string>>> RedisHGetAllCommand::operator()(redisContext* context, const std::string& hash_key) const
{
  redisReply* reply = static_cast<redisReply*>(redisCommand(context, "HGETALL %b", hash_key.data(), hash_key.length()));
  return std::make_unique<RedisHashReply>(reply);
}

std::unique_ptr<RedisReplyInterface<bool>> RedisHExistsCommand::operator()(redisContext* context, const std::string& hash_key, const std::string& key) const
{
  redisReply* reply = static_cast<redisReply*>(redisCommand(context, "HEXISTS %b %b", hash_key.data(), hash_key.length(), key.data(), key.length()));
  return std::make_unique<RedisIntAsBoolReply>(std::make_unique<RedisIntReply>(reply));
}

std::unique_ptr<RedisReplyInterface<bool>> RedisSIsMemberCommand::operator()(redisContext* context, const std::string& set_key, const std::string& key) const
{
  redisReply* reply = static_cast<redisReply*>(redisCommand(context, "SISMEMBER %b %b", set_key.data(), set_key.length(), key.data(), key.length()));
  return std::make_unique<RedisIntAsBoolReply>(std::make_unique<RedisIntReply>(reply));
}

std::unique_ptr<RedisReplyInterface<std::unordered_set<std::string>>> RedisSMembersCommand::operator()(redisContext* context, const std::string& set_key) const
{
  redisReply* reply = static_cast<redisReply*>(redisCommand(context, "SMEMBERS %b", set_key.data(), set_key.length()));
  return std::make_unique<RedisSetReply>(reply);
}

std::unique_ptr<RedisReplyInterface<bool>> RedisSScanCommand::operator()(redisContext* context, const std::string& set_key, const size_t& cursor, const std::string& key, const size_t& count) const
{
  redisReply* reply = static_cast<redisReply*>(redisCommand(context, "SSCAN %b %d %b %d", set_key.data(), set_key.length(), cursor, key.data(), key.length(), count));
  return std::make_unique<RedisScanAsBoolReply>(reply);
}

std::unique_ptr<RedisReplyInterface<std::unordered_set<std::string>>> RedisZrangeBylexCommand::operator()(redisContext* context, const std::string& set_key, const size_t& start, const size_t& stop) const
{
  redisReply* reply = static_cast<redisReply*>(redisCommand(context, "ZRANGE %b %d %d BYLEX", set_key.data(), set_key.length(), start, stop));
  return std::make_unique<RedisSetReply>(reply);
}

std::unique_ptr<RedisReplyInterface<std::string>> RedisGetLookupAction::getValue(redisContext* context, const std::string& key) const
{
  return d_getCommand(context, d_prefix + key);
}

std::unique_ptr<RedisReplyInterface<bool>> RedisGetLookupAction::keyExists(redisContext* context, const std::string& key) const
{
  return d_existsCommand(context, d_prefix + key);
}

std::unordered_map<std::string, std::string> RedisGetLookupAction::generateCopyCache([[maybe_unused]] redisContext* context) const
{
  return {};
}

bool RedisGetLookupAction::getFromCopyCache([[maybe_unused]] const GenericCacheInterface<std::string, std::string>& cache, [[maybe_unused]] const std::string& key, [[maybe_unused]] std::string& value) const
{
  return false;
}

std::unique_ptr<RedisReplyInterface<std::string>> RedisHGetLookupAction::getValue(redisContext* context, const std::string& key) const
{
  return d_getCommand(context, d_hash_key, key);
}

std::unique_ptr<RedisReplyInterface<bool>> RedisHGetLookupAction::keyExists(redisContext* context, const std::string& key) const
{
  return d_existsCommand(context, d_hash_key, key);
}

std::unordered_map<std::string, std::string> RedisHGetLookupAction::generateCopyCache(redisContext* context) const
{
  return d_getAllCommand(context, d_hash_key)->getValue();
}

bool RedisHGetLookupAction::getFromCopyCache(const GenericCacheInterface<std::string, std::string>& cache, const std::string& key, std::string& value) const
{
  return cache.getValue(key, value);
}

std::unique_ptr<RedisReplyInterface<std::string>> RedisSismemberLookupAction::getValue(redisContext* context, const std::string& key) const
{
  return std::make_unique<RedisBoolAsStringReply>(d_sIsMemberCommand(context, d_set_key, key));
}

std::unique_ptr<RedisReplyInterface<bool>> RedisSismemberLookupAction::keyExists(redisContext* context, const std::string& key) const
{
  return d_sIsMemberCommand(context, d_set_key, key);
}

std::unordered_map<std::string, std::string> RedisSismemberLookupAction::generateCopyCache(redisContext* context) const
{
  auto elements = d_sMembersCommand(context, d_set_key)->getValue();
  std::unordered_map<std::string, std::string> result{elements.size()};
  for (auto element : elements) {
    result.emplace(element, "1");
  }
  return result;
}

bool RedisSismemberLookupAction::getFromCopyCache(const GenericCacheInterface<std::string, std::string>& cache, const std::string& key, std::string& value) const
{
  if (cache.contains(key)) {
    value = "1";
    return true;
  }
  return false;
}

std::unique_ptr<RedisReplyInterface<std::string>> RedisSscanLookupAction::getValue(redisContext* context, const std::string& key) const
{
  redisReply* reply = static_cast<redisReply*>(redisCommand(context, "SSCAN %b 0 %b", d_set_key.data(), d_set_key.length(), key.data(), key.length()));
  return std::make_unique<RedisScanAsStringReply>(reply);
}

std::unique_ptr<RedisReplyInterface<bool>> RedisSscanLookupAction::keyExists(redisContext* context, const std::string& key) const
{
  redisReply* reply = static_cast<redisReply*>(redisCommand(context, "SSCAN %b 0 %b", d_set_key.data(), d_set_key.length(), key.data(), key.length()));
  return std::make_unique<RedisScanAsBoolReply>(reply);
}

std::unordered_map<std::string, std::string> RedisSscanLookupAction::generateCopyCache(redisContext* context) const
{
  redisReply* reply = static_cast<redisReply*>(redisCommand(context, "SMEMBERS %b", d_set_key.data(), d_set_key.length()));
  auto elements = RedisSetReply(reply).getValue();
  std::unordered_map<std::string, std::string> result{elements.size()};
  for (auto element : elements) {
    result.emplace(element, "1");
  }
  return result;
}

bool RedisSscanLookupAction::getFromCopyCache(const GenericCacheInterface<std::string, std::string>& cache, const std::string& key, std::string& value) const
{
  if (cache.contains(key)) {
    value = "1";
    return true;
  }
  return false;
}

bool ResultCachingRedisClient::getValue(const std::string& key, std::string& value)
{
  if (d_resultCache->getValue(key, value)) {
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

void CopyCache::insert(const std::string& key, std::string value)
{
  auto map = d_map.write_lock();
  map->emplace(key, value);
};

bool CopyCache::getValue(const std::string& key, std::string& value) const
{
  auto map = d_map.read_lock();

  auto entry = map->find(key);
  if (entry != map->end()) {
    value = entry->second;
    return true;
  }

  return false;
};

bool CopyCache::contains(const std::string& key) const
{
  auto map = d_map.read_lock();
  return map->find(key) != map->end();
};

bool CopyCache::needsUpdate() const
{
  auto map = d_map.read_lock();
  return map->size() == 0;
};

void CopyCache::insertBatch(std::unordered_map<std::string, std::string> batch) const
{
  auto map = d_map.write_lock();

  for (auto entry : batch) {
    map->emplace(entry);
  }
};

size_t CopyCache::purgeExpired([[maybe_unused]] size_t upTo, [[maybe_unused]] const time_t now)
{
  return 0;
};
size_t CopyCache::expunge([[maybe_unused]] size_t upTo)
{
  return 0;
};

bool CopyCachingRedisClient::getValue(const std::string& key, std::string& value)
{
  if (d_copyCache->getValue(key, value)) {
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

bool RedisKVClient::getValue(const std::string& key, std::string& value)
{
  auto connection = d_client->getConnection();
  auto reply = d_lookupAction->getValue(connection->get(), key);

  if (reply->ok()) {
    value = reply->getValue();
    vinfolog("Got value %s for key '%s'", value, key);
    return true;
  }

  vinfolog("Error while looking up key '%s' from Redis: %s", key, (connection->get())->errstr);
  return false;
}

std::unordered_map<std::string, std::string> RedisKVClient::generateCopyCache()
{
  return d_lookupAction->generateCopyCache(d_client->getConnection()->get());
}

bool RedisKVClient::keyExists(const std::string& key)
{
  auto connection = d_client->getConnection();
  auto reply = d_lookupAction->keyExists(connection->get(), key);
  if (reply->ok()) {
    return reply->getValue();
  }

  vinfolog("Error while looking up key '%s' from Redis: %s", key, (connection->get())->errstr);
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
  auto context = d_context.read_only_lock();
  if (context->get() != nullptr) {
    int result = redisReconnect(context->get());
    return result == REDIS_OK;
  }

  return false;
}
