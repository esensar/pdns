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

std::unique_ptr<RedisReply<std::string>> RedisGetCommand::getValue(redisContext* context, const std::string& key)
{
  redisReply* reply = static_cast<redisReply*>(redisCommand(context, "GET %b%b", d_prefix.data(), d_prefix.length(), key.data(), key.length()));
  return std::make_unique<RedisStringReply>(reply);
}

std::unique_ptr<RedisReply<bool>> RedisGetCommand::keyExists(redisContext* context, const std::string& key)
{
  redisReply* reply = static_cast<redisReply*>(redisCommand(context, "EXISTS %b%b", d_prefix.data(), d_prefix.length(), key.data(), key.length()));
  return std::make_unique<RedisIntReply>(reply);
}

cache_t RedisGetCommand::generateCopyCache([[maybe_unused]] redisContext* context)
{
  return {};
}

bool RedisGetCommand::getFromCopyCache([[maybe_unused]] cache_t& cache, [[maybe_unused]] const std::string& key, [[maybe_unused]] std::string& value)
{
  return false;
}

std::unique_ptr<RedisReply<std::string>> RedisHGetCommand::getValue(redisContext* context, const std::string& key)
{
  redisReply* reply = static_cast<redisReply*>(redisCommand(context, "HGET %b %b", d_hash_key.data(), d_hash_key.length(), key.data(), key.length()));
  return std::make_unique<RedisStringReply>(reply);
}

std::unique_ptr<RedisReply<bool>> RedisHGetCommand::keyExists(redisContext* context, const std::string& key)
{
  redisReply* reply = static_cast<redisReply*>(redisCommand(context, "HEXISTS %b %b", d_hash_key.data(), d_hash_key.length(), key.data(), key.length()));
  return std::make_unique<RedisIntReply>(reply);
}

cache_t RedisHGetCommand::generateCopyCache(redisContext* context)
{
  redisReply* reply = static_cast<redisReply*>(redisCommand(context, "HGETALL %b", d_hash_key.data(), d_hash_key.length()));
  return RedisHashReply(reply).getValue();
}

bool RedisHGetCommand::getFromCopyCache(cache_t& cache, const std::string& key, std::string& value)
{
  auto val = cache.find(key);
  if (val != cache.end()) {
    value = val->second;
    return true;
  }
  return false;
}

std::unique_ptr<RedisReply<std::string>> RedisSismemberCommand::getValue(redisContext* context, const std::string& key)
{
  redisReply* reply = static_cast<redisReply*>(redisCommand(context, "SISMEMBER %b %b", d_set_key.data(), d_set_key.length(), key.data(), key.length()));
  return std::make_unique<RedisIntAsStringReply>(reply);
}

std::unique_ptr<RedisReply<bool>> RedisSismemberCommand::keyExists(redisContext* context, const std::string& key)
{
  redisReply* reply = static_cast<redisReply*>(redisCommand(context, "SISMEMBER %b %b", d_set_key.data(), d_set_key.length(), key.data(), key.length()));
  return std::make_unique<RedisIntReply>(reply);
}

cache_t RedisSismemberCommand::generateCopyCache(redisContext* context)
{
  redisReply* reply = static_cast<redisReply*>(redisCommand(context, "SMEMBERS %b", d_set_key.data(), d_set_key.length()));
  auto elements = RedisSetReply(reply).getValue();
  cache_t result{elements.size()};
  for (auto element : elements) {
    result.emplace(element, "1");
  }
  return result;
}

bool RedisSismemberCommand::getFromCopyCache(cache_t& cache, const std::string& key, std::string& value)
{
  auto val = cache.find(key);
  if (val != cache.end()) {
    value = "1";
    return true;
  }
  return false;
}

std::unique_ptr<RedisReply<std::string>> RedisSscanCommand::getValue(redisContext* context, const std::string& key)
{
  redisReply* reply = static_cast<redisReply*>(redisCommand(context, "SSCAN %b 0 %b", d_set_key.data(), d_set_key.length(), key.data(), key.length()));
  return std::make_unique<RedisScanAsStringReply>(reply);
}

std::unique_ptr<RedisReply<bool>> RedisSscanCommand::keyExists(redisContext* context, const std::string& key)
{
  redisReply* reply = static_cast<redisReply*>(redisCommand(context, "SSCAN %b 0 %b", d_set_key.data(), d_set_key.length(), key.data(), key.length()));
  return std::make_unique<RedisScanAsBoolReply>(reply);
}

cache_t RedisSscanCommand::generateCopyCache(redisContext* context)
{
  redisReply* reply = static_cast<redisReply*>(redisCommand(context, "SMEMBERS %b", d_set_key.data(), d_set_key.length()));
  auto elements = RedisSetReply(reply).getValue();
  cache_t result{elements.size()};
  for (auto element : elements) {
    result.emplace(element, "1");
  }
  return result;
}

bool RedisSscanCommand::getFromCopyCache(cache_t& cache, const std::string& key, std::string& value)
{
  auto val = cache.find(key);
  if (val != cache.end()) {
    value = "1";
    return true;
  }
  return false;
}

bool RedisKVClient::getValue(const std::string& key, std::string& value)
{
  {
    auto cache = d_copyCache.read_lock();
    auto entry = cache->find(key);
    if (entry != cache->end()) {
      value = entry->second;
      return true;
    }
  }

  {
    auto cache = d_resultCache.read_lock();
    auto entry = cache->find(key);
    if (entry != cache->end()) {
      value = entry->second;
      return true;
    }
  }

  auto reply = d_command->getValue(d_connection.getConnection()->get(), key);

  if (d_copyCache.read_lock()->size() == 0) {
    auto newCache = d_command->generateCopyCache(d_connection.getConnection()->get());
    *d_copyCache.write_lock() = newCache;
  }

  if (reply->ok()) {
    value = reply->getValue();
    auto cache = d_resultCache.write_lock();
    cache->emplace(key, value);
    vinfolog("Got value %s for key '%s'", value, key);
    return true;
  }

  vinfolog("Error while looking up key '%s' from Redis: %s", key, (d_connection.getConnection()->get())->errstr);
  return false;
}

bool RedisKVClient::keyExists(const std::string& key)
{
  {
    auto cache = d_copyCache.read_lock();
    auto entry = cache->find(key);
    if (entry != cache->end()) {
      return true;
    }
  }

  {
    auto cache = d_resultCache.read_lock();
    if (cache->find(key) != cache->end()) {
      return true;
    }
  }

  auto connection = d_connection.getConnection();
  auto reply = d_command->keyExists(connection->get(), key);
  if (d_copyCache.read_lock()->size() == 0) {
    auto newCache = d_command->generateCopyCache(d_connection.getConnection()->get());
    *d_copyCache.write_lock() = newCache;
  }
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

RedisKVClient::RedisConnection::RedisConnection(const std::string& url)
{
  auto parsed = YaHTTP::URL();
  if (!parsed.parse(url)) {
    validateRedisUrl(parsed, url);
    // throw std::runtime_error("Invalid redis URL: " + url);
  }

  validateRedisUrl(parsed, url);
  d_url = parsed;

  if (parsed.port == 0) {
    parsed.port = 6379;
  }

  *(d_context.lock()) = std::unique_ptr<redisContext, decltype(&redisFree)>(redisConnect(parsed.host.c_str(), parsed.port), redisFree);

  auto context = d_context.read_only_lock();
  // Check if the context is null or if a specific
  // error occurred.
  if (context->get() == nullptr || context->get()->err) {
    if (context->get() != nullptr) {
      warnlog("Error connecting to redis: %s", context->get()->errstr);
    }
    else {
      warnlog("Can't allocate redis context");
    }
  }
}

bool RedisKVClient::RedisConnection::reconnect()
{
  auto context = d_context.read_only_lock();
  if (context->get() != nullptr) {
    int result = redisReconnect(context->get());
    return result == REDIS_OK;
  }

  return false;
}
