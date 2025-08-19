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
  redisReply* reply = static_cast<redisReply*>(redisCommand(context, "GET %s%s", d_prefix.c_str(), key.c_str()));
  return std::make_unique<RedisStringReply>(reply);
}

std::unique_ptr<RedisReply<bool>> RedisGetCommand::keyExists(redisContext* context, const std::string& key)
{
  redisReply* reply = static_cast<redisReply*>(redisCommand(context, "EXISTS %s%s", d_prefix.c_str(), key.c_str()));
  return std::make_unique<RedisIntReply>(reply);
}

std::unique_ptr<RedisReply<std::string>> RedisHGetCommand::getValue(redisContext* context, const std::string& key)
{
  redisReply* reply = static_cast<redisReply*>(redisCommand(context, "HGET %s %s", d_hash_key.c_str(), key.c_str()));
  return std::make_unique<RedisStringReply>(reply);
}

std::unique_ptr<RedisReply<bool>> RedisHGetCommand::keyExists(redisContext* context, const std::string& key)
{
  redisReply* reply = static_cast<redisReply*>(redisCommand(context, "HEXISTS %s %s", d_hash_key.c_str(), key.c_str()));
  return std::make_unique<RedisIntReply>(reply);
}

std::unique_ptr<RedisReply<std::string>> RedisSismemberCommand::getValue(redisContext* context, const std::string& key)
{
  redisReply* reply = static_cast<redisReply*>(redisCommand(context, "SISMEMBER %s %s", d_set_key.c_str(), key.c_str()));
  return std::make_unique<RedisIntAsStringReply>(reply);
}

std::unique_ptr<RedisReply<bool>> RedisSismemberCommand::keyExists(redisContext* context, const std::string& key)
{
  redisReply* reply = static_cast<redisReply*>(redisCommand(context, "SISMEMBER %s %s", d_set_key.c_str(), key.c_str()));
  return std::make_unique<RedisIntReply>(reply);
}

std::unique_ptr<RedisReply<std::string>> RedisSscanCommand::getValue(redisContext* context, const std::string& key)
{
  redisReply* reply = static_cast<redisReply*>(redisCommand(context, "SSCAN %s 0 %s", d_set_key.c_str(), key.c_str()));
  return std::make_unique<RedisScanAsStringReply>(reply);
}

std::unique_ptr<RedisReply<bool>> RedisSscanCommand::keyExists(redisContext* context, const std::string& key)
{
  redisReply* reply = static_cast<redisReply*>(redisCommand(context, "SSCAN %s 0 %s", d_set_key.c_str(), key.c_str()));
  return std::make_unique<RedisScanAsBoolReply>(reply);
}

bool RedisKVClient::getValue(const std::string& key, std::string& value)
{
  {
    auto cache = d_result_cache.read_lock();
    auto entry = cache->find(key);
    if (entry != cache->end()) {
      value = entry->second;
      vinfolog("Got value %s for key '%s' from cache", value, key);
      return true;
    }
  }

  auto reply = d_command->getValue(d_connection.getConnection()->get(), key);
  if (reply->ok()) {
    value = reply->getValue();
    auto cache = d_result_cache.write_lock();
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
    auto cache = d_result_cache.read_lock();
    if (cache->find(key) != cache->end()) {
      return true;
    }
  }

  auto connection = d_connection.getConnection();
  auto reply = d_command->keyExists(connection->get(), key);
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
