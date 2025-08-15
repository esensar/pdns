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
#include "yahttp/yahttp.hpp"
#include <hiredis/hiredis.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

std::unique_ptr<RedisReply<std::string>> RedisGetCommand::getValue(redisContext* context, const std::string& key)
{
  redisReply* reply = static_cast<redisReply*>(redisCommand(context, "GET %s%s", prefix.c_str(), key.c_str()));
  return std::make_unique<RedisStringReply>(reply);
}

std::unique_ptr<RedisReply<bool>> RedisGetCommand::keyExists(redisContext* context, const std::string& key)
{
  redisReply* reply = static_cast<redisReply*>(redisCommand(context, "EXISTS %s%s", prefix.c_str(), key.c_str()));
  return std::make_unique<RedisIntReply>(reply);
}

std::unique_ptr<RedisReply<std::string>> RedisHGetCommand::getValue(redisContext* context, const std::string& key)
{
  redisReply* reply = static_cast<redisReply*>(redisCommand(context, "HGET %s %s", hash_key.c_str(), key.c_str()));
  return std::make_unique<RedisStringReply>(reply);
}

std::unique_ptr<RedisReply<bool>> RedisHGetCommand::keyExists(redisContext* context, const std::string& key)
{
  redisReply* reply = static_cast<redisReply*>(redisCommand(context, "HEXISTS %s %s", hash_key.c_str(), key.c_str()));
  return std::make_unique<RedisIntReply>(reply);
}

std::unique_ptr<RedisReply<std::string>> RedisSismemberCommand::getValue(redisContext* context, const std::string& key)
{
  redisReply* reply = static_cast<redisReply*>(redisCommand(context, "SISMEMBER %s %s", set_key.c_str(), key.c_str()));
  return std::make_unique<RedisIntAsStringReply>(reply);
}

std::unique_ptr<RedisReply<bool>> RedisSismemberCommand::keyExists(redisContext* context, const std::string& key)
{
  redisReply* reply = static_cast<redisReply*>(redisCommand(context, "SISMEMBER %s %s", set_key.c_str(), key.c_str()));
  return std::make_unique<RedisIntReply>(reply);
}

std::unique_ptr<RedisReply<std::string>> RedisSscanCommand::getValue(redisContext* context, const std::string& key)
{
  redisReply* reply = static_cast<redisReply*>(redisCommand(context, "SSCAN %s 0 %s", set_key.c_str(), key.c_str()));
  return std::make_unique<RedisScanAsStringReply>(reply);
}

std::unique_ptr<RedisReply<bool>> RedisSscanCommand::keyExists(redisContext* context, const std::string& key)
{
  redisReply* reply = static_cast<redisReply*>(redisCommand(context, "SSCAN %s 0 %s", set_key.c_str(), key.c_str()));
  return std::make_unique<RedisScanAsBoolReply>(reply);
}

bool RedisKVClient::getValue(const std::string& key, std::string& value)
{
  auto reply = d_command->getValue(d_connection.getConnection(), key);
  if (reply->ok()) {
    value = reply->getValue();
    vinfolog("Got value %s for key '%s'", value, key);
    return true;
  }

  vinfolog("Error while looking up key '%s' from Redis: %s", key, (d_connection.getConnection())->errstr);
  return false;
}

bool RedisKVClient::keyExists(const std::string& key)
{
  auto reply = d_command->keyExists(d_connection.getConnection(), key);
  if (reply->ok()) {
    return reply->getValue();
  }

  vinfolog("Error while looking up key '%s' from Redis: %s", key, (d_connection.getConnection())->errstr);
  return false;
}

void validateRedisUrl(const YaHTTP::URL& parsed, const std::string& url)
{
  if (parsed.protocol.empty() || (parsed.protocol != "redis" && parsed.protocol != "rediss")) {
    throw std::runtime_error("Invalid redis URL: " + url + " - Invalid protocol! Use redis or rediss.");
  }
  else if (parsed.host.empty()) {
    throw std::runtime_error("Invalid redis URL: " + url + " - Host empty.");
  }
}

RedisKVClient::RedisConnection::RedisConnection(const std::string& url)
{
  auto parsed = YaHTTP::URL();
  if (!parsed.parse(url)) {
    validateRedisUrl(parsed, url);
    throw std::runtime_error("Invalid redis URL: " + url);
  }

  validateRedisUrl(parsed, url);

  if (parsed.port == 0) {
    parsed.port = 6379;
  }

  // The `redisContext` type represents the connection
  // to the Redis server. Here, we connect to the
  // default host and port.
  d_context = redisConnect(parsed.host.c_str(), parsed.port);

  // Check if the context is null or if a specific
  // error occurred.
  if (d_context == nullptr || d_context->err) {
    if (d_context != nullptr) {
      warnlog("Error connecting to redis: %s", d_context->errstr);
    }
    else {
      warnlog("Can't allocate redis context");
    }
  }
}

RedisKVClient::RedisConnection::~RedisConnection()
{
  if (d_context) {
    redisFree(d_context);
  }
}

bool RedisKVClient::RedisConnection::reconnect()
{
  if (d_context) {
    int result = redisReconnect(d_context);
    return result == REDIS_OK;
  }

  return false;
}
