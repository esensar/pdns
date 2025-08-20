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

#include "iputils.hh"
#include "lock.hh"
#include "yahttp/yahttp.hpp"
#include "yahttp/url.hpp"
#include <hiredis/hiredis.h>
#include <memory>
#include <string>

using cache_t = std::unordered_map<std::string, std::string>;

template <typename T>
class RedisReply
{
public:
  RedisReply(redisReply* reply) :
    d_reply(reply)
  {
  }
  virtual ~RedisReply()
  {
    if (d_reply) {
      freeReplyObject(d_reply);
    }
  }

  virtual bool ok()
  {
    return d_reply;
  }

  virtual T getValue() = 0;

protected:
  redisReply* d_reply;
};

class RedisStringReply : public RedisReply<std::string>
{
public:
  RedisStringReply(redisReply* reply) :
    RedisReply(reply)
  {
  }
  ~RedisStringReply() = default;
  bool ok() override
  {
    return d_reply && (d_reply->str);
  }
  std::string getValue() override
  {
    return std::string(d_reply->str, d_reply->len);
  }
};

class RedisIntAsStringReply : public RedisReply<std::string>
{
public:
  RedisIntAsStringReply(redisReply* reply) :
    RedisReply(reply)
  {
  }
  ~RedisIntAsStringReply() = default;
  bool ok() override
  {
    return d_reply && d_reply->type == REDIS_REPLY_INTEGER;
  }
  std::string getValue() override
  {
    return std::to_string(d_reply->integer);
  }
};

class RedisIntReply : public RedisReply<bool>
{
public:
  RedisIntReply(redisReply* reply) :
    RedisReply(reply)
  {
  }
  ~RedisIntReply() = default;
  bool getValue()
  {
    return d_reply->integer > 0;
  }
};

class RedisScanAsStringReply : public RedisReply<std::string>
{
public:
  RedisScanAsStringReply(redisReply* reply) :
    RedisReply(reply)
  {
  }
  ~RedisScanAsStringReply() = default;
  bool ok() override
  {
    return d_reply && d_reply->type == REDIS_REPLY_ARRAY && d_reply->elements == 2;
  }
  std::string getValue() override
  {
    auto members = d_reply->element[1];
    std::string result;
    for (size_t i = 0; i < members->elements; i++) {
      if (i) {
        result += ", ";
      }
      result += members->element[i]->str;
    }
    return result;
  }
};

class RedisScanAsBoolReply : public RedisReply<bool>
{
public:
  RedisScanAsBoolReply(redisReply* reply) :
    RedisReply(reply)
  {
  }
  ~RedisScanAsBoolReply() = default;
  bool ok() override
  {
    return d_reply && d_reply->type == REDIS_REPLY_ARRAY && d_reply->elements == 2 && d_reply->element[0]->type == REDIS_REPLY_BIGNUM;
  }
  bool getValue() override
  {
    return std::strcmp(d_reply->element[0]->str, "0") != 0;
  }
};

class RedisHashReply : public RedisReply<std::unordered_map<std::string, std::string>>
{
public:
  RedisHashReply(redisReply* reply) :
    RedisReply(reply)
  {
  }
  ~RedisHashReply() = default;
  bool ok() override
  {
    return d_reply && d_reply->type == REDIS_REPLY_ARRAY && d_reply->elements % 2 == 0;
  }
  std::unordered_map<std::string, std::string> getValue() override
  {
    std::unordered_map<std::string, std::string> result{d_reply->elements / 2};
    for (size_t i = 0; i < d_reply->elements; i += 2) {
      auto key = std::string(d_reply->element[i]->str, d_reply->element[i]->len);
      auto value = std::string(d_reply->element[i + 1]->str, d_reply->element[i + 1]->len);
      result.emplace(key, value);
    }
    return result;
  }
};

class RedisSetReply : public RedisReply<std::unordered_set<std::string>>
{
public:
  RedisSetReply(redisReply* reply) :
    RedisReply(reply)
  {
  }
  ~RedisSetReply() = default;
  bool ok() override
  {
    return d_reply && d_reply->type == REDIS_REPLY_ARRAY;
  }
  std::unordered_set<std::string> getValue() override
  {
    std::unordered_set<std::string> result{d_reply->elements};
    for (size_t i = 0; i < d_reply->elements; i++) {
      result.emplace(d_reply->element[i]->str);
    }
    return result;
  }
};

class RedisCommand
{
public:
  virtual ~RedisCommand() = default;
  virtual bool getFromCopyCache(cache_t& cache, const std::string& key, std::string& value) = 0;
  virtual std::unique_ptr<RedisReply<std::string>> getValue(redisContext* context, const std::string& key) = 0;
  virtual cache_t generateCopyCache(redisContext* context) = 0;
  virtual std::unique_ptr<RedisReply<bool>> keyExists(redisContext* context, const std::string& key) = 0;
};

class RedisGetCommand : public RedisCommand
{
public:
  RedisGetCommand(const std::string& prefix = "") :
    d_prefix(prefix)
  {
  }
  ~RedisGetCommand() = default;
  bool getFromCopyCache(cache_t& cache, const std::string& key, std::string& value) override;
  std::unique_ptr<RedisReply<std::string>> getValue(redisContext* context, const std::string& key) override;
  cache_t generateCopyCache(redisContext* context) override;
  std::unique_ptr<RedisReply<bool>> keyExists(redisContext* context, const std::string& key) override;

private:
  std::string d_prefix;
};

class RedisHGetCommand : public RedisCommand
{
public:
  RedisHGetCommand(const std::string& hash_key) :
    d_hash_key(hash_key)
  {
  }
  ~RedisHGetCommand() = default;
  bool getFromCopyCache(cache_t& cache, const std::string& key, std::string& value) override;
  std::unique_ptr<RedisReply<std::string>> getValue(redisContext* context, const std::string& key) override;
  cache_t generateCopyCache(redisContext* context) override;
  std::unique_ptr<RedisReply<bool>> keyExists(redisContext* context, const std::string& key) override;

private:
  std::string d_hash_key;
};

class RedisSismemberCommand : public RedisCommand
{
public:
  RedisSismemberCommand(const std::string& set_key) :
    d_set_key(set_key)
  {
  }
  ~RedisSismemberCommand() = default;
  bool getFromCopyCache(cache_t& cache, const std::string& key, std::string& value) override;
  std::unique_ptr<RedisReply<std::string>> getValue(redisContext* context, const std::string& key) override;
  cache_t generateCopyCache(redisContext* context) override;
  std::unique_ptr<RedisReply<bool>> keyExists(redisContext* context, const std::string& key) override;

private:
  std::string d_set_key;
};

class RedisSscanCommand : public RedisCommand
{
public:
  RedisSscanCommand(const std::string& set_key) :
    d_set_key(set_key)
  {
  }
  ~RedisSscanCommand() = default;
  bool getFromCopyCache(cache_t& cache, const std::string& key, std::string& value) override;
  std::unique_ptr<RedisReply<std::string>> getValue(redisContext* context, const std::string& key) override;
  cache_t generateCopyCache(redisContext* context) override;
  std::unique_ptr<RedisReply<bool>> keyExists(redisContext* context, const std::string& key) override;

private:
  std::string d_set_key;
};

class RedisKVClient
{
public:
  RedisKVClient(const std::string& url, std::unique_ptr<RedisCommand>&& command = std::make_unique<RedisGetCommand>()) :
    d_connection(url), d_command(std::move(command))
  {
  }

  bool getValue(const std::string& key, std::string& value);
  bool keyExists(const std::string& key);

private:
  class RedisConnection
  {
  public:
    RedisConnection(const std::string& url);
    ~RedisConnection() = default;
    bool reconnect();
    LockGuardedHolder<const std::unique_ptr<redisContext, decltype(&redisFree)>> getConnection()
    {
      return d_context.read_only_lock();
    }

  private:
    LockGuarded<std::unique_ptr<redisContext, decltype(&redisFree)>> d_context{std::unique_ptr<redisContext, decltype(&redisFree)>(nullptr, redisFree)};
    YaHTTP::URL d_url;
  };

  RedisConnection d_connection;
  std::unique_ptr<RedisCommand> d_command;
  SharedLockGuarded<cache_t> d_resultCache;
  SharedLockGuarded<cache_t> d_copyCache;
};
