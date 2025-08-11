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
#include <hiredis/hiredis.h>
#include <memory>
#include <string>

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

protected:
  redisReply* d_reply;
};

class RedisStringReply : public RedisReply
{
public:
  RedisStringReply(redisReply* reply) :
    RedisReply(reply)
  {
  }
  ~RedisStringReply() = default;
  bool ok() override
  {
    return d_reply && d_reply->str;
  }
  std::string getValue()
  {
    return std::string(d_reply->str);
  }
};

class RedisIntReply : public RedisReply
{
public:
  RedisIntReply(redisReply* reply) :
    RedisReply(reply)
  {
  }
  ~RedisIntReply() = default;
  long long getValue()
  {
    return d_reply->integer;
  }
};

class RedisCommand
{
public:
  virtual ~RedisCommand() = default;
  virtual RedisStringReply getValue(redisContext* context, const std::string& key) = 0;
  virtual RedisIntReply keyExists(redisContext* context, const std::string& key) = 0;
};

class RedisGetCommand : public RedisCommand
{
public:
  RedisGetCommand(const std::string& prefix = "") :
    prefix(prefix)
  {
  }
  ~RedisGetCommand() = default;
  RedisStringReply getValue(redisContext* context, const std::string& key) override;
  RedisIntReply keyExists(redisContext* context, const std::string& key) override;

private:
  std::string prefix;
};

class RedisHGetCommand : public RedisCommand
{
public:
  RedisHGetCommand(const std::string& hash_key) :
    hash_key(hash_key)
  {
  }
  ~RedisHGetCommand() = default;
  RedisStringReply getValue(redisContext* context, const std::string& key) override;
  RedisIntReply keyExists(redisContext* context, const std::string& key) override;

private:
  std::string hash_key;
};

class RedisClient
{
public:
  RedisClient(const ComboAddress& address, std::unique_ptr<RedisCommand>&& command = std::make_unique<RedisGetCommand>()) :
    d_connection(address), d_command(std::move(command))
  {
  }

  bool getValue(const std::string& key, std::string& value);
  bool keyExists(const std::string& key);

private:
  void reconnect();

  class RedisConnection
  {
  public:
    RedisConnection(const ComboAddress& address);
    ~RedisConnection();
    void reconnect();
    redisContext* getConnection()
    {
      return d_context;
    }

  private:
    redisContext* d_context;
  };

  RedisConnection d_connection;
  std::unique_ptr<RedisCommand> d_command;
};
