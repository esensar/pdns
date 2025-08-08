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
#include "redis.hh"
#include "dolog.hh"
#include <hiredis/hiredis.h>
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

RedisStringReply RedisGetCommand::getValue(redisContext* context, const std::string& key)
{
  redisReply* reply = static_cast<redisReply*>(redisCommand(context, "GET %s", key.c_str()));
  return RedisStringReply(reply);
}

RedisIntReply RedisGetCommand::keyExists(redisContext* context, const std::string& key)
{
  redisReply* reply = static_cast<redisReply*>(redisCommand(context, "EXISTS %s", key.c_str()));
  return RedisIntReply(reply);
}

void RedisClient::reconnect()
{
  d_connection.reconnect();
}

bool RedisClient::getValue(const std::string& key, std::string& value)
{
  auto reply = d_command->getValue(d_connection.getConnection(), key);
  if (reply.ok()) {
    value = reply.getValue();
    vinfolog("Got value %s for key '%s'", value, key);
    return true;
  }

  vinfolog("Error while looking up key '%s' from Redis: %s", key, (d_connection.getConnection())->errstr);
  return false;
}

bool RedisClient::keyExists(const std::string& key)
{
  auto reply = d_command->keyExists(d_connection.getConnection(), key);
  if (reply.ok()) {
    return reply.getValue() > 0;
  }

  vinfolog("Error while looking up key '%s' from Redis: %s", key, (d_connection.getConnection())->errstr);
  return false;
}

RedisClient::RedisConnection::RedisConnection(const ComboAddress& address)
{
  // The `redisContext` type represents the connection
  // to the Redis server. Here, we connect to the
  // default host and port.
  d_context = redisConnect(address.toString().c_str(), address.getPort());

  // Check if the context is null or if a specific
  // error occurred.
  if (d_context == nullptr || d_context->err) {
    if (d_context != nullptr) {
      warnlog("Error: %s", d_context->errstr);
    }
    else {
      warnlog("Can't allocate redis context");
    }
  }
}

RedisClient::RedisConnection::~RedisConnection()
{
  if (d_context) {
    redisFree(d_context);
  }
}

void RedisClient::RedisConnection::reconnect()
{
  if (d_context) {
    redisReconnect(d_context);
  }
}
