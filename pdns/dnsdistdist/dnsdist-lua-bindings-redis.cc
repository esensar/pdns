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
#include <memory>
#ifdef HAVE_REDIS
#include "redis.hh"
#endif /* HAVE_REDIS */

void setupLuaBindingsRedis([[maybe_unused]] LuaContext& luaCtx, [[maybe_unused]] bool client)
{
#ifdef HAVE_REDIS
  luaCtx.writeFunction("newRedisClient", [client](const std::string& url) {
    if (client) {
      return std::shared_ptr<RedisClient>(nullptr);
    }

    return std::make_shared<RedisClient>(url);
  });

  luaCtx.registerFunction<std::string (std::shared_ptr<RedisClient>::*)(const std::string&)>("get", [](std::shared_ptr<RedisClient>& kvs, const std::string& key) {
    std::string result;
    if (!kvs) {
      return result;
    }

    auto connection = kvs->getConnection();
    auto reply = RedisGetCommand{}(connection->get(), key);

    if (reply->ok()) {
      result = reply->getValue();
    }

    return result;
  });

  luaCtx.registerFunction<bool (std::shared_ptr<RedisClient>::*)(const std::string&)>("exists", [](std::shared_ptr<RedisClient>& kvs, const std::string& key) {
    if (!kvs) {
      return false;
    }

    auto connection = kvs->getConnection();
    auto reply = RedisExistsCommand{}(connection->get(), key);

    if (reply->ok()) {
      return reply->getValue();
    }

    return false;
  });

  luaCtx.registerFunction<std::string (std::shared_ptr<RedisClient>::*)(const std::string&, const std::string&)>("hget", [](std::shared_ptr<RedisClient>& kvs, const std::string& hash_key, const std::string& key) {
    std::string result;
    if (!kvs) {
      return result;
    }

    auto connection = kvs->getConnection();
    auto reply = RedisHGetCommand{}(connection->get(), hash_key, key);

    if (reply->ok()) {
      result = reply->getValue();
    }

    return result;
  });

  luaCtx.registerFunction<LuaAssociativeTable<std::string> (std::shared_ptr<RedisClient>::*)(const std::string&)>("hgetall", [](std::shared_ptr<RedisClient>& kvs, const std::string& hash_key) {
    if (!kvs) {
      return LuaAssociativeTable<std::string>();
    }

    auto connection = kvs->getConnection();
    auto reply = RedisHGetAllCommand{}(connection->get(), hash_key);

    if (reply->ok()) {
      return reply->getValue();
    }

    return LuaAssociativeTable<std::string>();
  });

  luaCtx.registerFunction<bool (std::shared_ptr<RedisClient>::*)(const std::string&, const std::string&)>("hexists", [](std::shared_ptr<RedisClient>& kvs, const std::string& hash_key, const std::string& key) {
    if (!kvs) {
      return false;
    }

    auto connection = kvs->getConnection();
    auto reply = RedisHExistsCommand{}(connection->get(), hash_key, key);

    if (reply->ok()) {
      return reply->getValue();
    }

    return false;
  });

  luaCtx.registerFunction<LuaArray<std::string> (std::shared_ptr<RedisClient>::*)(const std::string&)>("smembers", [](std::shared_ptr<RedisClient>& kvs, const std::string& set_key) {
    if (!kvs) {
      return LuaArray<std::string>();
    }

    auto connection = kvs->getConnection();
    auto reply = RedisSMembersCommand{}(connection->get(), set_key);

    if (reply->ok()) {
      auto members = reply->getValue();
      LuaArray<std::string> result{members.size()};
      for (const auto& member : members) {
        result.emplace_back(result.size() + 1, member);
      }
      return result;
    }

    return LuaArray<std::string>();
  });

  luaCtx.registerFunction<bool (std::shared_ptr<RedisClient>::*)(const std::string&, const std::string&)>("sismember", [](std::shared_ptr<RedisClient>& kvs, const std::string& set_key, const std::string& key) {
    if (!kvs) {
      return false;
    }

    auto connection = kvs->getConnection();
    auto reply = RedisSIsMemberCommand{}(connection->get(), set_key, key);

    if (reply->ok()) {
      return reply->getValue();
    }

    return false;
  });

  luaCtx.registerFunction<bool (std::shared_ptr<RedisClient>::*)(const std::string&, const int&, const std::string&, const int&)>("sscan", [](std::shared_ptr<RedisClient>& kvs, const std::string& set_key, const int& cursor, const std::string& key, const int& count) {
    if (!kvs) {
      return false;
    }

    auto connection = kvs->getConnection();
    auto reply = RedisSScanCommand{}(connection->get(), set_key, cursor, key, count);

    if (reply->ok()) {
      return reply->getValue();
    }

    return false;
  });

  luaCtx.registerFunction<LuaArray<std::string> (std::shared_ptr<RedisClient>::*)(const std::string&, const int&, const int&)>("zrangebylex", [](std::shared_ptr<RedisClient>& kvs, const std::string& set_key, const int& start, const int& stop) {
    if (!kvs) {
      return LuaArray<std::string>();
    }

    auto connection = kvs->getConnection();
    auto reply = RedisZrangeBylexCommand{}(connection->get(), set_key, start, stop);

    if (reply->ok()) {
      auto members = reply->getValue();
      LuaArray<std::string> result{members.size()};
      for (const auto& member : members) {
        result.emplace_back(result.size() + 1, member);
      }
      return result;
    }

    return LuaArray<std::string>();
  });
#endif /* HAVE_REDIS */
}
