#!/usr/bin/env python
import os
import socket
import time
import unittest
from threading import Thread

import dns
import fakeredis
from netaddr import IPNetwork, IPSet

from dnsdisttests import DNSDistTest, pickAvailablePort


class RedisGet(object):
    def testRedisGetKvs(self):
        """
        Redis: Match on Qname in KVS
        """
        name = "kvs.correct.tests.powerdns.com."
        query = dns.message.make_query(name, "A", "IN")
        # dnsdist set RA = RD for spoofed responses
        query.flags &= ~dns.flags.RD
        expectedResponse = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name, 3600, dns.rdataclass.IN, dns.rdatatype.A, "5.6.7.8")
        expectedResponse.answer.append(rrset)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (receivedQuery, receivedResponse) = sender(query, response=None, useQueue=False)
            self.assertFalse(receivedQuery)
            self.assertTrue(receivedResponse)
            self.assertEqual(expectedResponse, receivedResponse)

    def testRedisGetLua(self):
        """
        Redis: match on QName in Lua action
        """
        name = "lua-get.tests.powerdns.com."
        query = dns.message.make_query(name, "A", "IN")
        # dnsdist set RA = RD for spoofed responses
        query.flags &= ~dns.flags.RD
        expectedResponse = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name, 3600, dns.rdataclass.IN, dns.rdatatype.A, "7.8.9.10")
        expectedResponse.answer.append(rrset)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (receivedQuery, receivedResponse) = sender(query, response=None, useQueue=False)
            self.assertFalse(receivedQuery)
            self.assertTrue(receivedResponse)
            self.assertEqual(expectedResponse, receivedResponse)

    def testRedisGetKvsFailedLookup(self):
        """
        Redis: QName not found in KVS
        """
        name = "kvs.wrong.tests.powerdns.com."
        query = dns.message.make_query(name, "A", "IN")
        # dnsdist set RA = RD for spoofed responses
        query.flags &= ~dns.flags.RD
        expectedResponse = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name, 3600, dns.rdataclass.IN, dns.rdatatype.A, "9.9.9.9")
        expectedResponse.answer.append(rrset)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (receivedQuery, receivedResponse) = sender(query, response=None, useQueue=False)
            self.assertFalse(receivedQuery)
            self.assertTrue(receivedResponse)
            self.assertEqual(expectedResponse, receivedResponse)

    def testRedisGetLuaFailedLookup(self):
        """
        Redis: QName not found in Lua lookup
        """
        name = "lua-get.wrong.tests.powerdns.com."
        query = dns.message.make_query(name, "A", "IN")
        # dnsdist set RA = RD for spoofed responses
        query.flags &= ~dns.flags.RD
        expectedResponse = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name, 3600, dns.rdataclass.IN, dns.rdatatype.A, "9.9.9.10")
        expectedResponse.answer.append(rrset)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (receivedQuery, receivedResponse) = sender(query, response=None, useQueue=False)
            self.assertFalse(receivedQuery)
            self.assertTrue(receivedResponse)
            self.assertEqual(expectedResponse, receivedResponse)


class RedisHGet(object):
    def testRedisHGetKvs(self):
        """
        Redis: Match on Qname in KVS
        """
        name = "kvs.correct.tests.powerdns.com."
        query = dns.message.make_query(name, "A", "IN")
        # dnsdist set RA = RD for spoofed responses
        query.flags &= ~dns.flags.RD
        expectedResponse = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name, 3600, dns.rdataclass.IN, dns.rdatatype.A, "5.6.7.8")
        expectedResponse.answer.append(rrset)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (receivedQuery, receivedResponse) = sender(query, response=None, useQueue=False)
            self.assertFalse(receivedQuery)
            self.assertTrue(receivedResponse)
            self.assertEqual(expectedResponse, receivedResponse)

    def testRedisHGetLua(self):
        """
        Redis: match on QName in GET Lua action
        """
        name = "lua-get.tests.powerdns.com."
        query = dns.message.make_query(name, "A", "IN")
        # dnsdist set RA = RD for spoofed responses
        query.flags &= ~dns.flags.RD
        expectedResponse = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name, 3600, dns.rdataclass.IN, dns.rdatatype.A, "7.8.9.11")
        expectedResponse.answer.append(rrset)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (receivedQuery, receivedResponse) = sender(query, response=None, useQueue=False)
            self.assertFalse(receivedQuery)
            self.assertTrue(receivedResponse)
            self.assertEqual(expectedResponse, receivedResponse)

    def testRedisHGetLua(self):
        """
        Redis: match on QName in HGET Lua action
        """
        name = "lua-hget.tests.powerdns.com."
        query = dns.message.make_query(name, "A", "IN")
        # dnsdist set RA = RD for spoofed responses
        query.flags &= ~dns.flags.RD
        expectedResponse = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name, 3600, dns.rdataclass.IN, dns.rdatatype.A, "7.8.9.12")
        expectedResponse.answer.append(rrset)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (receivedQuery, receivedResponse) = sender(query, response=None, useQueue=False)
            self.assertFalse(receivedQuery)
            self.assertTrue(receivedResponse)
            self.assertEqual(expectedResponse, receivedResponse)

    def testRedisHGetKvsFailedLookup(self):
        """
        Redis: QName not found in KVS
        """
        name = "kvs.wrong.tests.powerdns.com."
        query = dns.message.make_query(name, "A", "IN")
        # dnsdist set RA = RD for spoofed responses
        query.flags &= ~dns.flags.RD
        expectedResponse = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name, 3600, dns.rdataclass.IN, dns.rdatatype.A, "9.9.9.9")
        expectedResponse.answer.append(rrset)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (receivedQuery, receivedResponse) = sender(query, response=None, useQueue=False)
            self.assertFalse(receivedQuery)
            self.assertTrue(receivedResponse)
            self.assertEqual(expectedResponse, receivedResponse)

    def testRedisGetLuaFailedLookup(self):
        """
        Redis: QName not found in Lua GET lookup
        """
        name = "lua-get.wrong.tests.powerdns.com."
        query = dns.message.make_query(name, "A", "IN")
        # dnsdist set RA = RD for spoofed responses
        query.flags &= ~dns.flags.RD
        expectedResponse = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name, 3600, dns.rdataclass.IN, dns.rdatatype.A, "9.9.9.10")
        expectedResponse.answer.append(rrset)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (receivedQuery, receivedResponse) = sender(query, response=None, useQueue=False)
            self.assertFalse(receivedQuery)
            self.assertTrue(receivedResponse)
            self.assertEqual(expectedResponse, receivedResponse)

    def testRedisHGetLuaFailedLookup(self):
        """
        Redis: QName not found in Lua HGET lookup
        """
        name = "lua-hget.wrong.tests.powerdns.com."
        query = dns.message.make_query(name, "A", "IN")
        # dnsdist set RA = RD for spoofed responses
        query.flags &= ~dns.flags.RD
        expectedResponse = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name, 3600, dns.rdataclass.IN, dns.rdatatype.A, "9.9.9.11")
        expectedResponse.answer.append(rrset)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (receivedQuery, receivedResponse) = sender(query, response=None, useQueue=False)
            self.assertFalse(receivedQuery)
            self.assertTrue(receivedResponse)
            self.assertEqual(expectedResponse, receivedResponse)


@unittest.skipIf("SKIP_REDIS_TESTS" in os.environ, "Redis tests are disabled")
class RedisTest(DNSDistTest):
    _redisPort = pickAvailablePort()
    _lookupAction = "get"
    _dataName = ""
    _config_template = """
    newServer{address="127.0.0.1:%d"}

    dataName = "%s"
    redis = newRedisClient("redis://127.0.0.1:%d")
    kvs = newRedisKVStore(redis, { lookupAction = "%s", dataName = dataName })

    function lua_redis_get_query(dq)
        if not redis:exists(dq.qname:toString()) then
            return DNSAction.None
        end
        local data = redis:get(dq.qname:toString())
        if data == nil then
            return DNSAction.None
        end
        return DNSAction.Spoof, data
    end

    function lua_redis_hget_query(dq)
        if not redis:hexists(dataName, dq.qname:toString()) then
            return DNSAction.None
        end
        local data = redis:hget(dataName, dq.qname:toString())
        if data == nil then
            return DNSAction.None
        end
        return DNSAction.Spoof, data
    end

    -- does a lookup in the Redis database using the qname as key, and store the result into the 'kvs-qname-result' tag
    addAction(RegexRule('kvs.*'), KeyValueStoreLookupAction(kvs, KeyValueLookupKeyQName(false), 'kvs-qname-result'))

    -- if the value of the 'kvs-qname-result' is set to 'test-result', spoof a response
    addAction(TagRule('kvs-qname-result', 'test-result'), SpoofAction('5.6.7.8'))

    -- does a lookup using get and directly spoofs if found
    addAction(RegexRule('lua-get.*'), LuaAction(lua_redis_get_query))

    -- does a lookup using hget and directly spoofs if found
    addAction(RegexRule('lua-hget.*'), LuaAction(lua_redis_hget_query))

    -- otherwise, spoof a different response
    addAction(RegexRule('kvs.*'), SpoofAction('9.9.9.9'))
    addAction(RegexRule('lua-get.*'), SpoofAction('9.9.9.10'))
    addAction(RegexRule('lua-hget.*'), SpoofAction('9.9.9.11'))
    """
    _config_params = ["_testServerPort", "_dataName", "_redisPort", "_lookupAction"]

    @classmethod
    def setUpRedis(cls):
        print("Configuring Redis for test")
        cls._redisPort = pickAvailablePort()
        cls._redisServer = fakeredis.TcpFakeServer(("localhost", cls._redisPort))
        cls._redisThread = Thread(target=cls._redisServer.serve_forever, daemon=True)
        cls._redisThread.start()

    @classmethod
    def tearDownClass(cls):
        super(RedisTest, cls).tearDownClass()
        cls._redisServer.shutdown()
        cls._redisThread.join()


class TestRedisGetSimple(RedisTest, RedisGet):
    @classmethod
    def setUpRedis(cls):
        super(TestRedisGetSimple, cls).setUpRedis()
        redis = fakeredis.FakeStrictRedis(server=cls._redisServer.fake_server)
        redis.set("kvs.correct.tests.powerdns.com", "test-result")
        redis.set("lua-get.tests.powerdns.com.", "7.8.9.10")

    @classmethod
    def setUpClass(cls):
        cls.setUpRedis()
        super(TestRedisGetSimple, cls).setUpClass()


class TestRedisHGetAndGetWithDataName(RedisTest, RedisHGet):
    _dataName = "test_hash"
    _lookupAction = "hget"

    @classmethod
    def setUpRedis(cls):
        super(TestRedisHGetAndGetWithDataName, cls).setUpRedis()
        redis = fakeredis.FakeStrictRedis(server=cls._redisServer.fake_server)
        redis.hset("test_hash", "kvs.correct.tests.powerdns.com", "test-result")
        redis.set("test_hashlua-get.tests.powerdns.com", "7.8.9.11")
        redis.hset("test_hash", "lua-hget.tests.powerdns.com.", "7.8.9.12")

    @classmethod
    def setUpClass(cls):
        cls.setUpRedis()
        super(TestRedisHGetAndGetWithDataName, cls).setUpClass()


@unittest.skipIf("SKIP_REDIS_TESTS" in os.environ, "Redis tests are disabled")
class RedisYamlTest(DNSDistTest):
    _redisPort = pickAvailablePort()
    _lookupAction = "get"
    _dataName = ""
    _yaml_config_template = """---
backends:
  - address: "127.0.0.1:%d"
    protocol: Do53

redis_clients:
  - name: test-redis
    url: redis://127.0.0.1:%d

key_value_stores:
  redis:
    - name: RedisKV
      redis_client: test-redis
      lookup_action: %s
      data_name: %s
  lookup_keys:
    qname_keys:
      - name: qname
        wire_format: false

query_rules:
  - name: Redis KV Rule
    selector:
      type: Regex
      expression: kvs.*
    action:
      type: KeyValueStoreLookup
      kvs_name: RedisKV
      lookup_key_name: qname
      destination_tag: kvs-qname-result

  - name: Spoof KV test rule
    selector:
      type: Tag
      tag: kvs-qname-result
      value: test-result
    action:
      type: Spoof
      ips:
        - 5.6.7.8

  - name: Redis Lua GET lookup rule
    selector:
      type: Regex
      expression: lua-get.*
    action:
      type: Lua
      function_code: |
        function lua_redis_get_query(dq)
            local redis = getObjectFromYAMLConfiguration("test-redis")
            if not redis:exists(dq.qname:toString()) then
                return DNSAction.None
            end
            local data = redis:get(dq.qname:toString())
            if data == nil then
                return DNSAction.None
            end
            return DNSAction.Spoof, data
        end
        return lua_redis_get_query

  - name: Redis Lua HGET lookup rule
    selector:
      type: Regex
      expression: lua-hget.*
    action:
      type: Lua
      function_code: |
        function lua_redis_hget_query(dq)
            local redis = getObjectFromYAMLConfiguration("test-redis")
            if not redis:hexists("%s", dq.qname:toString()) then
                return DNSAction.None
            end
            local data = redis:hget("%s", dq.qname:toString())
            if data == nil then
                return DNSAction.None
            end
            return DNSAction.Spoof, data
        end
        return lua_redis_hget_query

  - name: Spoof KV missed rule
    selector:
      type: Regex
      expression: kvs.*
    action:
      type: Spoof
      ips:
        - 9.9.9.9

  - name: Spoof Lua GET missed rule
    selector:
      type: Regex
      expression: lua-get.*
    action:
      type: Spoof
      ips:
        - 9.9.9.10

  - name: Spoof Lua HGET missed rule
    selector:
      type: Regex
      expression: lua-hget.*
    action:
      type: Spoof
      ips:
        - 9.9.9.11
"""
    _yaml_config_params = ["_testServerPort", "_redisPort", "_lookupAction", "_dataName", "_dataName", "_dataName"]

    @classmethod
    def setUpRedis(cls):
        print("Configuring Redis for YAML test")
        cls._redisPort = pickAvailablePort()
        cls._redisServer = fakeredis.TcpFakeServer(("localhost", cls._redisPort))
        cls._redisThread = Thread(target=cls._redisServer.serve_forever, daemon=True)
        cls._redisThread.start()

    @classmethod
    def tearDownClass(cls):
        super(RedisYamlTest, cls).tearDownClass()
        cls._redisServer.shutdown()
        cls._redisThread.join()


class TestRedisYamlGetSimple(RedisYamlTest, RedisGet):
    @classmethod
    def setUpRedis(cls):
        super(TestRedisYamlGetSimple, cls).setUpRedis()
        redis = fakeredis.FakeStrictRedis(server=cls._redisServer.fake_server)
        redis.set("kvs.correct.tests.powerdns.com", "test-result")
        redis.set("lua-get.tests.powerdns.com.", "7.8.9.10")

    @classmethod
    def setUpClass(cls):
        cls.setUpRedis()
        super(TestRedisYamlGetSimple, cls).setUpClass()


class TestRedisYamlHGetAndGetWithDataName(RedisYamlTest, RedisHGet):
    _dataName = "test_hash"
    _lookupAction = "hget"

    @classmethod
    def setUpRedis(cls):
        super(TestRedisYamlHGetAndGetWithDataName, cls).setUpRedis()
        redis = fakeredis.FakeStrictRedis(server=cls._redisServer.fake_server)
        redis.hset("test_hash", "kvs.correct.tests.powerdns.com", "test-result")
        redis.set("test_hashlua-get.tests.powerdns.com", "7.8.9.11")
        redis.hset("test_hash", "lua-hget.tests.powerdns.com.", "7.8.9.12")

    @classmethod
    def setUpClass(cls):
        cls.setUpRedis()
        super(TestRedisYamlHGetAndGetWithDataName, cls).setUpClass()


@unittest.skipIf("SKIP_REDIS_TESTS" in os.environ, "Redis tests are disabled")
class RedisCachingTest(RedisTest):
    _redisPort = pickAvailablePort()
    _copyCacheEnabled = "false"
    _config_template = """
    newServer{address="127.0.0.1:%d"}

    dataName = "%s"
    resultCache = newObjectCache("redisResultCache", { maxEntries = 1000 })
    negativeCache = newObjectCache("redisNegativeCache", { maxEntries = 1000 })
    redis = newRedisClient("redis://127.0.0.1:%d")
    kvs = newRedisKVStore(redis, { lookupAction = "%s", dataName = dataName, resultCache = resultCache, negativeCache = negativeCache, copyCacheEnabled = %s, copyCacheTtl = 100 })

    -- does a lookup in the Redis database using the qname as key, and store the result into the 'kvs-qname-result' tag
    addAction(RegexRule('kvs.*'), KeyValueStoreLookupAction(kvs, KeyValueLookupKeyQName(false), 'kvs-qname-result'))

    -- if the value of the 'kvs-qname-result' is set to 'test-result', spoof a response
    addAction(TagRule('kvs-qname-result', 'test-result'), SpoofAction('5.6.7.8'))

    -- otherwise, spoof a different response
    addAction(RegexRule('kvs.*'), SpoofAction('9.9.9.9'))
    """
    _config_params = ["_testServerPort", "_dataName", "_redisPort", "_lookupAction", "_copyCacheEnabled"]


class TestRedisGetWithCache(RedisCachingTest):
    _lookupAction = "get"

    @classmethod
    def setUpRedis(cls):
        super(TestRedisGetWithCache, cls).setUpRedis()
        cls._redis = fakeredis.FakeStrictRedis(server=cls._redisServer.fake_server)
        cls._redis.set("kvs.correct.tests.powerdns.com", "test-result")

    @classmethod
    def setUpClass(cls):
        cls.setUpRedis()
        super(TestRedisGetWithCache, cls).setUpClass()

    def testRedisGetKvs(self):
        """
        Redis: Match on Qname in KVS and store result in cache
        """
        # First run a regular query, it should retrieve the data
        name = "kvs.correct.tests.powerdns.com."
        query = dns.message.make_query(name, "A", "IN")
        # dnsdist set RA = RD for spoofed responses
        query.flags &= ~dns.flags.RD
        expectedResponse = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name, 3600, dns.rdataclass.IN, dns.rdatatype.A, "5.6.7.8")
        expectedResponse.answer.append(rrset)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (receivedQuery, receivedResponse) = sender(query, response=None, useQueue=False)
            self.assertFalse(receivedQuery)
            self.assertTrue(receivedResponse)
            self.assertEqual(expectedResponse, receivedResponse)

        # Now remove the key from redis
        self._redis.delete("kvs.correct.tests.powerdns.com")

        # Retry, we should still get the correct response, because we have it cached
        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (receivedQuery, receivedResponse) = sender(query, response=None, useQueue=False)
            self.assertFalse(receivedQuery)
            self.assertTrue(receivedResponse)
            self.assertEqual(expectedResponse, receivedResponse)


class TestRedisGetWithNegativeCache(RedisCachingTest):
    _lookupAction = "get"

    @classmethod
    def setUpRedis(cls):
        super(TestRedisGetWithNegativeCache, cls).setUpRedis()
        cls._redis = fakeredis.FakeStrictRedis(server=cls._redisServer.fake_server)

    @classmethod
    def setUpClass(cls):
        cls.setUpRedis()
        super(TestRedisGetWithNegativeCache, cls).setUpClass()

    def testRedisGetKvs(self):
        """
        Redis: Match on Qname in KVS and store result in negative cache
        """
        # The query should return 9.9.9.9 since the value is not in redis
        name = "kvs.correct.tests.powerdns.com."
        query = dns.message.make_query(name, "A", "IN")
        # dnsdist set RA = RD for spoofed responses
        query.flags &= ~dns.flags.RD
        expectedResponse = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name, 3600, dns.rdataclass.IN, dns.rdatatype.A, "9.9.9.9")
        expectedResponse.answer.append(rrset)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (receivedQuery, receivedResponse) = sender(query, response=None, useQueue=False)
            self.assertFalse(receivedQuery)
            self.assertTrue(receivedResponse)
            self.assertEqual(expectedResponse, receivedResponse)

        # Store the value
        self._redis.set("kvs.correct.tests.powerdns.com", "test-result")

        # Another query should return the same, because this key is stored in
        # negative cache
        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (receivedQuery, receivedResponse) = sender(query, response=None, useQueue=False)
            self.assertFalse(receivedQuery)
            self.assertTrue(receivedResponse)
            self.assertEqual(expectedResponse, receivedResponse)


class TestRedisHGetWithCache(RedisCachingTest):
    _lookupAction = "hget"
    _dataName = "test_hash"

    @classmethod
    def setUpRedis(cls):
        super(TestRedisHGetWithCache, cls).setUpRedis()
        cls._redis = fakeredis.FakeStrictRedis(server=cls._redisServer.fake_server)
        cls._redis.hset("test_hash", "kvs.correct.tests.powerdns.com", "test-result")

    @classmethod
    def setUpClass(cls):
        cls.setUpRedis()
        super(TestRedisHGetWithCache, cls).setUpClass()

    def testRedisHGetKvs(self):
        """
        Redis: Match on Qname in KVS and store result in cache
        """
        # First run a regular query, it should retrieve the data
        name = "kvs.correct.tests.powerdns.com."
        query = dns.message.make_query(name, "A", "IN")
        # dnsdist set RA = RD for spoofed responses
        query.flags &= ~dns.flags.RD
        expectedResponse = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name, 3600, dns.rdataclass.IN, dns.rdatatype.A, "5.6.7.8")
        expectedResponse.answer.append(rrset)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (receivedQuery, receivedResponse) = sender(query, response=None, useQueue=False)
            self.assertFalse(receivedQuery)
            self.assertTrue(receivedResponse)
            self.assertEqual(expectedResponse, receivedResponse)

        # Now remove the key from redis
        self._redis.delete("test_hash")

        # Retry, we should still get the correct response, because we have it cached
        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (receivedQuery, receivedResponse) = sender(query, response=None, useQueue=False)
            self.assertFalse(receivedQuery)
            self.assertTrue(receivedResponse)
            self.assertEqual(expectedResponse, receivedResponse)


class TestRedisHGetWithNegativeCache(RedisCachingTest):
    _lookupAction = "hget"
    _dataName = "test_hash"

    @classmethod
    def setUpRedis(cls):
        super(TestRedisHGetWithNegativeCache, cls).setUpRedis()
        cls._redis = fakeredis.FakeStrictRedis(server=cls._redisServer.fake_server)

    @classmethod
    def setUpClass(cls):
        cls.setUpRedis()
        super(TestRedisHGetWithNegativeCache, cls).setUpClass()

    def testRedisHGetKvs(self):
        """
        Redis: Match on Qname in KVS and store result in negative cache
        """
        # The query should return 9.9.9.9 since the value is not in redis
        name = "kvs.correct.tests.powerdns.com."
        query = dns.message.make_query(name, "A", "IN")
        # dnsdist set RA = RD for spoofed responses
        query.flags &= ~dns.flags.RD
        expectedResponse = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name, 3600, dns.rdataclass.IN, dns.rdatatype.A, "9.9.9.9")
        expectedResponse.answer.append(rrset)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (receivedQuery, receivedResponse) = sender(query, response=None, useQueue=False)
            self.assertFalse(receivedQuery)
            self.assertTrue(receivedResponse)
            self.assertEqual(expectedResponse, receivedResponse)

        # Store the value
        self._redis.hset("test_hash", "kvs.correct.tests.powerdns.com", "test-result")

        # Another query should return the same, because this key is stored in
        # negative cache
        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (receivedQuery, receivedResponse) = sender(query, response=None, useQueue=False)
            self.assertFalse(receivedQuery)
            self.assertTrue(receivedResponse)
            self.assertEqual(expectedResponse, receivedResponse)


class TestRedisHGetWithCopyCache(RedisCachingTest):
    _lookupAction = "hget"
    _dataName = "test_hash"
    _copyCacheEnabled = "true"

    @classmethod
    def setUpRedis(cls):
        super(TestRedisHGetWithCopyCache, cls).setUpRedis()
        cls._redis = fakeredis.FakeStrictRedis(server=cls._redisServer.fake_server)
        cls._redis.hset("test_hash", "kvs.correct.tests.powerdns.com", "test-result")
        cls._redis.hset("test_hash", "kvs.other.tests.powerdns.com", "test-result")

    @classmethod
    def setUpClass(cls):
        cls.setUpRedis()
        super(TestRedisHGetWithCopyCache, cls).setUpClass()

    def testRedisHGetKvs(self):
        """
        Redis: Match on Qname in KVS and store result in copy cache
        """
        # First run a regular query, it should retrieve the data
        name = "kvs.correct.tests.powerdns.com."
        query = dns.message.make_query(name, "A", "IN")
        # dnsdist set RA = RD for spoofed responses
        query.flags &= ~dns.flags.RD
        expectedResponse = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name, 3600, dns.rdataclass.IN, dns.rdatatype.A, "5.6.7.8")
        expectedResponse.answer.append(rrset)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (receivedQuery, receivedResponse) = sender(query, response=None, useQueue=False)
            self.assertFalse(receivedQuery)
            self.assertTrue(receivedResponse)
            self.assertEqual(expectedResponse, receivedResponse)

        # Now remove the key from redis
        self._redis.delete("test_hash")

        # Retry, we should still get the correct response, because we have it cached
        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (receivedQuery, receivedResponse) = sender(query, response=None, useQueue=False)
            self.assertFalse(receivedQuery)
            self.assertTrue(receivedResponse)
            self.assertEqual(expectedResponse, receivedResponse)

        # Then check the other key that was stored in the same hash - it should
        # be stored in the copy cache
        name = "kvs.other.tests.powerdns.com."
        query = dns.message.make_query(name, "A", "IN")
        # dnsdist set RA = RD for spoofed responses
        query.flags &= ~dns.flags.RD
        expectedResponse = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name, 3600, dns.rdataclass.IN, dns.rdatatype.A, "5.6.7.8")
        expectedResponse.answer.append(rrset)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (receivedQuery, receivedResponse) = sender(query, response=None, useQueue=False)
            self.assertFalse(receivedQuery)
            self.assertTrue(receivedResponse)
            self.assertEqual(expectedResponse, receivedResponse)


@unittest.skipIf("SKIP_REDIS_TESTS" in os.environ, "Redis tests are disabled")
class RedisCachingYamlTest(RedisYamlTest):
    _copyCacheEnabled = "false"
    _verboseMode = True
    _yaml_config_template = """---
backends:
  - address: "127.0.0.1:%d"
    protocol: Do53

redis_clients:
  - name: test-redis
    url: redis://127.0.0.1:%d

generic_caches:
  object:
    - name: "result-cache"
      max_entries: 1000
    - name: "negative-cache"
      max_entries: 1000

key_value_stores:
  redis:
    - name: RedisKV
      redis_client: test-redis
      lookup_action: %s
      data_name: %s
      result_cache: "result-cache"
      negative_cache: "negative-cache"
      copy_cache_enabled: %s
      copy_cache_ttl: 100
  lookup_keys:
    qname_keys:
      - name: qname
        wire_format: false

query_rules:
  - name: Redis KV Rule
    selector:
      type: Regex
      expression: kvs.*
    action:
      type: KeyValueStoreLookup
      kvs_name: RedisKV
      lookup_key_name: qname
      destination_tag: kvs-qname-result

  - name: Spoof KV test rule
    selector:
      type: Tag
      tag: kvs-qname-result
      value: test-result
    action:
      type: Spoof
      ips:
        - 5.6.7.8

  - name: Spoof KV missed rule
    selector:
      type: Regex
      expression: kvs.*
    action:
      type: Spoof
      ips:
        - 9.9.9.9
"""
    _yaml_config_params = ["_testServerPort", "_redisPort", "_lookupAction", "_dataName", "_copyCacheEnabled"]

    @classmethod
    def setUpRedis(cls):
        print("Configuring Redis for YAML test")
        cls._redisPort = pickAvailablePort()
        cls._redisServer = fakeredis.TcpFakeServer(("localhost", cls._redisPort))
        cls._redisThread = Thread(target=cls._redisServer.serve_forever, daemon=True)
        cls._redisThread.start()

    @classmethod
    def tearDownClass(cls):
        super(RedisYamlTest, cls).tearDownClass()
        cls._redisServer.shutdown()
        cls._redisThread.join()


class TestRedisYamlGetWithCache(RedisCachingYamlTest):
    _lookupAction = "get"

    @classmethod
    def setUpRedis(cls):
        super(TestRedisYamlGetWithCache, cls).setUpRedis()
        cls._redis = fakeredis.FakeStrictRedis(server=cls._redisServer.fake_server)
        cls._redis.set("kvs.correct.tests.powerdns.com", "test-result")

    @classmethod
    def setUpClass(cls):
        cls.setUpRedis()
        super(TestRedisYamlGetWithCache, cls).setUpClass()

    def testRedisYamlGetKvs(self):
        """
        RedisYaml: Match on Qname in KVS and store result in cache
        """
        # First run a regular query, it should retrieve the data
        name = "kvs.correct.tests.powerdns.com."
        query = dns.message.make_query(name, "A", "IN")
        # dnsdist set RA = RD for spoofed responses
        query.flags &= ~dns.flags.RD
        expectedResponse = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name, 3600, dns.rdataclass.IN, dns.rdatatype.A, "5.6.7.8")
        expectedResponse.answer.append(rrset)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (receivedQuery, receivedResponse) = sender(query, response=None, useQueue=False)
            self.assertFalse(receivedQuery)
            self.assertTrue(receivedResponse)
            self.assertEqual(expectedResponse, receivedResponse)

        # Now remove the key from redis
        self._redis.delete("kvs.correct.tests.powerdns.com")

        # Retry, we should still get the correct response, because we have it cached
        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (receivedQuery, receivedResponse) = sender(query, response=None, useQueue=False)
            self.assertFalse(receivedQuery)
            self.assertTrue(receivedResponse)
            self.assertEqual(expectedResponse, receivedResponse)


class TestRedisYamlGetWithNegativeCache(RedisCachingYamlTest):
    _lookupAction = "get"

    @classmethod
    def setUpRedis(cls):
        super(TestRedisYamlGetWithNegativeCache, cls).setUpRedis()
        cls._redis = fakeredis.FakeStrictRedis(server=cls._redisServer.fake_server)

    @classmethod
    def setUpClass(cls):
        cls.setUpRedis()
        super(TestRedisYamlGetWithNegativeCache, cls).setUpClass()

    def testRedisYamlGetKvs(self):
        """
        RedisYaml: Match on Qname in KVS and store result in negative cache
        """
        # The query should return 9.9.9.9 since the value is not in redis
        name = "kvs.correct.tests.powerdns.com."
        query = dns.message.make_query(name, "A", "IN")
        # dnsdist set RA = RD for spoofed responses
        query.flags &= ~dns.flags.RD
        expectedResponse = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name, 3600, dns.rdataclass.IN, dns.rdatatype.A, "9.9.9.9")
        expectedResponse.answer.append(rrset)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (receivedQuery, receivedResponse) = sender(query, response=None, useQueue=False)
            self.assertFalse(receivedQuery)
            self.assertTrue(receivedResponse)
            self.assertEqual(expectedResponse, receivedResponse)

        # Store the value
        self._redis.set("kvs.correct.tests.powerdns.com", "test-result")

        # Another query should return the same, because this key is stored in
        # negative cache
        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (receivedQuery, receivedResponse) = sender(query, response=None, useQueue=False)
            self.assertFalse(receivedQuery)
            self.assertTrue(receivedResponse)
            self.assertEqual(expectedResponse, receivedResponse)


class TestRedisYamlHGetWithCache(RedisCachingYamlTest):
    _lookupAction = "hget"
    _dataName = "test_hash"

    @classmethod
    def setUpRedis(cls):
        super(TestRedisYamlHGetWithCache, cls).setUpRedis()
        cls._redis = fakeredis.FakeStrictRedis(server=cls._redisServer.fake_server)
        cls._redis.hset("test_hash", "kvs.correct.tests.powerdns.com", "test-result")

    @classmethod
    def setUpClass(cls):
        cls.setUpRedis()
        super(TestRedisYamlHGetWithCache, cls).setUpClass()

    def testRedisYamlHGetKvs(self):
        """
        RedisYaml: Match on Qname in KVS and store result in cache
        """
        # First run a regular query, it should retrieve the data
        name = "kvs.correct.tests.powerdns.com."
        query = dns.message.make_query(name, "A", "IN")
        # dnsdist set RA = RD for spoofed responses
        query.flags &= ~dns.flags.RD
        expectedResponse = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name, 3600, dns.rdataclass.IN, dns.rdatatype.A, "5.6.7.8")
        expectedResponse.answer.append(rrset)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (receivedQuery, receivedResponse) = sender(query, response=None, useQueue=False)
            self.assertFalse(receivedQuery)
            self.assertTrue(receivedResponse)
            self.assertEqual(expectedResponse, receivedResponse)

        # Now remove the key from redis
        self._redis.delete("test_hash")

        # Retry, we should still get the correct response, because we have it cached
        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (receivedQuery, receivedResponse) = sender(query, response=None, useQueue=False)
            self.assertFalse(receivedQuery)
            self.assertTrue(receivedResponse)
            self.assertEqual(expectedResponse, receivedResponse)


class TestRedisYamlHGetWithNegativeCache(RedisCachingYamlTest):
    _lookupAction = "hget"
    _dataName = "test_hash"

    @classmethod
    def setUpRedis(cls):
        super(TestRedisYamlHGetWithNegativeCache, cls).setUpRedis()
        cls._redis = fakeredis.FakeStrictRedis(server=cls._redisServer.fake_server)

    @classmethod
    def setUpClass(cls):
        cls.setUpRedis()
        super(TestRedisYamlHGetWithNegativeCache, cls).setUpClass()

    def testRedisYamlHGetKvs(self):
        """
        RedisYaml: Match on Qname in KVS and store result in negative cache
        """
        # The query should return 9.9.9.9 since the value is not in redis
        name = "kvs.correct.tests.powerdns.com."
        query = dns.message.make_query(name, "A", "IN")
        # dnsdist set RA = RD for spoofed responses
        query.flags &= ~dns.flags.RD
        expectedResponse = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name, 3600, dns.rdataclass.IN, dns.rdatatype.A, "9.9.9.9")
        expectedResponse.answer.append(rrset)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (receivedQuery, receivedResponse) = sender(query, response=None, useQueue=False)
            self.assertFalse(receivedQuery)
            self.assertTrue(receivedResponse)
            self.assertEqual(expectedResponse, receivedResponse)

        # Store the value
        self._redis.hset("test_hash", "kvs.correct.tests.powerdns.com", "test-result")

        # Another query should return the same, because this key is stored in
        # negative cache
        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (receivedQuery, receivedResponse) = sender(query, response=None, useQueue=False)
            self.assertFalse(receivedQuery)
            self.assertTrue(receivedResponse)
            self.assertEqual(expectedResponse, receivedResponse)


class TestRedisYamlHGetWithCopyCache(RedisCachingYamlTest):
    _lookupAction = "hget"
    _dataName = "test_hash"
    _copyCacheEnabled = "true"

    @classmethod
    def setUpRedis(cls):
        super(TestRedisYamlHGetWithCopyCache, cls).setUpRedis()
        cls._redis = fakeredis.FakeStrictRedis(server=cls._redisServer.fake_server)
        cls._redis.hset("test_hash", "kvs.correct.tests.powerdns.com", "test-result")
        cls._redis.hset("test_hash", "kvs.other.tests.powerdns.com", "test-result")

    @classmethod
    def setUpClass(cls):
        cls.setUpRedis()
        super(TestRedisYamlHGetWithCopyCache, cls).setUpClass()

    def testRedisYamlHGetKvs(self):
        """
        RedisYaml: Match on Qname in KVS and store result in copy cache
        """
        # First run a regular query, it should retrieve the data
        name = "kvs.correct.tests.powerdns.com."
        query = dns.message.make_query(name, "A", "IN")
        # dnsdist set RA = RD for spoofed responses
        query.flags &= ~dns.flags.RD
        expectedResponse = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name, 3600, dns.rdataclass.IN, dns.rdatatype.A, "5.6.7.8")
        expectedResponse.answer.append(rrset)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (receivedQuery, receivedResponse) = sender(query, response=None, useQueue=False)
            self.assertFalse(receivedQuery)
            self.assertTrue(receivedResponse)
            self.assertEqual(expectedResponse, receivedResponse)

        # Now remove the key from redis
        self._redis.delete("test_hash")

        # Retry, we should still get the correct response, because we have it cached
        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (receivedQuery, receivedResponse) = sender(query, response=None, useQueue=False)
            self.assertFalse(receivedQuery)
            self.assertTrue(receivedResponse)
            self.assertEqual(expectedResponse, receivedResponse)

        # Then check the other key that was stored in the same hash - it should
        # be stored in the copy cache
        name = "kvs.other.tests.powerdns.com."
        query = dns.message.make_query(name, "A", "IN")
        # dnsdist set RA = RD for spoofed responses
        query.flags &= ~dns.flags.RD
        expectedResponse = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name, 3600, dns.rdataclass.IN, dns.rdatatype.A, "5.6.7.8")
        expectedResponse.answer.append(rrset)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (receivedQuery, receivedResponse) = sender(query, response=None, useQueue=False)
            self.assertFalse(receivedQuery)
            self.assertTrue(receivedResponse)
            self.assertEqual(expectedResponse, receivedResponse)
