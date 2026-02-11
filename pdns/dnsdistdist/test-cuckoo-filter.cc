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
#ifndef BOOST_TEST_DYN_LINK
#define BOOST_TEST_DYN_LINK
#endif

#define BOOST_TEST_NO_MAIN

#include <boost/test/unit_test.hpp>

#include "generic-cache.hh"

BOOST_AUTO_TEST_SUITE(test_cuckoo_filter)

BOOST_AUTO_TEST_CASE(test_cuckoo_insert_basic)
{
  CuckooFilter cuckoo{{}};

  BOOST_CHECK(!cuckoo.contains("test"));

  cuckoo.insertKey("test");
  BOOST_CHECK(cuckoo.contains("test"));

  cuckoo.remove("test");
  BOOST_CHECK(!cuckoo.contains("test"));
}

BOOST_AUTO_TEST_CASE(test_cuckoo_insert_duplicate)
{
  CuckooFilter cuckoo{{.d_maxEntries = 100}};

  BOOST_CHECK(!cuckoo.contains("test"));
  for (size_t i = 0; i < 100; i++) {
    cuckoo.insertKey("test_" + std::to_string(i));
    BOOST_CHECK_MESSAGE(cuckoo.contains("test_" + std::to_string(i)), "Value not found: test_" << std::to_string(i));
  }

  cuckoo.remove("test");
  BOOST_CHECK(!cuckoo.contains("test"));
}

BOOST_AUTO_TEST_SUITE_END()
