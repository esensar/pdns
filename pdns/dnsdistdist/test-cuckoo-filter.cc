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
  CuckooFilter cuckoo{{.d_maxEntries = 10}};

  BOOST_CHECK(!cuckoo.contains("test"));
  for (size_t i = 0; i < 100; i++) {
    cuckoo.insertKey("test");
    BOOST_CHECK(cuckoo.contains("test"));
  }

  cuckoo.remove("test");
  BOOST_CHECK(!cuckoo.contains("test"));
}

BOOST_AUTO_TEST_SUITE_END()
