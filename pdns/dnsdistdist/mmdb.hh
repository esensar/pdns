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

#include "dolog.hh"
#include <maxminddb.h>
#include <string>

class MMDB
{
public:
  MMDB(const std::string& fname, const std::string& modeStr)
  {
    int ec;
    int flags = 0;
    if (modeStr == "")
      /* for the benefit of ifdef */
      ;
#ifdef HAVE_MMAP
    else if (modeStr == "mmap")
      flags |= MMDB_MODE_MMAP;
#endif
    else
      throw PDNSException(std::string("Unsupported mode ") + modeStr + ("for mmdb"));
    memset(&d_s, 0, sizeof(d_s));
    if ((ec = MMDB_open(fname.c_str(), flags, &d_s)) < 0)
      throw PDNSException(std::string("Cannot open ") + fname + std::string(": ") + std::string(MMDB_strerror(ec)));
    vinfolog("Opened MMDB database %s (type: %s version: %d.%d)", fname, d_s.metadata.database_type, d_s.metadata.binary_format_major_version, d_s.metadata.binary_format_minor_version);
  }

  bool queryCountry(string& ret, const string& ip)
  {
    MMDB_entry_data_s data;
    MMDB_lookup_result_s res;
    if (!mmdbLookup(ip, res))
      return false;
    if (MMDB_get_value(&res.entry, &data, "country", "iso_code", NULL) != MMDB_SUCCESS || !data.has_data)
      return false;
    ret = string(data.utf8_string, data.data_size);
    return true;
  }

  bool queryContinent(string& ret, const string& ip)
  {
    MMDB_entry_data_s data;
    MMDB_lookup_result_s res;
    if (!mmdbLookup(ip, res))
      return false;
    if (MMDB_get_value(&res.entry, &data, "continent", "code", NULL) != MMDB_SUCCESS || !data.has_data)
      return false;
    ret = string(data.utf8_string, data.data_size);
    return true;
  }

  bool queryASN(string& ret, const string& ip)
  {
    MMDB_entry_data_s data;
    MMDB_lookup_result_s res;
    if (!mmdbLookup(ip, res))
      return false;
    if (MMDB_get_value(&res.entry, &data, "autonomous_system_organization", NULL) != MMDB_SUCCESS || !data.has_data)
      return false;
    ret = string(data.utf8_string, data.data_size);
    return true;
  }

  bool queryASnum(string& ret, const string& ip)
  {
    MMDB_entry_data_s data;
    MMDB_lookup_result_s res;
    if (!mmdbLookup(ip, res))
      return false;
    if (MMDB_get_value(&res.entry, &data, "autonomous_system_number", NULL) != MMDB_SUCCESS || !data.has_data)
      return false;
    ret = std::to_string(data.uint32);
    return true;
  }

  bool queryRegion(string& ret, const string& ip)
  {
    MMDB_entry_data_s data;
    MMDB_lookup_result_s res;
    if (!mmdbLookup(ip, res))
      return false;
    if (MMDB_get_value(&res.entry, &data, "subdivisions", "0", "iso_code", NULL) != MMDB_SUCCESS || !data.has_data)
      return false;
    ret = string(data.utf8_string, data.data_size);
    return true;
  }

  bool queryCity(string& ret, const string& ip, const string& language)
  {
    MMDB_entry_data_s data;
    MMDB_lookup_result_s res;
    if (!mmdbLookup(ip, res))
      return false;
    if ((MMDB_get_value(&res.entry, &data, "cities", "0", NULL) != MMDB_SUCCESS || !data.has_data) && (MMDB_get_value(&res.entry, &data, "city", "names", language.c_str(), NULL) != MMDB_SUCCESS || !data.has_data))
      return false;
    ret = string(data.utf8_string, data.data_size);
    return true;
  }

  bool queryLocation(const string& ip,
                     double& latitude, double& longitude,
                     int& prec)
  {
    MMDB_entry_data_s data;
    MMDB_lookup_result_s res;
    if (!mmdbLookup(ip, res))
      return false;
    if (MMDB_get_value(&res.entry, &data, "location", "latitude", NULL) != MMDB_SUCCESS || !data.has_data)
      return false;
    latitude = data.double_value;
    if (MMDB_get_value(&res.entry, &data, "location", "longitude", NULL) != MMDB_SUCCESS || !data.has_data)
      return false;
    longitude = data.double_value;
    if (MMDB_get_value(&res.entry, &data, "location", "accuracy_radius", NULL) != MMDB_SUCCESS || !data.has_data)
      return false;
    prec = data.uint16;
    return true;
  }

  bool exists(const string& ip)
  {
    MMDB_lookup_result_s res;
    return mmdbLookup(ip, res);
  }

  ~MMDB() { MMDB_close(&d_s); };

private:
  MMDB_s d_s;

  bool mmdbLookup(const string& ip, MMDB_lookup_result_s& res)
  {
    int gai_ec = 0, mmdb_ec = 0;
    res = MMDB_lookup_string(&d_s, ip.c_str(), &gai_ec, &mmdb_ec);

    if (gai_ec != 0) {
      vinfolog("MMDB_lookup_string(%s) failed: %s", ip, gai_strerror(gai_ec));
    }
    else if (mmdb_ec != MMDB_SUCCESS) {
      vinfolog("MMDB_lookup_string(%s) failed: %s", ip, MMDB_strerror(mmdb_ec));
    }
    else if (res.found_entry) {
      // gl.netmask = res.netmask;
      // /* If it's a IPv6 database, IPv4 netmasks are reduced from 128, so we need to deduct
      //    96 to get from [96,128] => [0,32] range */
      // if (!v6 && gl.netmask > 32)
      //   gl.netmask -= 96;
      return true;
    }
    return false;
  }
};
