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

#include <string>
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "dolog.hh"
#include "iputils.hh"
#include "mmdb.hh"
#include <maxminddb.h>

MMDB::MMDB(const std::string& fname, const std::string& modeStr)
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
  memset(&d_db, 0, sizeof(d_db));
  if ((ec = MMDB_open(fname.c_str(), flags, &d_db)) != MMDB_SUCCESS)
    throw PDNSException(std::string("Cannot open ") + fname + std::string(": ") + std::string(MMDB_strerror(ec)));
  vinfolog("Opened MMDB database %s (type: %s version: %d.%d)", fname, d_db.metadata.database_type, d_db.metadata.binary_format_major_version, d_db.metadata.binary_format_minor_version);
}

bool MMDB::queryCountry(string& ret, const ComboAddress& ip)
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

bool MMDB::queryContinent(string& ret, const ComboAddress& ip)
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

bool MMDB::queryASN(string& ret, const ComboAddress& ip)
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

bool MMDB::queryASnum(string& ret, const ComboAddress& ip)
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

bool MMDB::queryRegion(string& ret, const ComboAddress& ip)
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

bool MMDB::queryCity(string& ret, const ComboAddress& ip, const string& language)
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

bool MMDB::queryLocation(double& latitude, double& longitude,
                         int& prec,
                         const ComboAddress& ip)
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

bool MMDB::mmdbLookup(const ComboAddress& ip, MMDB_lookup_result_s& res)
{
  int mmdb_ec = 0;
  res = MMDB_lookup_sockaddr(&d_db, reinterpret_cast<const struct sockaddr*>(&ip), &mmdb_ec);

  if (mmdb_ec != MMDB_SUCCESS) {
    vinfolog("MMDB_lookup_sockaddr(%s) failed: %s", ip.toString(), MMDB_strerror(mmdb_ec));
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
