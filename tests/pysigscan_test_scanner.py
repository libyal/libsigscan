#!/usr/bin/env python
#
# Python-bindings scanner type test script
#
# Copyright (C) 2014-2020, Joachim Metz <joachim.metz@gmail.com>
#
# Refer to AUTHORS for acknowledgements.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

import sys

import pysigscan


class Signature(object):
  """Signature value class."""
 
  def __init__(self, identifier, pattern_offset, pattern, flags):
    super(Signature, self).__init__()
    self.identifier = identifier
    self.pattern_offset = pattern_offset
    self.pattern = pattern
    self.flags = flags


def pysigscan_test_scan_buffer(scanner, buffer, expected_scan_results):
  scan_state = pysigscan.scan_state()

  scan_state.set_data_size(len(buffer))

  scanner.scan_start(scan_state)
  scanner.scan_buffer(scan_state, buffer)
  scanner.scan_stop(scan_state)

  scan_results = []
  for scan_result in scan_state.scan_results:
    scan_results.append(scan_result.identifier)

  if sorted(scan_results) == sorted(expected_scan_results):
    result = True
  else:
    result = False

  print("Testing scan\t"),
  if not result:
    print("(FAIL)")
    return False
  print("(PASS)")

  return True


def main():
  RELATIVE_FROM_START = pysigscan.signature_flags.RELATIVE_FROM_START
  RELATIVE_FROM_END = pysigscan.signature_flags.RELATIVE_FROM_END

  evt_pattern = b"\x30\x00\x00\x00LfLe\x01\x00\x00\x00\x01\x00\x00\x00"
  lnk_pattern = (
      b"\x4c\x00\x00\x00\x01\x14\x02\x00\x00\x00\x00\x00\xc0\x00\x00\x00"
      b"\x00\x00\x00\x46")
  nk2_pattern = b"\x0d\xf0\xad\xba\xa0\x00\x00\x00\x01\x00\x00\x00"
  olecf_pattern = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
  olecf_beta_pattern = b"\x0e\x11\xfc\x0d\xd0\xcf\x11\x0e"
  regf_pattern = b"regf"
  vhdi_pattern = b"conectix"

  signatures = [
      Signature("7z", 0, b"7z\xbc\xaf\x27\x1c", RELATIVE_FROM_START),
      Signature("esedb", 4, b"\xef\xcd\xab\x89", RELATIVE_FROM_START),
      Signature("evt", 0, evt_pattern, RELATIVE_FROM_START),
      Signature("evtx", 0, b"ElfFile\x00", RELATIVE_FROM_START),
      Signature("ewf_e01", 0, b"EVF\x09\x0d\x0a\xff\x00", RELATIVE_FROM_START),
      Signature("ewf_l01", 0, b"LVF\x09\x0d\x0a\xff\x00", RELATIVE_FROM_START),
      Signature("lnk", 0, lnk_pattern, RELATIVE_FROM_START),
      Signature("msiecf", 0, b"Client UrlCache MMF Ver ", RELATIVE_FROM_START),
      Signature("nk2", 0, nk2_pattern, RELATIVE_FROM_START),
      Signature("olecf", 0, olecf_pattern, RELATIVE_FROM_START),
      Signature("olecf_beta", 0, olecf_beta_pattern, RELATIVE_FROM_START),
      Signature("pff", 0, b"!BDN", RELATIVE_FROM_START),
      Signature("qcow", 0, b"QFI\xfb", RELATIVE_FROM_START),
      Signature("rar", 0, b"Rar!\x1a\x07\x00", RELATIVE_FROM_START),
      Signature("regf", 0, b"regf", RELATIVE_FROM_START),
      Signature("vhdi_header", 0, vhdi_pattern, RELATIVE_FROM_START),
      Signature("vhdi_footer", 512, vhdi_pattern, RELATIVE_FROM_END),
      Signature("wtcdb_cache", 0, b"CMMM", RELATIVE_FROM_START),
      Signature("wtcdb_index", 0, b"IMMM", RELATIVE_FROM_START)]

  random_data = (
      b"\x01\xfa\xe0\xbe\x99\x8e\xdb\x70\xea\xcc\x6b\xae\x2f\xf5\xa2\xe4")

  scanner = pysigscan.scanner()

  for signature in signatures:
    scanner.add_signature(
        signature.identifier, signature.pattern_offset, signature.pattern,
        signature.flags)

  # TODO add test to set Unicode pattern.
  # TODO add test to set negative pattern offset.

  expected_scan_results = ["lnk"]
  if not pysigscan_test_scan_buffer(
      scanner, lnk_pattern, expected_scan_results):
    return False

  expected_scan_results = ["lnk"]
  if not pysigscan_test_scan_buffer(
      scanner, lnk_pattern, expected_scan_results):
    return False

  expected_scan_results = ["regf"]
  if not pysigscan_test_scan_buffer(
      scanner, regf_pattern, expected_scan_results):
    return False

  expected_scan_results = []
  if not pysigscan_test_scan_buffer(
      scanner, random_data, expected_scan_results):
    return False

  return True


if __name__ == "__main__":
  if not main():
    sys.exit(1)
  else:
    sys.exit(0)

