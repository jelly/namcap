#
# namcap rules - utility functions
# Copyright (C) 2009 Dan McGee <dan@archlinux.org>
#
#   This program is free software; you can redistribute it and/or modify
#   it under the terms of the GNU General Public License as published by
#   the Free Software Foundation; either version 2 of the License, or
#   (at your option) any later version.
#
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with this program; if not, write to the Free Software
#   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#

import re

def _file_has_magic(fileobj, magic_bytes):
	length = len(magic_bytes)
	magic = fileobj.read(length)
	fileobj.seek(0)
	return magic == magic_bytes

def is_elf(fileobj):
	"Take file object, peek at the magic bytes to check if ELF file."
	return _file_has_magic(fileobj, b"\x7fELF")

def is_static(fileobj):
	"Take file object, peek at the magic bytes to check if static lib."
	return _file_has_magic(fileobj, b"!<arch>\n")

def is_script(fileobj):
	"Take file object, peek at the magic bytes to check if script."
	return _file_has_magic(fileobj, b"#!")

def is_java(fileobj):
	"Take file object, peek at the magic bytes to check if class file."
	return _file_has_magic(fileobj, b"\xCA\xFE\xBA\xBE")

def script_type(fileobj):
	firstline = fileobj.readline()
	fileobj.seek(0)
	try:
		firstline = firstline.decode('utf-8', 'strict')
	except UnicodeDecodeError:
		return None
	if not firstline:
		return None
	script = re.compile('#!.*/(.*)')
	m = script.match(firstline)
	if m is None:
		return None
	cmd = m.group(1).split()
	name = cmd[0]
	if name == 'env':
		name = cmd[1]
	return name

# vim: set ts=4 sw=4 noet:
