# 
# namcap rules - fhs
# Copyright (C) 2003-2009 Jason Chu <jason@archlinux.org>
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

import os, re
from Namcap.ruleclass import *

class FHSRule(TarballRule):
	name = "directoryname"
	description = "Checks for standard directories."
	def analyze(self, pkginfo, tar):
		valid_paths = [
				'etc/', 'opt/',
				'lib/modules',
				'usr/bin/', 'usr/include/', 'usr/lib/', 'usr/lib32/',
				'usr/sbin/', 'usr/share/', 'usr/src/',
				'var/cache/', 'var/lib/', 'var/log/', 'var/opt/',
				'var/spool/', 'var/state/',
				'.PKGINFO', '.INSTALL', '.CHANGELOG', '.MTREE', '.BUILDINFO',
		]
		forbidden_paths = [
				'tmp/', 'var/tmp/',
				'run/', 'var/run/',
				'var/lock/'
		]
		custom_valid = {
			'^mingw-': ['usr/x86_64-w64-mingw32/lib/',
			            'usr/x86_64-w64-mingw32/bin/',
						'usr/x86_64-w64-mingw32/include/',
						'usr/i686-w64-mingw32/lib/',
						'usr/i686-w64-mingw32/bin/',
						'usr/i686-w64-mingw32/include/'],
			}
		for pattern in custom_valid:
			if re.search(pattern, pkginfo['name']):
				valid_paths.extend(custom_valid[pattern])
		for entry in tar.getmembers():
			name = os.path.normpath(entry.name)
			if entry.isdir():
				name += '/'

			# check for files in wrong dirs, directory itself will be
			# catched by emptydirs rule
			if name in forbidden_paths:
				continue
			bad_dirs = (name.startswith(dirname) for dirname in forbidden_paths)
			if any(bad_dirs):
				self.errors.append(('file-in-temporary-dir %s',	name))
				continue

			# matches directory names or parent directories
			good_dirs = (name.startswith(dirname) or dirname.startswith(name)
				for dirname in valid_paths)
			if not any(good_dirs):
				self.warnings.append(("file-in-non-standard-dir %s", name))

class FHSManpagesRule(TarballRule):
	name = "fhs-manpages"
	description = "Verifies correct installation of man pages"
	def analyze(self, pkginfo, tar):
		gooddir = 'usr/share/man'
		bad_dir = 'usr/man'
		for i in tar.getmembers():
			if not i.isfile():
				continue
			if i.name.startswith(gooddir):
				continue
			if i.name.startswith(bad_dir):
				self.errors.append(("non-fhs-man-page %s", i.name))
				continue
			#Check everything else to see if it has a 'man' path component
			if "man" in i.name.split(os.sep):
				self.warnings.append(("potential-non-fhs-man-page %s", i.name))

class FHSInfoPagesRule(TarballRule):
	name = "fhs-infopages"
	description = "Verifies correct installation of info pages"
	def analyze(self, pkginfo, tar):
		for i in tar.getmembers():
			if not i.isfile():
				continue
			if i.name.startswith('usr/share/info'):
				continue
			if i.name.startswith('usr/info'):
				self.errors.append(("non-fhs-info-page %s", i.name))
				continue
			if "info" in i.name.split(os.sep):
				self.warnings.append(("potential-non-fhs-info-page %s", i.name))

class RubyPathsRule(TarballRule):
	name = "rubypaths"
	description = "Verifies correct usage of folders by ruby packages"
	def analyze(self, pkginfo, tar):
		for i in tar.getmembers():
			if i.name.startswith('usr/lib/ruby/site_ruby'):
				self.warnings.append(("site-ruby", ()))
				return

# vim: set ts=4 sw=4 noet:
