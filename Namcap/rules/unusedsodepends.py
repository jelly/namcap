#
# namcap rules - unusedsodepends
# Copyright (C) 2009 Abhishek Dasgupta <abhidg@gmail.com>
# Copyright (C) 2013 Jan Alexander Steffens <jan.steffens@gmail.com>
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

import os, subprocess, re
import tempfile
from Namcap.util import is_elf
from Namcap.ruleclass import *

libre = re.compile('^\t(/.*)')
lddfail = re.compile('^\tnot a dynamic executable')

def get_unused_sodepends(filename):
	p = subprocess.Popen(["ldd", "-r", "-u", filename],
		env={'LANG': 'C'},
		stdout=subprocess.PIPE,
		stderr=subprocess.PIPE)
	var = p.communicate()
	if p.returncode == 0:
		return
	for j in var[0].decode('ascii').splitlines():
		# Don't raise an error, as the executable might be a valid ELF file,
		# just not a dynamically linked one
		n = lddfail.search(j)
		if n is not None:
			return

		n = libre.search(j)
		if n is not None:
			yield n.group(1)

class package(TarballRule):
	name = "unusedsodepends"
	description = "Checks for unused dependencies caused by linked shared libraries"
	def analyze(self, pkginfo, tar):
		for entry in tar:
			if not entry.isfile():
				continue

			# is it an ELF file ?
			f = tar.extractfile(entry)
			if not is_elf(f):
				f.close()
				continue
			elf = f.read()
			f.close()

			# write it to a temporary file
			f = tempfile.NamedTemporaryFile(delete = False)
			f.write(elf)
			f.close()

			os.chmod(f.name, 0o755)

			for lib in get_unused_sodepends(f.name):
				self.warnings.append(("unused-sodepend %s %s", (lib, entry.name)))

			os.unlink(f.name)

# vim: set ts=4 sw=4 noet:
