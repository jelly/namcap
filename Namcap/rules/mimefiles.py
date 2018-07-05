# 
# namcap rules - mimefiles
# Copyright (C) 2009 Hugo Doria <hugo@archlinux.org>
# Copyright (C) 2011 Rémy Oudompheng <remy@archlinux.org>
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
#   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
# 

from Namcap.ruleclass import *

class MimeDesktopRule(TarballRule):
	name = "mimedesktop"
	description = "Check for MIME desktop file depends"
	def analyze(self, pkginfo, tar):
		for entry in tar:
			if entry.issym():
				continue
			if not entry.name.startswith("usr/share/applications"):
				continue
			if not entry.name.endswith(".desktop"):
				continue
			with tar.extractfile(entry) as f:
				if not any(l.startswith(b"MimeType=") for l in f):
					continue
				pkginfo.detected_deps["desktop-file-utils"].append( ('desktop-file-utils-needed', ()) )
				break

# vim: set ts=4 sw=4 noet:
