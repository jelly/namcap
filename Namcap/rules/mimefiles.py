# 
# namcap rules - mimefiles
# Copyright (C) 2009 Hugo Doria <hugo@archlinux.org>
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

class package(TarballRule):
    name = "mimefiles"
    description = "Check for files in /usr/share/mime"
    def prereq(self):
        return "tar"
    def analyze(self, pkginfo, tar):        
        ret = [[], [], []]
        if 'usr/share/mime' in tar.getnames():            
            if hasattr(pkginfo, "depends"):
                if "shared-mime-info" not in pkginfo.depends:
                    ret[0].append(("dependency-detected-not-included %s", ("shared-mime-info",)))
            if ".INSTALL" not in tar.getnames():
                ret[0].append(("mime-cache-not-updated", ()))
            else:
                f = tar.extractfile(".INSTALL")                    
                if "update-mime-database" not in "\n".join(f.readlines()):
                    ret[0].append(("mime-cache-not-updated", ()))

        return ret
# vim: set ts=4 sw=4 noet:
