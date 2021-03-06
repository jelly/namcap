# -*- coding: utf-8 -*-
# 
# namcap rules - depends
# Copyright (C) 2003-2009 Jason Chu <jason@archlinux.org>
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
#   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
# 

"""Checks dependencies semi-smartly."""

import re
from Namcap.ruleclass import *
import Namcap.tags
from Namcap import package

# manual overrides for relationships outside the normal metadata
implicit_provides = {
	'java-environment': ['java-runtime'],
}

def single_covered(depend):
	"Returns full coverage tree of one package, with loops broken"
	covered = set()
	todo = set([depend])
	while todo:
		i = todo.pop()
		covered.add(i)
		pac = package.load_from_db(i)
		if pac is None:
			continue
		todo |= set(pac["depends"]) - covered

	return covered - set([depend])

def getcovered(dependlist):
	"""
	Returns full coverage tree set, without packages
	from self-loops (iterable of package names)
	"""

	covered = set()
	for d in dependlist:
		covered |= single_covered(d)
	return covered

def getcustom(pkginfo):
	custom_name = {'^mingw-': ['mingw-w64-crt'],}
	custom_depend = set()
	for pattern in custom_name:
		if re.search(pattern, pkginfo['name']):
			custom_depend.update(custom_name[pattern])
	return custom_depend

def getprovides(depends):
	provides = {}
	for i in depends:
		provides[i] = set()
		if i in implicit_provides:
			provides[i].update(implicit_provides[i])
		pac = package.load_from_db(i)
		if pac is None:
			continue
		if not pac["provides"]:
			continue
		provides[i].update(pac["provides"])
	return provides

def analyze_depends(pkginfo):
	errors, warnings, infos = [], [], []

	# compute needed dependencies + recursive
	dependlist = set(pkginfo.detected_deps.keys())
	indirectdependlist = getcovered(dependlist)
	customlist = getcustom(pkginfo)
	for i in indirectdependlist:
		infos.append(("dependency-covered-by-link-dependence %s", i))
	needed_depend = dependlist | indirectdependlist | customlist
	# the minimal set of needed dependencies
	smartdepend = set(dependlist) - indirectdependlist

	# Find all the covered dependencies from the PKGBUILD
	pkginfo.setdefault("depends", [])
	explicitdepend = set(pkginfo["depends"])
	implicitdepend = getcovered(explicitdepend)
	pkgbuild_depend = explicitdepend | implicitdepend

	# Include the optdepends from the PKGBUILD
	pkginfo.setdefault("optdepends", [])
	optdepend = set(pkginfo["optdepends"])
	optdepend |= getcovered(optdepend)

	# Get the provides so we can reference them later
	# smartprovides : depend => (packages provided by depend)
	smartprovides = getprovides(smartdepend | explicitdepend)

	# The set of all provides for detected dependencies
	allprovides = set()
	for plist in smartprovides.values():
		allprovides |= plist

	# Do the actual message outputting stuff
	for i in smartdepend:
		# if the needed package is itself:
		if i == pkginfo["name"]:
			continue
		# if the dependency is satisfied
		if i in pkgbuild_depend:
			continue
		# if the dependency is pulled as a provider for some explicit dep
		if smartprovides[i] & pkgbuild_depend:
			continue
		# the dependency is satisfied by a provides
		if i in allprovides:
			continue
		# compute dependency reason
		reasons = pkginfo.detected_deps[i]
		reason_strings = [Namcap.tags.format_message(reason) for reason in reasons]
		reason = ', '.join(reason_strings)
		# still not found, maybe it is specified as optional
		if i in optdepend:
			warnings.append(("dependency-detected-but-optional %s (%s)", (i, reason)))
			continue
		# maybe, it is pulled as a provider for an optdepend
		if smartprovides[i] & optdepend:
			warnings.append(("dependency-detected-but-optional %s (%s)", (i, reason)))
			continue
		# now i'm pretty sure i didn't find it.
		errors.append(("dependency-detected-not-included %s (%s)", (i, reason)))

	for i in pkginfo["depends"]:
		# multilib packages usually depend on their regular counterparts
		if pkginfo["name"].startswith('lib32-') and i == pkginfo["name"].partition('-')[2]:
			continue
		# the package provides an important dependency
		if i in smartprovides and (smartprovides[i] & smartdepend):
			continue
		# a needed dependency is superfluous it is implicitly satisfied
		if i in implicitdepend and (i in smartdepend or i in indirectdependlist):
			warnings.append(("dependency-already-satisfied %s", i))
		# a dependency is unneeded if:
		#   it is not in the depends as we see them
		#   it does not pull some needed dependency which provides it
		elif i not in needed_depend and i not in allprovides:
			warnings.append(("dependency-not-needed %s", i))
	infos.append(("depends-by-namcap-sight depends=(%s)", ' '.join(smartdepend) ))

	return errors, warnings, infos

# vim: set ts=4 sw=4 noet:
