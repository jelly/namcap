#
# namcap rules - elffiles
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
#   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#

from elftools.elf.elffile import ELFFile
from elftools.elf.dynamic import DynamicSection
from elftools.elf.sections import SymbolTableSection

from Namcap.util import is_elf
from Namcap.ruleclass import *

# Valid directories for ELF files
valid_dirs = ['bin/', 'sbin/', 'usr/bin/', 'usr/sbin/', 'lib/',
		'usr/lib/', 'usr/lib32/']
# Questionable directories for ELF files
# (Suppresses some output spam.)
questionable_dirs = ['opt/']

class ELFPaths(TarballRule):
	name = "elfpaths"
	description = "Check about ELF files outside some standard paths."
	def analyze(self, pkginfo, tar):
		invalid_elffiles = []
		questionable_elffiles = []

		for entry in tar:
			# is it a regular file ?
			if not entry.isfile():
				continue
			# is it outside standard binary dirs ?
			in_std_dirs = any(entry.name.startswith(d) for d in valid_dirs)
			in_que_dirs = any(entry.name.startswith(d) for d in questionable_dirs)

			if in_std_dirs:
				continue
			# is it an ELF file ?
			f = tar.extractfile(entry)
			if is_elf(f):
				if in_que_dirs:
					questionable_elffiles.append(entry.name)
				else:
					invalid_elffiles.append(entry.name)

		que_elfdirs = [d for d in questionable_dirs if any(f.startswith(d) for f in questionable_elffiles)]
		self.errors = [("elffile-not-in-allowed-dirs %s", i)
				for i in invalid_elffiles]
		self.errors.extend(("elffile-in-questionable-dirs %s", i)
				for i in que_elfdirs)
		self.infos = [("elffile-not-in-allowed-dirs %s", i)
				for i in questionable_elffiles]


class ELFTextRelocationRule(TarballRule):
	"""
	Check for text relocations in ELF files.
	"""

	name = "elftextrel"
	description = "Check for text relocations in ELF files."

	def analyze(self, pkginfo, tar):
		files_with_textrel = []

		for entry in tar:
			if not entry.isfile():
				continue
			fp = tar.extractfile(entry)
			if not is_elf(fp):
				continue
			elffile = ELFFile(fp)
			for section in elffile.iter_sections():
				if not isinstance(section, DynamicSection):
					continue
				for tag in section.iter_tags():
					if tag.entry.d_tag == 'DT_TEXTREL':
						files_with_textrel.append(entry.name)

		if files_with_textrel:
			self.warnings = [("elffile-with-textrel %s", i)
					for i in files_with_textrel]

class ELFExecStackRule(TarballRule):
	"""
	Check for executable stacks in ELF files.

	Introduced by FS#26458. Uses pyelftools to read the GNU_STACK
	program header and ensure it does not have the executable bit
	set.
	"""

	name = "elfexecstack"
	description = "Check for executable stacks in ELF files."

	def analyze(self, pkginfo, tar):
		exec_stacks = []

		for entry in tar:
			if not entry.isfile():
				continue
			fp = tar.extractfile(entry)
			if not is_elf(fp):
				continue
			elffile = ELFFile(fp)
			for segment in elffile.iter_segments():
				if segment['p_type'] != 'PT_GNU_STACK':
					continue

				mode = segment['p_flags']
				if mode & 1:
					exec_stacks.append(entry.name)

		if exec_stacks:
			self.warnings = [("elffile-with-execstack %s", i)
					for i in exec_stacks]

class ELFGnuRelroRule(TarballRule):
	"""
	Check for read-only relocation in ELF files.

	Introduced by FS#26435. Uses pyelftools to check for GNU_RELRO.
	"""

	name = "elfgnurelro"
	description = "Check for FULL RELRO in ELF files."

	def has_bind_now(self, elffile):
		for section in elffile.iter_sections():
			if not isinstance(section, DynamicSection):
				continue
			if any(tag.entry.d_tag == 'DT_BIND_NOW' for tag in section.iter_tags()):
				return True
		return False

	def analyze(self, pkginfo, tar):
		missing_relro = []

		for entry in tar:
			if not entry.isfile():
				continue
			fp = tar.extractfile(entry)
			if not is_elf(fp):
				continue
			elffile = ELFFile(fp)
			if any(seg['p_type'] == 'PT_GNU_RELRO' for seg in elffile.iter_segments()):
				if self.has_bind_now(elffile):
					continue

			missing_relro.append(entry.name)

		if missing_relro:
			self.warnings = [("elffile-without-relro %s", i)
					for i in missing_relro]

class ELFUnstrippedRule(TarballRule):
	"""
	Checks for unstripped ELF files. Uses pyelftools to check if
	.symtab exists.

	Introduced by FS#27485.
	"""

	name = "elfunstripped"
	description = "Check for unstripped ELF files."

	def analyze(self, pkginfo, tar):
		unstripped_binaries = []

		for entry in tar:
			if not entry.isfile():
				continue
			fp = tar.extractfile(entry)
			if not is_elf(fp):
				continue
			elffile = ELFFile(fp)
			for section in elffile.iter_sections():
				if not isinstance(section, SymbolTableSection):
					continue

				if section['sh_entsize'] == 0:
					continue

				if section.name == '.symtab':
					unstripped_binaries.append(entry.name)
		if unstripped_binaries:
			self.warnings = [("elffile-unstripped %s", i)
					for i in unstripped_binaries]

class NoPIERule(TarballRule):
	"""
	Checks for no PIE ELF files.
	"""

	name = "elfnopie"
	description = "Check for no PIE ELF files."

	def has_dt_debug(self, elffile):
		for section in elffile.iter_sections():
			if not isinstance(section, DynamicSection):
				continue
			if any(tag.entry.d_tag == 'DT_DEBUG' for tag in section.iter_tags()):
				return True
		return False

	def analyze(self, pkginfo, tar):
		nopie_binaries = []

		for entry in tar:
			if not entry.isfile():
				continue
			fp = tar.extractfile(entry)
			if not is_elf(fp):
				continue
			elffile = ELFFile(fp)
			if elffile.header['e_type'] != 'ET_DYN' or not self.has_dt_debug(elffile):
				nopie_binaries.append(entry.name)

		if nopie_binaries:
			self.warnings = [("elffile-nopie %s", i) for i in nopie_binaries]


# vim: set ts=4 sw=4 noet:
