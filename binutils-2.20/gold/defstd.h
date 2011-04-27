// defstd.h -- define standard symbols for gold   -*- C++ -*-

// Copyright 2006, 2007, 2008 Free Software Foundation, Inc.
// Written by Ian Lance Taylor <iant@google.com>.

// This file is part of gold.

// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street - Fifth Floor, Boston,
// MA 02110-1301, USA.

#ifndef GOLD_DEFSTD_H
#define GOLD_DEFSTD_H

#include <string>
#include <set>
#include "symtab.h"

namespace gold
{

extern void
define_standard_symbols(Symbol_table*, const Layout*);

// @LOCALMOD-BEGIN
extern void
get_standard_symbols(std::set<std::string> &symbols);
// @LOCALMOD-END

} // End namespace gold.

#endif // !defined(GOLD_DEFSTD_H)
