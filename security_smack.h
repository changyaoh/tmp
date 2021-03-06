/*
 * Copyright (C) 2013 .
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library.  If not, see
 * <http://www.gnu.org/licenses/>.
 *
 * Author:
 *   Changyao Han <changyaoh@gmail.com>
 *
 */

#ifndef __VIR_SECURITY_SMACK_H__
# define __VIR_SECURITY_SMACK_H__

# include "security_driver.h"

int getfilelabel(const char *path, char ** label);
int setfilelabel(const char *path,const char * label);
int fgetfilelabel(int fd,char ** label);
int fsetfilelabel(int fd,const char * label);
int setsockcreate(const char *label,const char *attr);


extern virSecurityDriver virSmackSecurityDriver;

# define SMACK_PREFIX "smack-"

#endif /* __VIR_SECURITY_SMACK_H__ */
