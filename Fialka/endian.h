/** \file endian.h
  *
  * \brief Describes functions exported by endian.c
  *
  * This file is licensed as described by the file LICENCE.
  */

#ifndef ENDIAN_H_INCLUDED
#define ENDIAN_H_INCLUDED
#include "common.h"


extern void writeU32BigEndian(uint8_tt *out, uint32_tt in);
extern void writeU32LittleEndian(uint8_tt *out, uint32_tt in);
extern uint32_tt readU32BigEndian(uint8_tt *in);
extern uint32_tt readU32LittleEndian(uint8_tt *in);
extern void swapEndian(uint32_tt *v);

#endif // #ifndef ENDIAN_H_INCLUDED
