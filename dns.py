#!/usr/bin/env python3
# coding: utf-8

import os
from bitstring import BitArray

def scramble(data, offset, reverse=False):
    a = bitstr.BitArray(data, endian="little")
    b = bitstr.BitArray(length=len(a))
    
    if len(offset) != 2:
        raise ValueError("The offset must be a tuple with two values!")
    p1, p2 = offset

    for i in range(len(a)): 
        if (i < p1):
            b[i] = a[i]
        elif (i < p2 ):
            x = (a[i-p1] if reverse else b[i-p1])
            b[i] = a[i] ^ x
        else:
            x = (a[i-p1] if reverse else b[i-p1])
            y = (a[i-p2] if reverse else b[i-p2 ])
            b[i] = a[i] ^ x ^ y

    return b.tobytes()

def random_bytes(length):
    return bytearray(os.urandom(length))