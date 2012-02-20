#!/usr/bin/python

# Copyright (c) 2012, Braiden Kindt.
# All rights reserved.
# 
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 
#   1. Redistributions of source code must retain the above copyright
#      notice, this list of conditions and the following disclaimer.
# 
#   2. Redistributions in binary form must reproduce the above
#      copyright notice, this list of conditions and the following
#      disclaimer in the documentation and/or other materials
#      provided with the distribution.
# 
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDER AND CONTRIBUTORS
# ''AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY
# WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

"""
Mock hardware for test or reverse engineering device I don't
own. Using two usb sticks can run this code against windows
ANT agent and it will pretend to be a GPS device.
"""

# FIXME fill in constants for the device you're trying to emulate
DEVICE_NUMBER = 0
DEVICE_TYPE_ID = 0
TRANS_TYPE = 0
BEACON_DESCRIPTOR = "\x00\x00\x00\x00"
DEVICE_SN = "1234"

import logging
import time
import struct
import sys

import antd.cfg as cfg
import antd.hw as hw
import antd.ant as ant
import antd.antfs as antfs
import antd.garmin as garmin

_log = logging.getLogger()
cfg.init_loggers(logging.INFO)

if len(sys.argv) != 2:
	print "usage: %s <chatscript>" % sys.argv[0]
	sys.exit(1)

with open(sys.argv[1]) as file:
    mock = garmin.MockHost(file.read())

usb_ant_stick = hw.UsbHardware()
ant_core = ant.Core(usb_ant_stick)
ant_session = ant.Session(ant_core)
chan = ant_session.channels[0]
net = ant_session.networks[0]

try:
    while True:
        _log.info("RESET")
        ant_session.reset_system()
        net.set_key("\xa8\xa4\x23\xb9\xf5\x5e\x63\xc1")
        chan.assign(0x10, net.network_number)
        chan.set_id(DEVICE_NUMBER, DEVICE_TYPE_ID, TRANS_TYPE)
        chan.set_period(0x1000) # 8hz
        chan.set_rf_freq(50) # 2450mhz
        chan.open()
        beacon = "\x43\x24\x00\x03" + BEACON_DESCRIPTOR
        chan.send_broadcast(beacon)
        while 1:
            try:
                msg = chan.read()
            except ant.AntTimeoutError:
                break
            else:
                if msg.startswith("\x44\x02"):
                    _log.info("LINK: %s", msg.encode("hex"))
                    pg, cmd, freq, period, host = struct.unpack("BBBB4s", msg)
                    period = 2 ** (period - 1)
                    _log.info("LINK: freq=%s, period=%s, host=%s", freq, period, host.encode("hex"))
                    chan.set_rf_freq(freq)
                    chan.set_period(0x8000 / period)
                    beacon = "\x43\x24\x01\x03" + host
                    chan.send_broadcast(beacon)
                elif msg.startswith("\x44\x04\x01"):
                    _log.info("AUTH: get SN#")
                    chan.write(beacon + "\x44\x84\x01\x00" + DEVICE_SN)
                elif msg.startswith("\x44\x04\x02"):
                    _log.info("AUTH: pair")
                    beacon = "\x43\x24\x02\x03" + host
                    chan.write(beacon + "\x44\x84\x01\x08" + DEVICE_SN + ("\x00" * 8))
                    chan.send_broadcast(beacon)
                elif msg.startswith("\x44\x04\x03"):
                    _log.info("AUTH: key")
                    beacon = "\x43\x24\x02\x03" + host
                    chan.write(beacon + "\x44\x84\x01\x00" + DEVICE_SN)
                    chan.send_broadcast(beacon)
                elif msg.startswith("\x44\x0D"):
                    _log.info("RECV: " + msg[8:].encode("hex"))
                    mock.write(msg[8:])
                    data = mock.read()
                    _log.info("SEND: " + data.encode("hex"))
                    reply = "".join([
                        beacon,
                        "\x44\x8D\xFF\xFF\x00\x00" + struct.pack("<H", (len(data) - 1) / 8 + 1),
                        data,
                    ])
                    chan.write(reply)

finally:
    ant_session.close()


# vim: ts=4 sts=4 et
