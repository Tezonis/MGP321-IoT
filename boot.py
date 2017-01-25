# boot.py -- run on boot-up
import os
from machine import UART
uart = UART(0, 115200)
os.dupterm(uart)

import machine
from network import WLAN
wlan = WLAN() # get current object, without changing the mode

if machine.reset_cause() != machine.SOFT_RESET:
    wlan.init(mode=WLAN.STA)
    # configuration below MUST match your home router settings!!
    wlan.ifconfig(config=('192.168.1.2', '255.255.255.0', '192.168.1.1', '8.8.8.8'))

if not wlan.isconnected():
    # change the line below to match your network ssid, security and password
    wlan.connect('Livebox-34C0', auth=(WLAN.WPA2, 'vT7PpSP5W9yysTRoS9'), timeout=5000)
    while not wlan.isconnected():
        machine.idle() # save power while waiting
        print('WLAN connection succeeded!')
        break
