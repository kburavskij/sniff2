import pyshark
import ipinfo
import ipaddress
import matplotlib.pyplot as plt
import numpy as np
import os
import sys

access_token = '8f2a068b0e4e27'
file = os.path.dirname(os.path.abspath(__file__)) + '/captures/output.pcap'
output = open(file, "w")
handler = ipinfo.getHandler(access_token)

try:
    interface = sys.argv[1]
    duration = sys.argv[2]
except IndexError:
    print("You haven't specified interface and or duration")
    print("python3 sniff.py en0 30")
    sys.exit(1)

cap = pyshark.LiveCapture(interface=interface, output_file=file, display_filter='ip && !(ip.dst==10.0.0.0/8) && !(ip.dst==192.168.0.0/16) && ip.version == 4')
cap.sniff(timeout=int(duration))
ipDetails =	{}

for packet in cap.sniff_continuously(packet_count=len(cap)):
    try:
        if(packet.ip.src and not ipaddress.ip_address(packet.ip.src).is_private):
            details = handler.getDetails(packet.ip.src)
            ipDetails[packet.ip.src] = {"lat": details.latitude, "long": details.longitude, "country": details.country}
    except AttributeError as e:
        pass

    try:
        if(packet.ip.dst and not ipaddress.ip_address(packet.ip.dst).is_private):
            details = handler.getDetails(packet.ip.dst)
            ipDetails[packet.ip.dst] = {"lat": details.latitude, "long": details.longitude, "country": details.country}
    except AttributeError as e:
        pass

countryList = []

for ip in ipDetails:
    countryList.append(ipDetails[ip]['country'])

countries, counts = np.unique(countryList, return_counts=True)

plt.bar(countries, counts)
plt.savefig('plot.png')
plt.show()

output.close()