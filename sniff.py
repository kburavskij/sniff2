import pyshark
import ipinfo
import ipaddress
from datetime import datetime
import matplotlib.pyplot as plt
import numpy as np
import os

access_token = '8f2a068b0e4e27'
file = os.path.dirname(os.path.abspath(__file__)) + '/captures/output.pcap'
output = open(file, "w")

handler = ipinfo.getHandler(access_token)
cap = pyshark.LiveCapture(interface='en0', output_file=file, display_filter='ip && !(ip.dst==10.0.0.0/8) && !(ip.dst==192.168.0.0/16) && ip.version == 4')
print(datetime.now().strftime("%H:%M:%S"))

cap.sniff(timeout=30)

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
plt.show()

output.close()