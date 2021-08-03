# How to run.

- Make sure you have tshark/wireshark installed on your machine
- Run via CLI by providing interface of packet capture and duration, like so 'python3 sniff.py en0 30'

# High-level documentation

> Libraries used

* pyshark
* matplotlib
* numpy
* ipinfo
* ipaddress

> #### 1. pyshark 

> This is the main library that was used to achieve the goal. It provides an API for network analysis without any GUI like Wireshark (Hence the need to have tshark/wireshark installed on you machine). It handles the packet capture and unwrapping.

> Used features were:
> - 'LiveCapture' and 'sniff' for capturing packets real-time and saving them to a file.
> - Packet unwrapping for details such as Source/Destination IP.

> #### 2. matplotlib & numpy 

> Matplotlib is a visualization lib that plots out the data and numpy is mainly for mathematical use, while in this case was used to find and count unique countries and due to its convenience, quite similiar to lodash.

> #### 3. ipinfo & ipaddress 

> ipinfo a geoloc for IP API service was primarily picked up for long/lat data API, but later was used to find IP's country. Meanwhile ipaddress serves a purpose or not needing to regex filter private IP's and one line it with a simple bool.