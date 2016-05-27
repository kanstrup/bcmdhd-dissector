bcmdhd-dissector
================

Wireshark protocol dissector for brcmfmac host<->firmware communication protocols

With this plugin the communication protocol between the Linux kernel brcmfmac driver
and the wifi chip firmware is decoded using Wireshark.

Below screenshot shows some of the data flow when inserting a brcmfmac compatible wifi dongle and bringing the
interface up.

![alt screenshot](https://github.com/kanstrup/bcmdhd-dissector/blob/master/examples/screenshot.png)

Next screenshot shows firmware commands interleaved with actual rx/tx data from/to chip while establishing a
wifi connection.

![alt screenshot](https://github.com/kanstrup/bcmdhd-dissector/blob/master/examples/screenshot2.png)

Install instructions
--------------------
1) Copy *.lua to ~/.wireshark/plugins/ folder

2) Clone https://github.com/kanstrup/brcm80211-trace-cmd

3) export TRACE_CMD_PLUGIN_DIR environment to the path of your brmfmac.py file from above brcm80211-trace-cmd

Capturing with patched brcmfmac driver
-------------------------------------

The brcmfmac driver patch add tracepoint events with hexdump of firmware commands
and events. It also add support to dump the TX/RX data passed to/from chip. Then
use trace-cmd with the brcmfmac plugins to record and extract hexdump data and
convert to pcap format with text2pcap tool. The pcap file can then be opened in
wireshark with the lua dissector plugins installed.

1) Patch brcmfmac driver with <pre>0001-brcmfmac-Add-tracepoints-for-bcmdhd-dissector-tool.patch</pre>

2) Enable BRCMDBG config flag and build brcmfmac module.

3) Start trace-cmd recording: <pre>trace-cmd record -e brcmfmac:brcmf_dissect_hexdump -e brcmfmac:brcmf_dissect_data_hexdump</pre>
4) Stop recording when done

5) Create trace-cmd report and let text2pcap tool convert to pcap format: <pre>trace-cmd report | text2pcap - dump.cap</pre>
6) Open pcap file with wireshark

NOTE: With some regexp magic one can trick text2pcap to also include timestamps of recorded events in the capture file: <pre>trace-cmd report | perl -pe 's/.*\[\d{3}\]\s+(\d+.\d{6}):.*\n(.*)/$1 $2/' | text2pcap -t "%s." - dump.cap</pre>


Example dumps
-------------
The examples folder contains some dumps taken from a patched brcmfmac driver
