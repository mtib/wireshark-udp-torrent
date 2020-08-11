# wireshark-udp-torrent
Lua Wireshark Plugin adding WIP Parsing of UDP Torrent Tracker Communications.

![](https://github.com/mtib/wireshark-udp-torrent/blob/master/ws.png)

## Usage

Copy "udp_torrent.lua" into your WireShark's [Plugin directory](https://www.wireshark.org/docs/wsug_html_chunked/ChPluginFolders.html). Reload WireShark (CTRL+Shift+L) and UDP Packets on port 6969 (in/out) will be dissected by the UDP Torrent plugin.

## Features

- Dissecting of (some) *connect* and *announce* packets
  - Parsing list of peers

## TODO

- Don't consume uninterpreted packets / data
- Add more supported packets
- Dissect based on packet content instead of port
