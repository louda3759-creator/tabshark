# TabShark

TabShark opens packet capture files (`.pcap` and `.pcapng`) in your browser and shows what is inside: every packet, every protocol layer, every field, and the raw bytes behind it.

It runs entirely on the page. Nothing is uploaded, and there is no server and no external API.

## What it does

1. **Reads a capture file.** Supports `.pcap` (microsecond or nanosecond timestamps, big or little endian) and `.pcapng`.
2. **Decodes each packet.** Ethernet, ARP, IPv4, IPv6, TCP, UDP, ICMP, DNS, HTTP and TLS handshakes (including the server name).
3. **Shows it in three panes.**
   - Packet list: number, time, source, destination, protocol, length, info.
   - Protocol tree: every layer and field of the selected packet, including TCP flags, sequence numbers and window size.
   - Hex and ASCII: the raw bytes. Click a field to highlight its bytes, or click a byte to jump to its field.
4. **Filters packets.** A filter bar and quick chips narrow the list. A Find box searches packet text and payload.
5. **Flags problems.** TCP resets, retransmissions, DNS error replies, ICMP unreachable messages, malformed packets and wrong checksums are marked red.

## How to use

1. Open `index.html` in a browser.
2. Drag a capture file onto the page, or press **Open capture**. To try it without a file, press **Load Sample Capture**.
3. Click a packet, then expand its layers in the protocol tree.
4. Click any field to see its bytes in the hex pane.
5. Type a filter, for example `tcp.port == 80`, or press a chip such as **Errors**.

## Filters

| Filter | Shows |
| --- | --- |
| `tcp`, `udp`, `dns`, `http`, `tls`, `icmp`, `arp`, `ip`, `ipv6` | Packets using that protocol |
| `error` | Resets, retransmissions, malformed packets, DNS and ICMP errors |
| `ip.addr == 192.168.1.10` | Packets to or from that address |
| `tcp.port == 80`, `udp.port == 53`, `port == 443` | Packets using that port |
| `tcp.flags.syn && !tcp.flags.ack` | Connection attempts |
| `tcp.analysis.retransmission` | Retransmitted segments |
| `frame.len > 200` | Packets longer than 200 bytes |
| `dns.qry.name contains "example"` | DNS queries by name |
| `http.request.method == "GET"` | HTTP requests by method |
| `(tcp || udp) && !dns` | Grouping and negation |
| `example.com` | Any bare word searches the list text |

Operators: `==`, `!=`, `>`, `<`, `>=`, `<=`, `contains`. Combine with `&&`, `||`, `!` and parentheses.

## Keyboard

| Key | Action |
| --- | --- |
| `/` | Focus the filter |
| Up, Down, PageUp, PageDown, Home, End | Move through the list |
| Enter, Shift+Enter (in Find) | Next, previous match |
| `?` | Open the guide |

## Files

| File | Purpose |
| --- | --- |
| `index.html` | Page layout |
| `styles.css` | Styling |
| `pcap-parser.js` | Capture reader, packet decoder, flow analysis, sample generator |
| `app.js` | Filter, packet list, protocol tree, hex viewer |

## Limitations

- No TCP stream reassembly: an HTTP message or TLS record split across segments appears per segment.
- TLS is summarized (versions, server name, cipher suites). Encrypted data is not decrypted.
- HTTP/2, QUIC and other protocols appear as plain TCP or UDP.
- Large captures are parsed in the main thread, so very big files take a moment.

## Author

Khaled Ahmed: [linkedin.com/in/khaled-ahmed-241002386](https://www.linkedin.com/in/khaled-ahmed-241002386)
