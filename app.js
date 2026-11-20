/* =============================================================================
   TabShark - pcap-parser.js
   Pure binary capture reader + protocol dissector. No dependencies.
   Exposes a single global: window.TabShark

   Capture formats : .pcap (us / ns, big / little endian) and .pcapng
   Link layers     : Ethernet (1), Raw IP (101), BSD loopback (0), Linux cooked (113)
   Protocols       : Ethernet II, 802.1Q, ARP, IPv4, IPv6, TCP, UDP, ICMP, ICMPv6,
                     DNS, HTTP/1.x, TLS (record + handshake detection, SNI)
   ============================================================================= */
(function (global) {
  'use strict';

  /* ---------------------------------------------------------------------------
     Dissection tree node. Every node carries the byte range it covers so the
     UI can cross-highlight it in the hex viewer. When the tree is not needed
     (summary pass) a shared NULL node swallows all add() calls for free.
     ------------------------------------------------------------------------- */
  class Node {
    constructor(label, value, start, len, opts) {
      this.label = label;
      this.value = value === undefined || value === null ? '' : String(value);
      this.start = start;
      this.end = start + len;
      this.children = [];
      this.parent = null;
      this.err = !!(opts && opts.err);
      this.bit = !!(opts && opts.bit);
    }
    add(label, value, start, len, opts) {
      const n = new Node(label, value, start, len, opts);
      n.parent = this;
      this.children.push(n);
      return n;
    }
  }
  const NULL = { add() { return NULL; }, children: [] };

  class Malformed extends Error { constructor(layer) { super('Malformed ' + layer); this.layer = layer; } }
  class Truncated extends Error { constructor(layer) { super('Truncated ' + layer); this.layer = layer; } }

  /* ---------------------------------------------------------------------------
     Formatting helpers
     ------------------------------------------------------------------------- */
  const hex = (n, w) => '0x' + (n >>> 0).toString(16).padStart(w || 2, '0');
  const hx2 = (n) => n.toString(16).padStart(2, '0');
  const mac = (d, o) => Array.from(d.subarray(o, o + 6), hx2).join(':');
  const ip4 = (d, o) => d[o] + '.' + d[o + 1] + '.' + d[o + 2] + '.' + d[o + 3];
  const hexStr = (d, s, e) => Array.from(d.subarray(s, e), hx2).join('');
  const swap16 = (n) => ((n & 255) << 8) | (n >> 8);

  function ip6(d, o) {
    const w = [];
    for (let i = 0; i < 8; i++) w.push((d[o + 2 * i] << 8) | d[o + 2 * i + 1]);
    let bs = -1, bl = 0;
    for (let i = 0; i < 8;) {
      if (w[i] === 0) { let j = i; while (j < 8 && w[j] === 0) j++; if (j - i > bl) { bs = i; bl = j - i; } i = j; } else i++;
    }
    const h = (x) => x.toString(16);
    if (bl < 2) return w.map(h).join(':');
    return w.slice(0, bs).map(h).join(':') + '::' + w.slice(bs + bl).map(h).join(':');
  }

  /* Show the bits selected by `mask` in place, dots elsewhere: "0100 ...." */
  function bits(val, mask, width) {
    let s = '';
    for (let i = width - 1; i >= 0; i--) {
      s += ((mask >> i) & 1) ? ((val >> i) & 1) : '.';
      if (i % 4 === 0 && i) s += ' ';
    }
    return s;
  }

  function ascii(d, s, e) {
    let out = '';
    for (let i = s; i < e; i++) out += d[i] >= 32 && d[i] < 127 ? String.fromCharCode(d[i]) : '.';
    return out;
  }

  /* Internet checksum. Returns the folded 16-bit sum (0xffff when valid). */
  function csum(d, s, e, init) {
    let sum = init || 0;
    for (let i = s; i + 1 < e; i += 2) sum += (d[i] << 8) | d[i + 1];
    if ((e - s) & 1) sum += d[e - 1] << 8;
    while (sum > 0xffff) sum = (sum & 0xffff) + (sum >>> 16);
    return sum;
  }

  function fmtAbs(pkt) {
    if (!pkt.sec) return 'not recorded';
    const dt = new Date(pkt.sec * 1000);
    if (isNaN(dt)) return 'invalid';
    return dt.toISOString().slice(0, 19).replace('T', ' ') + '.' + String(pkt.nsec).padStart(9, '0') + ' UTC';
  }

  const ETH_TYPES = { 0x0800: 'IPv4', 0x0806: 'ARP', 0x86dd: 'IPv6', 0x8100: '802.1Q Virtual LAN', 0x88cc: 'LLDP', 0x8847: 'MPLS' };
  const IP_PROTOS = { 1: 'ICMP', 2: 'IGMP', 6: 'TCP', 17: 'UDP', 41: 'IPv6', 47: 'GRE', 50: 'ESP', 51: 'AH', 58: 'ICMPv6', 89: 'OSPF', 132: 'SCTP' };
  const BCAST = 'ff:ff:ff:ff:ff:ff';

  function need(c, o, n, layer, end) {
    const lim = end === undefined ? c.d.length : end;
    if (o + n > lim) throw (c.pkt.capLen < c.pkt.origLen ? new Truncated(layer) : new Malformed(layer));
  }

  function newMeta() {
    return {
      protos: ['frame'], proto: '', info: '', src: '', dst: '', error: false, errKind: '',
      ipv: 0, ipSrc: '', ipDst: '', ttl: 0, l4: '', sp: 0, dp: 0, flags: 0, tcp: null,
      ethSrc: '', ethDst: '', dnsNames: [], host: '', method: '', status: 0, sni: '',
      retrans: false, appInfo: false, opts: ''
    };
  }

  /* ===========================================================================
     Dissector entry point
     dissect(pkt, tree) -> { m: meta, root: Node }
     ========================================================================= */
  function dissect(pkt, tree) {
    const d = pkt.data;
    const c = {
      d, dv: new DataView(d.buffer, d.byteOffset, d.byteLength), tree, pkt,
      root: tree ? new Node('', '', 0, d.length) : NULL, m: newMeta(), addrOff: 0, ipv: 0
    };
    const m = c.m;
    let bad = null, trunc = false;
    try { linkLayer(c); }
    catch (e) {
      if (e instanceof Malformed) bad = e.layer;
      else if (e instanceof Truncated) trunc = true;
      else if (e instanceof RangeError) bad = m.proto || 'Frame';
      else throw e;
    }
    if (bad) {
      m.error = true; m.errKind = 'Malformed'; m.retrans = false; m.info = '[Malformed Packet: ' + bad + ']';
      if (tree) c.root.add('[Malformed Packet: ' + bad + ']', 'The packet is shorter than the protocol requires', 0, 0, { err: true });
    } else if (trunc) {
      m.info = (m.info || m.proto || 'Frame') + ' [Packet size limited during capture]';
    }
    if (!m.proto) m.proto = 'Unknown';
    if (!m.info) m.info = m.proto;

    if (tree) {
      const fr = new Node('Frame ' + pkt.no + ': ' + pkt.origLen + ' bytes on wire (' + pkt.origLen * 8 + ' bits), ' +
        pkt.capLen + ' bytes captured (' + pkt.capLen * 8 + ' bits)', '', 0, d.length);
      fr.parent = c.root;
      fr.add('Arrival Time', fmtAbs(pkt), 0, 0);
      fr.add('Epoch Time', pkt.sec + '.' + String(pkt.nsec).padStart(9, '0') + ' seconds', 0, 0);
      fr.add('Time since first packet', pkt.rel_t.toFixed(9) + ' seconds', 0, 0);
      fr.add('Frame Number', pkt.no, 0, 0);
      fr.add('Frame Length', pkt.origLen + ' bytes (' + pkt.origLen * 8 + ' bits)', 0, 0);
      fr.add('Capture Length', pkt.capLen + ' bytes (' + pkt.capLen * 8 + ' bits)', 0, 0);
      fr.add('Protocols in frame', m.protos.slice(1).join(':'), 0, 0);
      c.root.children.unshift(fr);
    }
    return { m, root: c.root };
  }

  /* ------------------------------ link layers ------------------------------ */
  function linkLayer(c) {
    const { d, dv, m } = c, link = c.pkt.link;
    if (link === 1) return ethernet(c, 0);
    if (link === 101 || link === 12 || link === 228 || link === 229) {
      const v = d.length ? d[0] >> 4 : 0;
      if (v === 4) return ipv4(c, 0);
      if (v === 6) return ipv6(c, 0);
    } else if (link === 0 || link === 108) {
      need(c, 0, 4, 'Loopback');
      let fam = dv.getUint32(0, true);
      if (fam > 0xffff) fam = dv.getUint32(0, false);
      c.root.add('Null/Loopback', 'Family: ' + fam, 0, 4);
      m.protos.push('null');
      if (fam === 2) return ipv4(c, 4);
      if (fam === 24 || fam === 28 || fam === 30) return ipv6(c, 4);
    } else if (link === 113) {
      need(c, 0, 16, 'Linux cooked capture');
      const type = dv.getUint16(14);
      const n = c.root.add('Linux cooked capture v1', '', 0, 16);
      n.add('Packet type', dv.getUint16(0), 0, 2);
      n.add('Link-layer address length', dv.getUint16(4), 4, 2);
      n.add('Protocol', (ETH_TYPES[type] || 'Unknown') + ' (' + hex(type, 4) + ')', 14, 2);
      m.protos.push('sll');
      return etherPayload(c, type, 16);
    }
    m.proto = 'Unknown';
    m.info = 'Unsupported link type ' + link;
  }

  function etherPayload(c, type, o) {
    if (type === 0x0800) return ipv4(c, o);
    if (type === 0x0806) return arp(c, o);
    if (type === 0x86dd) return ipv6(c, o);
    c.m.proto = ETH_TYPES[type] || 'Ethernet';
    c.m.info = 'Ethertype ' + hex(type, 4) + ', ' + (c.d.length - o) + ' bytes of payload';
    if (c.tree && c.d.length > o) c.root.add('Data (' + (c.d.length - o) + ' bytes)', '', o, c.d.length - o);
  }

  function ethernet(c, o) {
    need(c, o, 14, 'Ethernet');
    const { d, dv, m } = c;
    m.ethDst = mac(d, o); m.ethSrc = mac(d, o + 6);
    let type = dv.getUint16(o + 12), hl = 14, vlan = -1;
    if (type === 0x8100) { need(c, o, 18, '802.1Q'); vlan = dv.getUint16(o + 14); type = dv.getUint16(o + 16); hl = 18; }
    m.src = m.ethSrc; m.dst = m.ethDst === BCAST ? 'Broadcast' : m.ethDst;
    m.proto = 'Ethernet'; m.protos.push('eth');
    const n = c.root.add('Ethernet II, Src: ' + m.ethSrc + ', Dst: ' + m.ethDst, '', o, hl);
    n.add('Destination', m.ethDst + (m.ethDst === BCAST ? ' (Broadcast)' : (d[o] & 1 ? ' (Multicast)' : '')), o, 6);
    n.add('Source', m.ethSrc, o + 6, 6);
    if (vlan >= 0) {
      const v = n.add('802.1Q Virtual LAN, ID: ' + (vlan & 0xfff), '', o + 12, 4);
      v.add('Priority', vlan >> 13, o + 14, 2);
      v.add('VLAN ID', vlan & 0xfff, o + 14, 2);
    }
    if (type <= 1500) { m.proto = '802.3'; m.info = 'IEEE 802.3 frame, length ' + type; n.add('Length', type, o + hl - 2, 2); return; }
    n.add('Type', (ETH_TYPES[type] || 'Unknown') + ' (' + hex(type, 4) + ')', o + hl - 2, 2);
    etherPayload(c, type, o + hl);
  }

  function arp(c, o) {
    need(c, o, 28, 'ARP');
    const { d, dv, m } = c;
    const hw = dv.getUint16(o), pt = dv.getUint16(o + 2), op = dv.getUint16(o + 6);
    const sha = mac(d, o + 8), spa = ip4(d, o + 14), tha = mac(d, o + 18), tpa = ip4(d, o + 24);
    m.proto = 'ARP'; m.protos.push('arp');
    if (m.ethDst === BCAST) m.dst = 'Broadcast';
    if (op === 1) m.info = spa === tpa ? 'Gratuitous ARP for ' + tpa + ' (Request)' : 'Who has ' + tpa + '? Tell ' + spa;
    else if (op === 2) m.info = spa + ' is at ' + sha;
    else m.info = 'ARP opcode ' + op;
    const n = c.root.add('Address Resolution Protocol (' + (op === 1 ? 'request' : op === 2 ? 'reply' : 'opcode ' + op) + ')', '', o, 28);
    n.add('Hardware type', (hw === 1 ? 'Ethernet' : 'Unknown') + ' (' + hw + ')', o, 2);
    n.add('Protocol type', (ETH_TYPES[pt] || 'Unknown') + ' (' + hex(pt, 4) + ')', o + 2, 2);
    n.add('Hardware size', d[o + 4], o + 4, 1);
    n.add('Protocol size', d[o + 5], o + 5, 1);
    n.add('Opcode', (op === 1 ? 'request' : op === 2 ? 'reply' : 'unknown') + ' (' + op + ')', o + 6, 2);
    n.add('Sender MAC address', sha, o + 8, 6);
    n.add('Sender IP address', spa, o + 14, 4);
    n.add('Target MAC address', tha, o + 18, 6);
    n.add('Target IP address', tpa, o + 24, 4);
  }

  /* ---------------------------------- IPv4 --------------------------------- */
  function ipv4(c, o) {
    need(c, o, 20, 'IPv4');
    const { d, dv, m } = c;
    const ihl = (d[o] & 15) * 4;
    if ((d[o] >> 4) !== 4 || ihl < 20) throw new Malformed('IPv4');
    need(c, o, ihl, 'IPv4');
    const total = dv.getUint16(o + 2), id = dv.getUint16(o + 4), ff = dv.getUint16(o + 6);
    const ttl = d[o + 8], pr = d[o + 9], ck = dv.getUint16(o + 10);
    if (total < ihl) throw new Malformed('IPv4');
    const src = ip4(d, o + 12), dst = ip4(d, o + 16);
    m.ipv = 4; m.ipSrc = src; m.ipDst = dst; m.src = src; m.dst = dst; m.ttl = ttl; m.proto = 'IPv4'; m.protos.push('ip');
    c.ipv = 4; c.addrOff = o + 12;
    const end = Math.min(o + total, d.length);
    const off = (ff & 0x1fff) * 8, mf = (ff >> 13) & 1;
    const pname = IP_PROTOS[pr] || 'Protocol ' + pr;

    if (c.tree) {
      const n = c.root.add('Internet Protocol Version 4, Src: ' + src + ', Dst: ' + dst, '', o, ihl);
      n.add(bits(d[o], 0xf0, 8) + ' = Version: 4', '', o, 1);
      n.add(bits(d[o], 0x0f, 8) + ' = Header Length: ' + ihl + ' bytes (' + ihl / 4 + ')', '', o, 1);
      n.add('Differentiated Services Field', hex(d[o + 1]) + ' (DSCP ' + (d[o + 1] >> 2) + ', ECN ' + (d[o + 1] & 3) + ')', o + 1, 1);
      n.add('Total Length', total, o + 2, 2);
      n.add('Identification', hex(id, 4) + ' (' + id + ')', o + 4, 2);
      const fl = n.add('Flags', hex(ff >> 8) + (ff & 0x4000 ? ', Don\'t fragment' : '') + (mf ? ', More fragments' : ''), o + 6, 1);
      fl.add(bits(ff, 0x8000, 16) + ' = Reserved bit: ' + ((ff >> 15) & 1 ? 'Set' : 'Not set'), '', o + 6, 1, { bit: true });
      fl.add(bits(ff, 0x4000, 16) + ' = Don\'t fragment: ' + ((ff >> 14) & 1 ? 'Set' : 'Not set'), '', o + 6, 1, { bit: true });
      fl.add(bits(ff, 0x2000, 16) + ' = More fragments: ' + (mf ? 'Set' : 'Not set'), '', o + 6, 1, { bit: true });
      n.add('Fragment Offset', off, o + 6, 2);
      n.add('Time to Live', ttl, o + 8, 1);
      n.add('Protocol', pname + ' (' + pr + ')', o + 9, 1);
      const okc = csum(d, o, o + ihl) === 0xffff;
      n.add('Header Checksum', hex(ck, 4) + (okc ? ' [correct]' : ' [incorrect]'), o + 10, 2, okc ? null : { err: true });
      n.add('Source Address', src, o + 12, 4);
      n.add('Destination Address', dst, o + 16, 4);
      if (ihl > 20) n.add('Options', (ihl - 20) + ' bytes', o + 20, ihl - 20);
    }
    if (off || mf) { m.info = 'Fragmented IP protocol (proto=' + pname + ' ' + pr + ', off=' + off + ', ID=' + hex(id, 4) + ')'; return; }
    l4(c, pr, o + ihl, end);
  }

  /* ---------------------------------- IPv6 --------------------------------- */
  function ipv6(c, o) {
    need(c, o, 40, 'IPv6');
    const { d, dv, m } = c;
    if ((d[o] >> 4) !== 6) throw new Malformed('IPv6');
    const pl = dv.getUint16(o + 4);
    let nh = d[o + 6];
    const src = ip6(d, o + 8), dst = ip6(d, o + 24);
    m.ipv = 6; m.ipSrc = src; m.ipDst = dst; m.src = src; m.dst = dst; m.ttl = d[o + 7]; m.proto = 'IPv6'; m.protos.push('ipv6');
    c.ipv = 6; c.addrOff = o + 8;
    const end = pl === 0 ? d.length : Math.min(o + 40 + pl, d.length);
    if (c.tree) {
      const n = c.root.add('Internet Protocol Version 6, Src: ' + src + ', Dst: ' + dst, '', o, 40);
      n.add(bits(d[o], 0xf0, 8) + ' = Version: 6', '', o, 1);
      n.add('Traffic Class', hex(((d[o] & 15) << 4) | (d[o + 1] >> 4)), o, 2);
      n.add('Flow Label', hex(dv.getUint32(o) & 0xfffff, 5), o + 1, 3);
      n.add('Payload Length', pl, o + 4, 2);
      n.add('Next Header', (IP_PROTOS[nh] || 'Unknown') + ' (' + nh + ')', o + 6, 1);
      n.add('Hop Limit', d[o + 7], o + 7, 1);
      n.add('Source Address', src, o + 8, 16);
      n.add('Destination Address', dst, o + 24, 16);
    }
    let p = o + 40;
    while ((nh === 0 || nh === 43 || nh === 60 || nh === 44 || nh === 51) && p + 8 <= end) {
      const len = nh === 44 ? 8 : nh === 51 ? (d[p + 1] + 2) * 4 : (d[p + 1] + 1) * 8;
      const names = { 0: 'Hop-by-Hop Options', 43: 'Routing Header', 60: 'Destination Options', 44: 'Fragment Header', 51: 'Authentication Header' };
      const en = c.root.add('IPv6 ' + names[nh], '', p, len);
      en.add('Next Header', (IP_PROTOS[d[p]] || 'Unknown') + ' (' + d[p] + ')', p, 1);
      if (nh === 44 && (dv.getUint16(p + 2) >> 3) !== 0) { m.info = 'Fragmented IPv6 protocol (off=' + (dv.getUint16(p + 2) >> 3) * 8 + ')'; return; }
      nh = d[p]; p += len;
    }
    l4(c, nh, p, end);
  }

  function l4(c, pr, o, end) {
    const m = c.m;
    if (pr === 6) return tcp(c, o, end);
    if (pr === 17) return udp(c, o, end);
    if (pr === 1) return icmp(c, o, end);
    if (pr === 58) return icmpv6(c, o, end);
    m.proto = IP_PROTOS[pr] || 'IPv' + m.ipv;
    m.info = (IP_PROTOS[pr] || 'Protocol ' + pr) + ', ' + Math.max(0, end - o) + ' bytes of payload';
    if (c.tree && end > o) c.root.add('Payload (' + (end - o) + ' bytes)', '', o, end - o);
  }

  function pseudoSum(c, proto, len) {
    let s = 0;
    const n = c.ipv === 4 ? 8 : 32;
    for (let i = 0; i < n; i += 2) s += (c.d[c.addrOff + i] << 8) | c.d[c.addrOff + i + 1];
    return s + proto + len;
  }
  const fullFrame = (c) => c.pkt.capLen === c.pkt.origLen;

  /* ---------------------------------- ICMP --------------------------------- */
  function icmp(c, o, end) {
    need(c, o, 4, 'ICMP', end);
    const { d, dv, m } = c;
    const type = d[o], code = d[o + 1], ck = dv.getUint16(o + 2);
    const T = { 0: 'Echo (ping) reply', 3: 'Destination unreachable', 4: 'Source quench', 5: 'Redirect', 8: 'Echo (ping) request', 9: 'Router advertisement', 10: 'Router solicitation', 11: 'Time-to-live exceeded', 12: 'Parameter problem', 13: 'Timestamp request', 14: 'Timestamp reply' };
    const U = { 0: 'Network unreachable', 1: 'Host unreachable', 2: 'Protocol unreachable', 3: 'Port unreachable', 4: 'Fragmentation needed', 5: 'Source route failed', 13: 'Communication administratively filtered' };
    const name = T[type] || 'Type ' + type;
    m.proto = 'ICMP'; m.l4 = 'icmp'; m.protos.push('icmp');
    const n = c.root.add('Internet Control Message Protocol', '', o, end - o);
    n.add('Type', type + ' (' + name + ')', o, 1);
    n.add('Code', code + (type === 3 && U[code] ? ' (' + U[code] + ')' : ''), o + 1, 1);
    if (c.tree) {
      const ok = fullFrame(c) ? csum(d, o, end) === 0xffff : null;
      n.add('Checksum', hex(ck, 4) + (ok === null ? '' : ok ? ' [correct]' : ' [incorrect]'), o + 2, 2);
    }
    if ((type === 0 || type === 8) && end - o >= 8) {
      const id = dv.getUint16(o + 4), sq = dv.getUint16(o + 6);
      n.add('Identifier (BE)', id + ' (' + hex(id, 4) + ')', o + 4, 2);
      n.add('Sequence Number (BE)', sq + ' (' + hex(sq, 4) + ')', o + 6, 2);
      if (end > o + 8) n.add('Data (' + (end - o - 8) + ' bytes)', ascii(d, o + 8, Math.min(end, o + 24)), o + 8, end - o - 8);
      m.info = name + '  id=' + hex(id, 4) + ', seq=' + sq + '/' + swap16(sq) + ', ttl=' + m.ttl;
    } else {
      m.info = name + (type === 3 && U[code] ? ' (' + U[code] + ')' : '');
      if (type === 3 || type === 11 || type === 12 || type === 5) {
        if (type !== 5) { m.error = true; m.errKind = 'ICMP'; }
        if (end > o + 8) n.add('Original packet header and data (' + (end - o - 8) + ' bytes)', '', o + 8, end - o - 8);
      }
    }
  }

  function icmpv6(c, o, end) {
    need(c, o, 4, 'ICMPv6', end);
    const { d, dv, m } = c;
    const type = d[o], code = d[o + 1];
    const T = { 1: 'Destination Unreachable', 2: 'Packet Too Big', 3: 'Time Exceeded', 4: 'Parameter Problem', 128: 'Echo (ping) request', 129: 'Echo (ping) reply', 133: 'Router Solicitation', 134: 'Router Advertisement', 135: 'Neighbor Solicitation', 136: 'Neighbor Advertisement' };
    const name = T[type] || 'Type ' + type;
    m.proto = 'ICMPv6'; m.l4 = 'icmp'; m.protos.push('icmpv6');
    const n = c.root.add('Internet Control Message Protocol v6', '', o, end - o);
    n.add('Type', name + ' (' + type + ')', o, 1);
    n.add('Code', code, o + 1, 1);
    if (c.tree && fullFrame(c)) {
      const ok = csum(d, o, end, pseudoSum(c, 58, end - o)) === 0xffff;
      n.add('Checksum', hex(dv.getUint16(o + 2), 4) + (ok ? ' [correct]' : ' [incorrect]'), o + 2, 2);
    }
    m.info = name;
    if ((type === 135 || type === 136) && end - o >= 24) {
      const tgt = ip6(d, o + 8);
      n.add('Target Address', tgt, o + 8, 16);
      m.info = name + (type === 135 ? ' for ' : ' ') + tgt;
    } else if ((type === 128 || type === 129) && end - o >= 8) {
      const id = dv.getUint16(o + 4), sq = dv.getUint16(o + 6);
      n.add('Identifier', hex(id, 4), o + 4, 2);
      n.add('Sequence', sq, o + 6, 2);
      m.info = name + ' id=' + hex(id, 4) + ', seq=' + sq + ', hop limit=' + m.ttl;
    } else if (type >= 1 && type <= 4) { m.error = true; m.errKind = 'ICMP'; }
  }

  /* ----------------------------------- UDP --------------------------------- */
  function udp(c, o, end) {
    need(c, o, 8, 'UDP', end);
    const { d, dv, m } = c;
    const sp = dv.getUint16(o), dp = dv.getUint16(o + 2), len = dv.getUint16(o + 4), ck = dv.getUint16(o + 6);
    if (len < 8) throw new Malformed('UDP');
    const pend = Math.min(end, o + len), plen = pend - o - 8;
    m.l4 = 'udp'; m.sp = sp; m.dp = dp; m.proto = 'UDP'; m.protos.push('udp');
    const n = c.root.add('User Datagram Protocol, Src Port: ' + sp + ', Dst Port: ' + dp, '', o, 8);
    n.add('Source Port', sp, o, 2);
    n.add('Destination Port', dp, o + 2, 2);
    n.add('Length', len, o + 4, 2);
    if (c.tree) {
      let note = '';
      if (ck === 0 && c.ipv === 4) note = ' [none]';
      else if (fullFrame(c) && o + len <= c.d.length) note = csum(d, o, o + len, pseudoSum(c, 17, len)) === 0xffff ? ' [correct]' : ' [incorrect]';
      n.add('Checksum', hex(ck, 4) + note, o + 6, 2);
    }
    m.info = sp + ' \u2192 ' + dp + ' Len=' + plen;
    if (plen > 0) {
      n.add('UDP payload (' + plen + ' bytes)', '', o + 8, plen);
      if (sp === 53 || dp === 53 || sp === 5353 || dp === 5353) dns(c, o + 8, pend);
      else c.root.add('Data (' + plen + ' bytes)', ascii(d, o + 8, Math.min(pend, o + 8 + 32)), o + 8, plen);
    }
  }

  /* ----------------------------------- TCP --------------------------------- */
  const TCP_FLAGS = ['FIN', 'SYN', 'RST', 'PSH', 'ACK', 'URG', 'ECE', 'CWR', 'NS'];
  const TCP_FLAG_LABEL = { FIN: 'Fin', SYN: 'Syn', RST: 'Reset', PSH: 'Push', ACK: 'Acknowledgment', URG: 'Urgent', ECE: 'ECN-Echo', CWR: 'Congestion Window Reduced', NS: 'Accurate ECN' };
  const flagList = (fl) => TCP_FLAGS.filter((_, i) => (fl >> i) & 1);

  function tcpInfoStr(m, rel) {
    const t = m.tcp, fl = flagList(t.flags);
    const seq = rel ? rel.seq : t.seq, ack = rel ? rel.ack : t.ack;
    return m.sp + ' \u2192 ' + m.dp + ' [' + fl.join(', ') + '] Seq=' + seq + (t.flags & 16 ? ' Ack=' + ack : '') +
      ' Win=' + t.win + ' Len=' + t.len + (m.opts ? ' ' + m.opts : '');
  }

  function tcp(c, o, end) {
    need(c, o, 20, 'TCP', end);
    const { d, dv, m } = c;
    const sp = dv.getUint16(o), dp = dv.getUint16(o + 2), seq = dv.getUint32(o + 4), ack = dv.getUint32(o + 8);
    const hl = (d[o + 12] >> 4) * 4, fl = d[o + 13] | ((d[o + 12] & 1) << 8);
    const win = dv.getUint16(o + 14), ck = dv.getUint16(o + 16), urg = dv.getUint16(o + 18);
    if (hl < 20 || o + hl > end) throw new Malformed('TCP');
    const plen = end - o - hl;
    m.l4 = 'tcp'; m.sp = sp; m.dp = dp; m.flags = fl; m.proto = 'TCP'; m.protos.push('tcp');
    m.tcp = { seq, ack, win, len: plen, flags: fl };
    if (fl & 4) { m.error = true; m.errKind = 'TCP Reset'; }
    const rel = c.pkt.rel;

    const n = c.root.add('Transmission Control Protocol, Src Port: ' + sp + ', Dst Port: ' + dp +
      ', Seq: ' + (rel ? rel.seq : seq) + (fl & 16 ? ', Ack: ' + (rel ? rel.ack : ack) : '') + ', Len: ' + plen, '', o, hl);
    n.add('Source Port', sp, o, 2);
    n.add('Destination Port', dp, o + 2, 2);
    n.add('TCP Segment Len', plen, o + hl, 0);
    if (rel) {
      n.add('Sequence Number', rel.seq + '    (relative sequence number)', o + 4, 4);
      n.add('Sequence Number (raw)', seq, o + 4, 4);
      if (fl & 16) {
        n.add('Acknowledgment Number', rel.ack + '    (relative ack number)', o + 8, 4);
        n.add('Acknowledgment number (raw)', ack, o + 8, 4);
      }
    } else {
      n.add('Sequence Number (raw)', seq, o + 4, 4);
      n.add('Acknowledgment number (raw)', ack, o + 8, 4);
    }
    n.add(bits(d[o + 12], 0xf0, 8) + ' = Header Length: ' + hl + ' bytes (' + hl / 4 + ')', '', o + 12, 1);
    const fn = n.add('Flags', hex(fl, 3) + ' (' + flagList(fl).join(', ') + ')', o + 12, 2);
    if (c.tree) {
      fn.add(bits(d[o + 12], 0x0e, 8) + ' = Reserved: Not set', '', o + 12, 1, { bit: true });
      for (let b = 8; b >= 0; b--) {
        const nm = TCP_FLAGS[b], inFirst = b === 8;
        const byteVal = inFirst ? d[o + 12] : d[o + 13], bitPos = inFirst ? 0 : b;
        fn.add(bits(byteVal, 1 << bitPos, 8) + ' = ' + TCP_FLAG_LABEL[nm] + ': ' + ((fl >> b) & 1 ? 'Set' : 'Not set'), '', inFirst ? o + 12 : o + 13, 1, { bit: true });
      }
    }
    n.add('Window', win, o + 14, 2);
    if (c.tree) {
      const ok = fullFrame(c) ? csum(d, o, end, pseudoSum(c, 6, end - o)) === 0xffff : null;
      n.add('Checksum', hex(ck, 4) + (ok === null ? '' : ok ? ' [correct]' : ' [incorrect]'), o + 16, 2, ok === false ? { err: true } : null);
    }
    n.add('Urgent Pointer', urg, o + 18, 2);

    /* options */
    const oi = [];
    if (hl > 20) {
      const on = n.add('Options: (' + (hl - 20) + ' bytes)', '', o + 20, hl - 20), names = [];
      let q = o + 20; const oe = o + hl;
      while (q < oe) {
        const k = d[q];
        if (k === 0) { on.add('TCP Option - End of Option List (EOL)', '', q, 1); names.push('End of Option List'); break; }
        if (k === 1) { on.add('TCP Option - No-Operation (NOP)', '', q, 1); names.push('No-Operation (NOP)'); q++; continue; }
        const l = d[q + 1];
        if (l < 2 || q + l > oe) break;
        if (k === 2 && l === 4) { const v = dv.getUint16(q + 2); on.add('TCP Option - Maximum segment size: ' + v + ' bytes', '', q, l); names.push('Maximum segment size'); oi.push('MSS=' + v); }
        else if (k === 3 && l === 3) { const v = d[q + 2]; on.add('TCP Option - Window scale: ' + v + ' (multiply by ' + (1 << v) + ')', '', q, l); names.push('Window scale'); oi.push('WS=' + (1 << v)); }
        else if (k === 4) { on.add('TCP Option - SACK permitted', '', q, l); names.push('SACK permitted'); oi.push('SACK_PERM'); }
        else if (k === 5) { on.add('TCP Option - SACK (' + (l - 2) / 8 + ' blocks)', '', q, l); names.push('SACK'); oi.push('SACK'); }
        else if (k === 8 && l === 10) { const a = dv.getUint32(q + 2), b = dv.getUint32(q + 6); on.add('TCP Option - Timestamps: TSval ' + a + ', TSecr ' + b, '', q, l); names.push('Timestamps'); oi.push('TSval=' + a, 'TSecr=' + b); }
        else { on.add('TCP Option - Kind ' + k, '', q, l); names.push('Kind ' + k); }
        q += l;
      }
      on.label = 'Options: (' + (hl - 20) + ' bytes), ' + names.join(', ');
    }
    m.opts = oi.join(' ');
    if (c.pkt.analysis && c.pkt.analysis.retrans) {
      const an = n.add('[SEQ/ACK analysis]', '', o, 0);
      an.add('[TCP Analysis Flags]', '', o, 0).add('[Expert Info (Note/Sequence): This frame is a (suspected) retransmission]', '', o, 0, { err: true });
    }

    /* payload + application layers */
    const p = o + hl;
    let app = false;
    if (plen > 0) {
      n.add('TCP payload (' + plen + ' bytes)', '', p, plen);
      if (http(c, p, end)) app = true;
      else if (tls(c, p, end)) app = true;
      else if (sp === 53 || dp === 53) {
        if (plen > 2) { dns(c, p + 2, end); app = true; }
      }
      if (!app) c.root.add('Data (' + plen + ' bytes)', ascii(d, p, Math.min(end, p + 32)), p, plen);
    }
    m.appInfo = app;
    if (!app) m.info = tcpInfoStr(m, null);
  }

  /* ----------------------------------- HTTP -------------------------------- */
  const HTTP_RE = /^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|CONNECT|TRACE) \S+ HTTP\/1\.[01]\r\n|^HTTP\/1\.[01] \d{3}/;

  function http(c, o, end) {
    const { d, m } = c;
    const lim = Math.min(end, o + 8192);
    let s = '';
    for (let i = o; i < lim; i++) s += String.fromCharCode(d[i]);
    if (!HTTP_RE.test(s)) return false;
    const lines = [];
    let pos = 0, complete = false;
    while (pos < s.length) {
      const e = s.indexOf('\r\n', pos);
      if (e < 0) { lines.push([pos, s.length, s.slice(pos)]); pos = s.length; break; }
      if (e === pos) { pos += 2; complete = true; break; }
      lines.push([pos, e + 2, s.slice(pos, e)]);
      pos = e + 2;
    }
    const isResp = s.startsWith('HTTP/');
    m.proto = 'HTTP'; m.protos.push('http');
    const first = lines[0][2];
    let ctype = '';
    lines.slice(1).forEach(([, , t]) => {
      const i = t.indexOf(':');
      if (i < 0) return;
      const k = t.slice(0, i).toLowerCase(), v = t.slice(i + 1).trim();
      if (k === 'host') m.host = v;
      if (k === 'content-type') ctype = v.split(';')[0];
    });
    if (isResp) {
      const mm = /^HTTP\/1\.[01] (\d{3})/.exec(first);
      m.status = mm ? +mm[1] : 0;
      m.info = first + (ctype ? '  (' + ctype + ')' : '');
      if (m.status >= 400) { m.error = true; m.errKind = 'HTTP ' + m.status; }
    } else {
      m.method = first.split(' ')[0];
      m.info = first;
    }
    const n = c.root.add('Hypertext Transfer Protocol', '', o, end - o);
    lines.forEach(([a, b, t], idx) => {
      const ln = n.add(t + '\\r\\n', '', o + a, b - a);
      if (idx === 0) {
        const mm = /^(\S+) (\S+) (\S+)/.exec(t);
        if (mm && !isResp) {
          ln.add('Request Method', mm[1], o + a, mm[1].length);
          ln.add('Request URI', mm[2], o + a + mm[1].length + 1, mm[2].length);
          ln.add('Request Version', mm[3], o + a + mm[1].length + mm[2].length + 2, mm[3].length);
        } else if (isResp) {
          const rm = /^(\S+) (\d{3}) ?(.*)$/.exec(t);
          if (rm) {
            ln.add('Response Version', rm[1], o + a, rm[1].length);
            ln.add('Status Code', rm[2], o + a + rm[1].length + 1, 3);
            if (rm[3]) ln.add('Response Phrase', rm[3], o + a + rm[1].length + 5, rm[3].length);
          }
        }
      }
    });
    if (!isResp && m.host) {
      const uri = (/^\S+ (\S+)/.exec(first) || [])[1] || '/';
      n.add('Full request URI', 'http://' + m.host + uri, o, 0);
    }
    if (complete) n.add('\\r\\n', '', o + pos - 2, 2);
    const bodyLen = end - (o + pos);
    if (complete && bodyLen > 0) n.add('File Data: ' + bodyLen + ' bytes', '', o + pos, bodyLen);
    return true;
  }

  /* ----------------------------------- TLS --------------------------------- */
  const TLSV = { 0x0300: 'SSLv3', 0x0301: 'TLSv1', 0x0302: 'TLSv1.1', 0x0303: 'TLSv1.2', 0x0304: 'TLSv1.3' };
  const TLS_CT = { 20: 'Change Cipher Spec', 21: 'Alert', 22: 'Handshake Protocol', 23: 'Application Data' };
  const TLS_HS = { 0: 'Hello Request', 1: 'Client Hello', 2: 'Server Hello', 4: 'New Session Ticket', 8: 'Encrypted Extensions', 11: 'Certificate', 12: 'Server Key Exchange', 13: 'Certificate Request', 14: 'Server Hello Done', 15: 'Certificate Verify', 16: 'Client Key Exchange', 20: 'Finished' };
  const TLS_EXT = { 0: 'server_name', 5: 'status_request', 10: 'supported_groups', 11: 'ec_point_formats', 13: 'signature_algorithms', 16: 'application_layer_protocol_negotiation', 23: 'extended_master_secret', 35: 'session_ticket', 43: 'supported_versions', 45: 'psk_key_exchange_modes', 51: 'key_share', 65281: 'renegotiation_info' };
  const TLS_CS = { 0x1301: 'TLS_AES_128_GCM_SHA256', 0x1302: 'TLS_AES_256_GCM_SHA384', 0x1303: 'TLS_CHACHA20_POLY1305_SHA256', 0xc02b: 'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256', 0xc02f: 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256', 0xc02c: 'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384', 0xc030: 'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384', 0xcca9: 'TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256', 0xcca8: 'TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256', 0x009c: 'TLS_RSA_WITH_AES_128_GCM_SHA256', 0x002f: 'TLS_RSA_WITH_AES_128_CBC_SHA', 0x0035: 'TLS_RSA_WITH_AES_256_CBC_SHA' };

  function tlsDetect(d, o, end) {
    return end - o >= 5 && d[o] >= 20 && d[o] <= 23 && d[o + 1] === 3 && d[o + 2] <= 4 && ((d[o + 3] << 8) | d[o + 4]) <= 18432;
  }

  function tls(c, o, end) {
    const { d, dv, m } = c;
    if (!tlsDetect(d, o, end)) return false;
    m.protos.push('tls', 'ssl');
    const infos = [];
    const st = { ver13: false, hsVer: 0 };
    let p = o, first = true, recVer = 0;
    while (p + 5 <= end && tlsDetect(d, p, end + 0)) {
      const ct = d[p], ver = dv.getUint16(p + 1), len = dv.getUint16(p + 3);
      if (first) { recVer = ver; first = false; }
      const rend = Math.min(p + 5 + len, end);
      const vn = TLSV[ver] || 'TLS';
      const rec = c.root.add(vn + ' Record Layer: ' + TLS_CT[ct], '', p, rend - p);
      rec.add('Content Type', TLS_CT[ct] + ' (' + ct + ')', p, 1);
      rec.add('Version', vn + ' (' + hex(ver, 4) + ')', p + 1, 2);
      rec.add('Length', len, p + 3, 2);
      if (ct === 22) {
        let q = p + 5;
        const hsNames = [];
        while (q + 4 <= rend) {
          const ht = d[q], hl = (d[q + 1] << 16) | (d[q + 2] << 8) | d[q + 3];
          const hend = Math.min(q + 4 + hl, rend);
          if (TLS_HS[ht] === undefined || (hl > len)) {
            rec.add('Handshake Protocol: Encrypted Handshake Message', '', q, rend - q);
            hsNames.push('Encrypted Handshake Message'); break;
          }
          const hn = rec.add('Handshake Protocol: ' + TLS_HS[ht], '', q, hend - q);
          hn.add('Handshake Type', TLS_HS[ht] + ' (' + ht + ')', q, 1);
          hn.add('Length', hl, q + 1, 3);
          hsNames.push(TLS_HS[ht]);
          try {
            if (ht === 1) clientHello(c, hn, q + 4, hend, st);
            else if (ht === 2) serverHello(c, hn, q + 4, hend, st);
          } catch (e) {
            if (!(e instanceof RangeError)) throw e;
            hn.add('[Handshake continues in a following segment]', '', hend, 0);
          }
          q = q + 4 + hl;
        }
        rec.label = vn + ' Record Layer: Handshake Protocol: ' + hsNames.join(', ');
        infos.push(hsNames.join(', ') + (m.sni && hsNames[0] === 'Client Hello' ? ' (SNI=' + m.sni + ')' : ''));
      } else if (ct === 23) {
        rec.add('Encrypted Application Data', (rend - p - 5) + ' bytes', p + 5, rend - p - 5);
        infos.push('Application Data');
      } else if (ct === 20) {
        rec.add('Change Cipher Spec Message', '', p + 5, rend - p - 5);
        infos.push('Change Cipher Spec');
      } else {
        const lvl = rend - p >= 7 ? d[p + 5] : 0, desc = rend - p >= 7 ? d[p + 6] : 0;
        rec.add('Alert Message', 'Level ' + lvl + ', Description ' + desc, p + 5, Math.max(0, rend - p - 5));
        infos.push('Encrypted Alert');
        if (lvl === 2) { m.error = true; m.errKind = 'TLS Alert'; }
      }
      if (rend >= end) break;
      p = rend;
    }
    const base = st.ver13 ? 0x0304 : (st.hsVer || recVer);
    m.proto = TLSV[base] || 'TLS';
    m.info = infos.join(', ');
    return true;
  }

  function clientHello(c, n, r, hend, st) {
    const { d, dv, m } = c;
    const ver = dv.getUint16(r);
    st.hsVer = ver;
    n.add('Version', (TLSV[ver] || 'Unknown') + ' (' + hex(ver, 4) + ')', r, 2); r += 2;
    n.add('Random', hexStr(d, r, r + 8) + '...', r, 32); r += 32;
    const sl = d[r];
    n.add('Session ID Length', sl, r, 1); r += 1;
    if (sl) n.add('Session ID', hexStr(d, r, r + Math.min(sl, 8)) + '...', r, sl);
    r += sl;
    const csl = dv.getUint16(r);
    n.add('Cipher Suites Length', csl, r, 2); r += 2;
    const cs = n.add('Cipher Suites (' + csl / 2 + ' suites)', '', r, csl);
    for (let i = 0; i < csl; i += 2) {
      const id = dv.getUint16(r + i);
      cs.add('Cipher Suite: ' + (TLS_CS[id] || 'Unknown') + ' (' + hex(id, 4) + ')', '', r + i, 2);
    }
    r += csl;
    const cm = d[r];
    n.add('Compression Methods Length', cm, r, 1); r += 1;
    n.add('Compression Methods', cm + ' method(s)', r, cm); r += cm;
    if (r + 2 > hend) return;
    const el = dv.getUint16(r);
    n.add('Extensions Length', el, r, 2); r += 2;
    extensions(c, n, r, Math.min(r + el, hend), true, st);
  }

  function serverHello(c, n, r, hend, st) {
    const { d, dv } = c;
    const ver = dv.getUint16(r);
    st.hsVer = ver;
    n.add('Version', (TLSV[ver] || 'Unknown') + ' (' + hex(ver, 4) + ')', r, 2); r += 2;
    n.add('Random', hexStr(d, r, r + 8) + '...', r, 32); r += 32;
    const sl = d[r];
    n.add('Session ID Length', sl, r, 1); r += 1;
    if (sl) n.add('Session ID', hexStr(d, r, r + Math.min(sl, 8)) + '...', r, sl);
    r += sl;
    const cs = dv.getUint16(r);
    n.add('Cipher Suite', (TLS_CS[cs] || 'Unknown') + ' (' + hex(cs, 4) + ')', r, 2); r += 2;
    n.add('Compression Method', d[r] === 0 ? 'null (0)' : d[r], r, 1); r += 1;
    if (r + 2 > hend) return;
    const el = dv.getUint16(r);
    n.add('Extensions Length', el, r, 2); r += 2;
    extensions(c, n, r, Math.min(r + el, hend), false, st);
  }

  function extensions(c, n, r, eend, isClient, st) {
    const { d, dv, m } = c;
    while (r + 4 <= eend) {
      const t = dv.getUint16(r), l = dv.getUint16(r + 2);
      const en = n.add('Extension: ' + (TLS_EXT[t] || 'type ' + t) + ' (len=' + l + ')', '', r, Math.min(4 + l, eend - r));
      en.add('Type', (TLS_EXT[t] || 'Unknown') + ' (' + t + ')', r, 2);
      en.add('Length', l, r + 2, 2);
      const b = r + 4;
      if (t === 0 && l >= 5 && isClient) {
        const nl = dv.getUint16(b + 3);
        const name = ascii(d, b + 5, b + 5 + nl);
        m.sni = name;
        en.add('Server Name Indication extension', '', b, l)
          .add('Server Name', name, b + 5, nl);
        en.label = 'Extension: server_name (len=' + l + ') name=' + name;
      } else if (t === 43) {
        if (isClient) {
          const ll = d[b], list = [];
          for (let i = 0; i < ll; i += 2) { const v = dv.getUint16(b + 1 + i); list.push(TLSV[v] || hex(v, 4)); if (v === 0x0304) st.ver13 = true; }
          en.add('Supported Versions', list.join(', '), b, l);
        } else {
          const v = dv.getUint16(b);
          if (v === 0x0304) st.ver13 = true;
          en.add('Supported Version', TLSV[v] || hex(v, 4), b, 2);
        }
      } else if (t === 16 && isClient && l > 2) {
        const names = [];
        let q = b + 2;
        while (q < b + 2 + dv.getUint16(b) && q < eend) { const sl = d[q]; names.push(ascii(d, q + 1, q + 1 + sl)); q += 1 + sl; }
        en.add('ALPN Protocols', names.join(', '), b, l);
      }
      r += 4 + l;
    }
  }

  /* ----------------------------------- DNS --------------------------------- */
  const DNS_T = { 1: 'A', 2: 'NS', 5: 'CNAME', 6: 'SOA', 12: 'PTR', 15: 'MX', 16: 'TXT', 28: 'AAAA', 33: 'SRV', 41: 'OPT', 65: 'HTTPS', 255: 'ANY' };
  const DNS_RC = ['No error', 'Format error', 'Server failure', 'No such name', 'Not implemented', 'Refused'];
  const DNS_OP = { 0: 'Standard query', 1: 'Inverse query', 2: 'Server status request', 4: 'Notify', 5: 'Update' };

  function dnsName(d, p, base, end) {
    let name = '', jumped = false, next = -1, hops = 0;
    for (;;) {
      if (p >= end) throw new Malformed('DNS');
      const l = d[p];
      if (l === 0) { if (!jumped) next = p + 1; break; }
      if ((l & 0xc0) === 0xc0) {
        if (p + 1 >= end) throw new Malformed('DNS');
        if (!jumped) next = p + 2;
        jumped = true;
        p = base + (((l & 0x3f) << 8) | d[p + 1]);
        if (++hops > 32) throw new Malformed('DNS');
        continue;
      }
      if (p + 1 + l > end) throw new Malformed('DNS');
      name += (name ? '.' : '') + ascii(d, p + 1, p + 1 + l);
      p += 1 + l;
    }
    return { name: name || '<Root>', next };
  }

  function dns(c, o, end) {
    need(c, o, 12, 'DNS', end);
    const { d, dv, m } = c;
    const id = dv.getUint16(o), fl = dv.getUint16(o + 2);
    const qd = dv.getUint16(o + 4), an = dv.getUint16(o + 6), ns = dv.getUint16(o + 8), ar = dv.getUint16(o + 10);
    const qr = fl >> 15, op = (fl >> 11) & 15, rc = fl & 15;
    m.proto = (m.sp === 5353 || m.dp === 5353) ? 'MDNS' : 'DNS'; m.protos.push('dns');
    const opn = DNS_OP[op] || 'Opcode ' + op;
    const rcn = DNS_RC[rc] || 'Rcode ' + rc;
    const root = c.root.add('Domain Name System (' + (qr ? 'response' : 'query') + ')', '', o, end - o);
    root.add('Transaction ID', hex(id, 4), o, 2);
    const fn = root.add('Flags: ' + hex(fl, 4) + ' ' + opn + (qr ? ' response' : '') + ', ' + rcn, '', o + 2, 2);
    if (c.tree) {
      const B = (mask, txt) => fn.add(bits(fl, mask, 16) + ' = ' + txt, '', o + 2, 2, { bit: true });
      B(0x8000, 'Response: Message is a ' + (qr ? 'response' : 'query'));
      B(0x7800, 'Opcode: ' + opn + ' (' + op + ')');
      B(0x0400, 'Authoritative: Server is ' + ((fl >> 10) & 1 ? '' : 'not ') + 'an authority for domain');
      B(0x0200, 'Truncated: Message is ' + ((fl >> 9) & 1 ? '' : 'not ') + 'truncated');
      B(0x0100, 'Recursion desired: ' + ((fl >> 8) & 1 ? 'Do query recursively' : 'Do not query recursively'));
      B(0x0080, 'Recursion available: Server can ' + ((fl >> 7) & 1 ? '' : 'not ') + 'do recursive queries');
      B(0x0040, 'Z: reserved (' + ((fl >> 6) & 1) + ')');
      B(0x0020, 'Answer authenticated: ' + ((fl >> 5) & 1 ? 'Authenticated' : 'Not authenticated'));
      B(0x0010, 'Non-authenticated data: ' + ((fl >> 4) & 1 ? 'Acceptable' : 'Unacceptable'));
      B(0x000f, 'Reply code: ' + rcn + ' (' + rc + ')');
    }
    root.add('Questions', qd, o + 4, 2);
    root.add('Answer RRs', an, o + 6, 2);
    root.add('Authority RRs', ns, o + 8, 2);
    root.add('Additional RRs', ar, o + 10, 2);

    let p = o + 12, qinfo = '';
    if (qd) {
      const qn = root.add('Queries', '', p, 0);
      for (let i = 0; i < Math.min(qd, 64); i++) {
        const nm = dnsName(d, p, o, end);
        need(c, nm.next, 4, 'DNS', end);
        const t = dv.getUint16(nm.next), cl = dv.getUint16(nm.next + 2);
        const q = qn.add(nm.name + ': type ' + (DNS_T[t] || t) + ', class ' + (cl === 1 ? 'IN' : cl), '', p, nm.next + 4 - p);
        q.add('Name', nm.name, p, nm.next - p);
        q.add('Type', (DNS_T[t] || 'Unknown') + ' (' + t + ')', nm.next, 2);
        q.add('Class', (cl === 1 ? 'IN' : 'Class ' + cl) + ' (' + hex(cl, 4) + ')', nm.next + 2, 2);
        m.dnsNames.push(nm.name);
        if (!qinfo) qinfo = (DNS_T[t] || t) + ' ' + nm.name;
        p = nm.next + 4;
      }
      qn.end = p;
    }
    const answers = [];
    const sections = [['Answers', an], ['Authoritative nameservers', ns], ['Additional records', ar]];
    sections.forEach(([label, cnt], si) => {
      if (!cnt) return;
      const sn = root.add(label, '', p, 0);
      for (let i = 0; i < Math.min(cnt, 64); i++) {
        const r = parseRR(c, p, o, end, sn);
        if (si === 0) answers.push(r.summary);
        p = r.next;
      }
      sn.end = p;
    });
    m.info = opn + (qr ? ' response' : '') + ' ' + hex(id, 4) + (qr && rc ? ' ' + rcn : '') + (qinfo ? ' ' + qinfo : '') + (answers.length ? ' ' + answers.join(', ') : '');
    if (qr && rc) { m.error = true; m.errKind = 'DNS ' + rcn; }
  }

  function parseRR(c, p, base, end, sec) {
    const { d, dv } = c;
    const start = p;
    const nm = dnsName(d, p, base, end);
    p = nm.next;
    need(c, p, 10, 'DNS', end);
    const type = dv.getUint16(p), cls = dv.getUint16(p + 2), ttl = dv.getUint32(p + 4), rl = dv.getUint16(p + 8);
    p += 10;
    need(c, p, rl, 'DNS', end);
    let txt = '', kind = '';
    const tn = DNS_T[type] || String(type);
    const kids = [];
    if (type === 1 && rl === 4) { txt = ip4(d, p); kind = 'Address'; }
    else if (type === 28 && rl === 16) { txt = ip6(d, p); kind = 'AAAA Address'; }
    else if (type === 2 || type === 5 || type === 12) { txt = dnsName(d, p, base, end).name; kind = tn === 'CNAME' ? 'CNAME' : tn === 'NS' ? 'Name Server' : 'Domain Name'; }
    else if (type === 15 && rl >= 3) { const pr = dv.getUint16(p); txt = pr + ' ' + dnsName(d, p + 2, base, end).name; kind = 'Mail Exchange'; }
    else if (type === 16 && rl >= 1) { txt = ascii(d, p + 1, p + rl); kind = 'TXT'; }
    else if (type === 6) { txt = dnsName(d, p, base, end).name; kind = 'Primary name server'; }
    const rn = sec.add(nm.name + ': type ' + tn + ', class ' + (cls === 1 ? 'IN' : cls) + (txt ? ', ' + (kind === 'Address' ? 'addr ' : '') + txt : ''), '', start, p + rl - start);
    rn.add('Name', nm.name, start, nm.next - start);
    rn.add('Type', tn + ' (' + type + ')', nm.next, 2);
    rn.add('Class', (cls === 1 ? 'IN' : 'Class ' + cls) + ' (' + hex(cls, 4) + ')', nm.next + 2, 2);
    rn.add('Time to live', ttl + ' (' + ttl + ' seconds)', nm.next + 4, 4);
    rn.add('Data length', rl, nm.next + 8, 2);
    if (txt) rn.add(kind, txt, p, rl);
    return { next: p + rl, summary: tn + (txt ? ' ' + txt : '') };
  }

  /* ===========================================================================
     Flow analysis: relative TCP numbers + retransmission detection.
     Call process() on every packet in capture order after dissect(pkt, false).
     ========================================================================= */
  class FlowTracker {
    constructor() { this.dirs = new Map(); }
    process(pkt) {
      const m = pkt.m;
      if (!m.tcp || !m.ipSrc) return;
      const t = m.tcp;
      const k = m.ipSrc + ':' + m.sp + '>' + m.ipDst + ':' + m.dp;
      const rk = m.ipDst + ':' + m.dp + '>' + m.ipSrc + ':' + m.sp;
      let st = this.dirs.get(k);
      if (!st) { st = { isn: t.seq, next: t.seq }; this.dirs.set(k, st); }
      const peer = this.dirs.get(rk);
      pkt.rel = { seq: (t.seq - st.isn) >>> 0, ack: (t.flags & 16) && peer ? (t.ack - peer.isn) >>> 0 : t.ack };
      const adv = t.len + (t.flags & 2 ? 1 : 0) + (t.flags & 1 ? 1 : 0);
      if (adv > 0 && !(t.flags & 4)) {
        if (((t.seq + adv - st.next) | 0) <= 0) {
          m.retrans = true; m.error = true; m.errKind = 'Retransmission';
          pkt.analysis = { retrans: true };
        } else st.next = (t.seq + adv) >>> 0;
      }
      if (!m.appInfo) m.info = tcpInfoStr(m, pkt.rel);
      if (m.retrans) m.info = '[TCP Retransmission] ' + m.info;
    }
  }

  /* ===========================================================================
     Capture readers
     ========================================================================= */
  const LINKTYPES = { 0: 'BSD loopback', 1: 'Ethernet', 101: 'Raw IP', 113: 'Linux cooked', 228: 'Raw IPv4', 229: 'Raw IPv6' };

  function readCapture(buf) {
    if (buf.byteLength < 12) throw new Error('The file is too small to be a capture file.');
    const dv = new DataView(buf);
    const magic = dv.getUint32(0, false);
    if (magic === 0x0a0d0d0a) return readPcapng(buf, dv);
    let le, nano;
    switch (magic) {
      case 0xa1b2c3d4: le = false; nano = false; break;
      case 0xd4c3b2a1: le = true; nano = false; break;
      case 0xa1b23c4d: le = false; nano = true; break;
      case 0x4d3cb2a1: le = true; nano = true; break;
      default: throw new Error('Unrecognized file format. TabShark reads .pcap and .pcapng captures.');
    }
    if (buf.byteLength < 24) throw new Error('The pcap global header is incomplete.');
    const cap = {
      format: 'pcap', littleEndian: le, nano,
      versionMajor: dv.getUint16(4, le), versionMinor: dv.getUint16(6, le),
      thisZone: dv.getInt32(8, le), snaplen: dv.getUint32(16, le),
      linkType: dv.getUint32(20, le) & 0x0fffffff, packets: [], warnings: [], size: buf.byteLength
    };
    let p = 24, no = 0;
    while (p + 16 <= buf.byteLength) {
      const sec = dv.getUint32(p, le), frac = dv.getUint32(p + 4, le);
      let incl = dv.getUint32(p + 8, le);
      const orig = dv.getUint32(p + 12, le);
      if (incl > 0x1000000) { cap.warnings.push('Stopped at packet ' + (no + 1) + ': implausible captured length.'); break; }
      if (p + 16 + incl > buf.byteLength) {
        incl = buf.byteLength - p - 16;
        cap.warnings.push('The final packet is truncated in the file.');
      }
      cap.packets.push({
        no: ++no, sec, nsec: nano ? frac : frac * 1000, capLen: incl, origLen: orig,
        data: new Uint8Array(buf, p + 16, incl), link: cap.linkType, fileOffset: p
      });
      p += 16 + incl;
    }
    return cap;
  }

  function readPcapng(buf, dv) {
    const total = buf.byteLength;
    const cap = { format: 'pcapng', littleEndian: true, nano: false, packets: [], warnings: [], size: total, linkType: -1, snaplen: 0, versionMajor: 1, versionMinor: 0 };
    let p = 0, le = true, ifs = [], no = 0;
    while (p + 12 <= total) {
      let type = dv.getUint32(p, le);
      if (type === 0x0a0d0d0a) {
        le = dv.getUint32(p + 8, true) === 0x1a2b3c4d;
        if (!le && dv.getUint32(p + 8, false) !== 0x1a2b3c4d) { cap.warnings.push('Unknown byte-order magic in section header.'); le = true; }
        cap.littleEndian = le;
        cap.versionMajor = dv.getUint16(p + 12, le); cap.versionMinor = dv.getUint16(p + 14, le);
        ifs = [];
        type = 0x0a0d0d0a;
      }
      const blen = dv.getUint32(p + 4, le);
      if (blen < 12 || blen % 4 || p + blen > total) { cap.warnings.push('Stopped at a damaged block at byte ' + p + '.'); break; }
      const b = p + 8;
      if (type === 1) {
        const link = dv.getUint16(b, le), snap = dv.getUint32(b + 4, le);
        let ups = 1e6, q = b + 8;
        while (q + 4 <= p + blen - 4) {
          const code = dv.getUint16(q, le), ol = dv.getUint16(q + 2, le);
          if (code === 0) break;
          if (code === 9 && ol >= 1) { const v = dv.getUint8(q + 4); ups = (v & 0x80) ? Math.pow(2, v & 0x7f) : Math.pow(10, v); }
          q += 4 + ((ol + 3) & ~3);
        }
        ifs.push({ link, snap, ups });
        if (cap.linkType < 0) { cap.linkType = link; cap.snaplen = snap; }
      } else if (type === 6 && blen >= 32) {
        const id = dv.getUint32(b, le), hi = dv.getUint32(b + 4, le), lo = dv.getUint32(b + 8, le);
        let incl = dv.getUint32(b + 12, le);
        const orig = dv.getUint32(b + 16, le), itf = ifs[id] || { link: 1, ups: 1e6 };
        incl = Math.min(incl, blen - 32);
        const t = (BigInt(hi) << 32n) | BigInt(lo), ub = BigInt(Math.round(itf.ups));
        const sec = Number(t / ub), rem = Number(t % ub);
        cap.packets.push({
          no: ++no, sec, nsec: Math.round(rem * 1e9 / itf.ups), capLen: incl, origLen: orig,
          data: new Uint8Array(buf, b + 20, incl), link: itf.link, fileOffset: p
        });
      } else if (type === 3 && blen >= 16) {
        const orig = dv.getUint32(b, le), itf = ifs[0] || { link: 1 };
        const incl = Math.min(orig, blen - 16);
        cap.packets.push({ no: ++no, sec: 0, nsec: 0, capLen: incl, origLen: orig, data: new Uint8Array(buf, b + 4, incl), link: itf.link, fileOffset: p });
      }
      p += blen;
    }
    if (cap.linkType < 0) cap.linkType = 1;
    return cap;
  }

  /* ===========================================================================
     Sample capture generator - builds a real little-endian microsecond pcap
     in memory, with valid IPv4 / TCP / UDP checksums.
     ========================================================================= */
  function generateSample() {
    const frames = [];
    const be16 = (n) => [(n >> 8) & 255, n & 255];
    const be32 = (n) => [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255];
    const ipb = (s) => s.split('.').map(Number);
    const mb = (s) => s.split(':').map((x) => parseInt(x, 16));
    const str = (s) => Array.from(s, (ch) => ch.charCodeAt(0));
    const fin = (a) => (~csum(a, 0, a.length)) & 0xffff;

    const CL = { mac: '3c:22:fb:7a:10:5e', ip: '192.168.1.10' };
    const GW = { mac: 'a4:2b:b0:11:c3:90', ip: '192.168.1.1' };
    const WEB = '93.184.216.34', SEC = '142.250.74.46', PEER = '192.168.1.50';
    const ids = {};
    const nextId = (ip) => (ids[ip] = (ids[ip] || 0x2a00) + 1);

    const eth = (dm, sm, type, pl) => mb(dm).concat(mb(sm), be16(type), pl);
    function ipv4p(src, dst, proto, pl, ttl) {
      const h = [0x45, 0, ...be16(20 + pl.length), ...be16(nextId(src)), 0x40, 0, ttl || 64, proto, 0, 0, ...ipb(src), ...ipb(dst)];
      const ck = fin(h); h[10] = ck >> 8; h[11] = ck & 255;
      return h.concat(pl);
    }
    function l4sum(src, dst, proto, seg, at) {
      const ps = [...ipb(src), ...ipb(dst), 0, proto, ...be16(seg.length)];
      const ck = fin(ps.concat(seg));
      seg[at] = ck >> 8; seg[at + 1] = ck & 255;
      return seg;
    }
    function tcpSeg(src, dst, sp, dp, seq, ack, flags, win, pl, opts) {
      opts = opts || []; pl = pl || [];
      const seg = [...be16(sp), ...be16(dp), ...be32(seq), ...be32(ack), ((20 + opts.length) / 4) << 4, flags, ...be16(win), 0, 0, 0, 0, ...opts, ...pl];
      return l4sum(src, dst, 6, seg, 16);
    }
    function udpSeg(src, dst, sp, dp, pl) {
      const seg = [...be16(sp), ...be16(dp), ...be16(8 + pl.length), 0, 0, ...pl];
      return l4sum(src, dst, 17, seg, 6);
    }
    const out = (t, dm, sm, type, pl) => frames.push({ t, bytes: eth(dm, sm, type, pl) });
    const toWeb = (t, ip, seg) => out(t, GW.mac, CL.mac, 0x0800, ipv4p(CL.ip, ip, 6, seg));
    const fromWeb = (t, ip, seg) => out(t, CL.mac, GW.mac, 0x0800, ipv4p(ip, CL.ip, 6, seg, 57));

    const qname = (n) => n.split('.').flatMap((l) => [l.length, ...str(l)]).concat(0);
    const dnsQuery = (id, name) => [...be16(id), 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0, ...qname(name), 0, 1, 0, 1];

    /* ARP */
    out(0.0, 'ff:ff:ff:ff:ff:ff', CL.mac, 0x0806, [0, 1, 8, 0, 6, 4, 0, 1, ...mb(CL.mac), ...ipb(CL.ip), 0, 0, 0, 0, 0, 0, ...ipb(GW.ip)]);
    out(0.000812, CL.mac, GW.mac, 0x0806, [0, 1, 8, 0, 6, 4, 0, 2, ...mb(GW.mac), ...ipb(GW.ip), ...mb(CL.mac), ...ipb(CL.ip)]);

    /* DNS query + response (compressed name pointer) */
    const q1 = dnsQuery(0x1a2b, 'example.com');
    out(0.012104, GW.mac, CL.mac, 0x0800, ipv4p(CL.ip, GW.ip, 17, udpSeg(CL.ip, GW.ip, 53114, 53, q1)));
    const r1 = [...be16(0x1a2b), 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0, ...qname('example.com'), 0, 1, 0, 1, 0xc0, 0x0c, 0, 1, 0, 1, ...be32(3600), 0, 4, ...ipb(WEB)];
    out(0.036421, CL.mac, GW.mac, 0x0800, ipv4p(GW.ip, CL.ip, 17, udpSeg(GW.ip, CL.ip, 53, 53114, r1), 64));

    /* TCP 3-way handshake + HTTP GET + 200 OK + close */
    const synOpts = [2, 4, 0x05, 0xb4, 4, 2, 8, 10, ...be32(884200), ...be32(0), 1, 3, 3, 7];
    const sackOpts = [2, 4, 0x05, 0xb4, 4, 2, 8, 10, ...be32(77310), ...be32(884200), 1, 3, 3, 8];
    const tsOpts = (a, b) => [1, 1, 8, 10, ...be32(a), ...be32(b)];
    const cs = 0x3b9aca01, ss = 0x7c1e4a00, SP = 49722;
    toWeb(0.037102, WEB, tcpSeg(CL.ip, WEB, SP, 80, cs, 0, 0x02, 64240, [], synOpts));
    fromWeb(0.058734, WEB, tcpSeg(WEB, CL.ip, 80, SP, ss, cs + 1, 0x12, 65535, [], sackOpts));
    toWeb(0.058801, WEB, tcpSeg(CL.ip, WEB, SP, 80, cs + 1, ss + 1, 0x10, 502, [], tsOpts(884231, 77310)));
    const get = str('GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: TabShark-Sample/1.0\r\nAccept: text/html\r\nConnection: close\r\n\r\n');
    toWeb(0.059377, WEB, tcpSeg(CL.ip, WEB, SP, 80, cs + 1, ss + 1, 0x18, 502, get, tsOpts(884232, 77310)));
    fromWeb(0.081204, WEB, tcpSeg(WEB, CL.ip, 80, SP, ss + 1, cs + 1 + get.length, 0x10, 508, [], tsOpts(77340, 884232)));
    const body = str('<!doctype html><html><head><title>Example Domain</title></head><body><h1>Example Domain</h1><p>Captured with TabShark.</p></body></html>');
    const resp = str('HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=UTF-8\r\nContent-Length: ' + body.length + '\r\nConnection: close\r\n\r\n').concat(body);
    fromWeb(0.082311, WEB, tcpSeg(WEB, CL.ip, 80, SP, ss + 1, cs + 1 + get.length, 0x18, 508, resp, tsOpts(77341, 884232)));
    toWeb(0.082544, WEB, tcpSeg(CL.ip, WEB, SP, 80, cs + 1 + get.length, ss + 1 + resp.length, 0x10, 502, [], tsOpts(884260, 77341)));
    toWeb(0.090391, WEB, tcpSeg(CL.ip, WEB, SP, 80, cs + 1 + get.length, ss + 1 + resp.length, 0x11, 502, [], tsOpts(884268, 77341)));
    fromWeb(0.112187, WEB, tcpSeg(WEB, CL.ip, 80, SP, ss + 1 + resp.length, cs + 2 + get.length, 0x11, 508, [], tsOpts(77390, 884268)));
    toWeb(0.112243, WEB, tcpSeg(CL.ip, WEB, SP, 80, cs + 2 + get.length, ss + 2 + resp.length, 0x10, 502, [], tsOpts(884290, 77390)));

    /* UDP datagram */
    const probe = str('TabShark UDP probe #1');
    out(0.204511, 'b8:27:eb:44:19:2c', CL.mac, 0x0800, ipv4p(CL.ip, PEER, 17, udpSeg(CL.ip, PEER, 51515, 5001, probe)));

    /* ICMP echo */
    const echo = (type, id, sq) => { const h = [type, 0, 0, 0, ...be16(id), ...be16(sq), ...str('abcdefghijklmnopqrstuvwabcdefghi')]; const ck = fin(h); h[2] = ck >> 8; h[3] = ck & 255; return h; };
    out(0.402018, GW.mac, CL.mac, 0x0800, ipv4p(CL.ip, GW.ip, 1, echo(8, 0x0001, 1)));
    out(0.402967, CL.mac, GW.mac, 0x0800, ipv4p(GW.ip, CL.ip, 1, echo(0, 0x0001, 1), 64));

    /* DNS error: NXDOMAIN */
    out(0.500114, GW.mac, CL.mac, 0x0800, ipv4p(CL.ip, GW.ip, 17, udpSeg(CL.ip, GW.ip, 53871, 53, dnsQuery(0x5c3d, 'nonexistent.invalid'))));
    const r2 = [...be16(0x5c3d), 0x81, 0x83, 0, 1, 0, 0, 0, 0, 0, 0, ...qname('nonexistent.invalid'), 0, 1, 0, 1];
    out(0.515602, CL.mac, GW.mac, 0x0800, ipv4p(GW.ip, CL.ip, 17, udpSeg(GW.ip, CL.ip, 53, 53871, r2), 64));

    /* TCP RST: connection refused */
    toWeb(0.600231, WEB, tcpSeg(CL.ip, WEB, 49730, 8081, 0x1d4c0a10, 0, 0x02, 64240, [], synOpts));
    fromWeb(0.621874, WEB, tcpSeg(WEB, CL.ip, 8081, 49730, 0, 0x1d4c0a11, 0x14, 0, [], []));

    /* TLS handshake with a retransmitted ClientHello */
    const ext = (t, data) => [...be16(t), ...be16(data.length), ...data];
    const host = str('www.example.org');
    const rnd = (seed) => Array.from({ length: 32 }, (_, i) => (seed + i * 7) & 255);
    const sni = ext(0, [...be16(host.length + 3), 0, ...be16(host.length), ...host]);
    const alpn = ext(16, [...be16(12), 2, ...str('h2'), 8, ...str('http/1.1')]);
    const exts = sni.concat(ext(10, [0, 4, 0, 0x1d, 0, 0x17]), ext(13, [0, 4, 4, 3, 8, 4]), alpn, ext(43, [2, 3, 4]), ext(45, [1, 1]));
    const chBody = [3, 3, ...rnd(11), 32, ...rnd(97), 0, 8, 0x13, 1, 0x13, 2, 0x13, 3, 0xc0, 0x2b, 1, 0, ...be16(exts.length), ...exts];
    const ch = [22, 3, 1, ...be16(chBody.length + 4), 1, 0, ...be16(chBody.length), ...chBody];
    const shBody = [3, 3, ...rnd(201), 32, ...rnd(97), 0x13, 1, 0, 0, 46, 0, 43, 0, 2, 3, 4, 0, 51, 0, 36, 0, 0x1d, 0, 32, ...rnd(5)];
    const sh = [22, 3, 3, ...be16(shBody.length + 4), 2, 0, ...be16(shBody.length), ...shBody];
    const appData = [23, 3, 3, 0, 40, ...rnd(33), ...rnd(9).slice(0, 8)];
    const c2 = 0x4a3b2c10, s2 = 0x91a0b000;
    toWeb(0.800412, SEC, tcpSeg(CL.ip, SEC, 49741, 443, c2, 0, 0x02, 64240, [], synOpts));
    fromWeb(0.811893, SEC, tcpSeg(SEC, CL.ip, 443, 49741, s2, c2 + 1, 0x12, 65535, [], sackOpts));
    toWeb(0.811940, SEC, tcpSeg(CL.ip, SEC, 49741, 443, c2 + 1, s2 + 1, 0x10, 502, [], tsOpts(884800, 77400)));
    toWeb(0.812377, SEC, tcpSeg(CL.ip, SEC, 49741, 443, c2 + 1, s2 + 1, 0x18, 502, ch, tsOpts(884801, 77400)));
    toWeb(1.021904, SEC, tcpSeg(CL.ip, SEC, 49741, 443, c2 + 1, s2 + 1, 0x18, 502, ch, tsOpts(885010, 77400)));
    fromWeb(1.034120, SEC, tcpSeg(SEC, CL.ip, 443, 49741, s2 + 1, c2 + 1 + ch.length, 0x18, 508, sh.concat([20, 3, 3, 0, 1, 1], appData), tsOpts(77620, 885010)));

    /* Serialise as classic little-endian microsecond pcap */
    const base = Math.floor(Date.UTC(2026, 10, 19, 9, 30, 0) / 1000);
    let size = 24;
    frames.forEach((f) => (size += 16 + f.bytes.length));
    const buf = new ArrayBuffer(size), dv = new DataView(buf), u8 = new Uint8Array(buf);
    dv.setUint32(0, 0xa1b2c3d4, true); dv.setUint16(4, 2, true); dv.setUint16(6, 4, true);
    dv.setInt32(8, 0, true); dv.setUint32(12, 0, true); dv.setUint32(16, 65535, true); dv.setUint32(20, 1, true);
    let p = 24;
    frames.forEach((f) => {
      const whole = Math.floor(f.t), us = Math.round((f.t - whole) * 1e6);
      dv.setUint32(p, base + whole, true); dv.setUint32(p + 4, us, true);
      dv.setUint32(p + 8, f.bytes.length, true); dv.setUint32(p + 12, f.bytes.length, true);
      u8.set(f.bytes, p + 16);
      p += 16 + f.bytes.length;
    });
    return buf;
  }

  global.TabShark = { readCapture, dissect, FlowTracker, generateSample, LINKTYPES, hex, ascii };
})(typeof window !== 'undefined' ? window : globalThis);

/* =============================================================================
   TabShark - app.js
   UI layer: splash, file loading, display filter, virtualized packet list,
   protocol tree, hex/ASCII viewer with two-way byte cross-highlighting.
   ============================================================================= */
(function () {
  'use strict';

  const TS = window.TabShark;
  const $ = (id) => document.getElementById(id);
  const ROW = 26, HEAD = 28;

  /* ------------------------------ icons ---------------------------------- */
  const ICONS = {
    upload: '<path d="M12 15V4"/><path d="m7 9 5-5 5 5"/><path d="M4 15v3a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-3"/>',
    zap: '<path d="M13 2 4 14h7l-1 8 9-12h-7z"/>',
    trash: '<path d="M4 7h16M10 11v6M14 11v6M6 7l1 13h10l1-13M9 7V4h6v3"/>',
    help: '<circle cx="12" cy="12" r="9"/><path d="M9.5 9.5a2.5 2.5 0 1 1 3.5 2.3c-.7.3-1 .9-1 1.7"/><path d="M12 17h.01"/>',
    filter: '<path d="M3 5h18l-7 8v6l-4-2v-4z"/>',
    search: '<circle cx="11" cy="11" r="7"/><path d="m20 20-3.5-3.5"/>',
    x: '<path d="M6 6l12 12M18 6 6 18"/>',
    up: '<path d="m6 15 6-6 6 6"/>',
    down: '<path d="m6 9 6 6 6-6"/>',
    left: '<path d="m15 6-6 6 6 6"/>',
    right: '<path d="m9 6 6 6-6 6"/>',
    radar: '<circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="5"/><path d="M12 12 18 6"/><circle cx="12" cy="12" r="1"/>',
    shield: '<path d="M12 3 5 6v6c0 4.5 3 7.5 7 9 4-1.5 7-4.5 7-9V6z"/><path d="m9 12 2 2 4-4"/>',
    layers: '<path d="m12 3 9 5-9 5-9-5z"/><path d="m3 13 9 5 9-5"/>',
    code: '<path d="m8 8-5 4 5 4M16 8l5 4-5 4M14 5l-4 14"/>',
    list: '<path d="M8 6h13M8 12h13M8 18h13M3 6h.01M3 12h.01M3 18h.01"/>',
    keyboard: '<rect x="3" y="6" width="18" height="12" rx="2"/><path d="M7 10h.01M11 10h.01M15 10h.01M8 14h8"/>',
    globe: '<circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3c3 3 3 15 0 18M12 3c-3 3-3 15 0 18"/>',
    lock: '<rect x="5" y="11" width="14" height="9" rx="2"/><path d="M8 11V8a4 4 0 0 1 8 0v3"/>',
    tcp: '<path d="M4 8h14M14 4l4 4-4 4M20 16H6M10 12l-4 4 4 4"/>',
    send: '<path d="m21 3-9 18-2-8-8-2z"/><path d="M21 3 10 13"/>',
    book: '<path d="M3 5h7a2 2 0 0 1 2 2v13a2 2 0 0 0-2-2H3zM21 5h-7a2 2 0 0 0-2 2v13a2 2 0 0 1 2-2h7z"/>',
    activity: '<path d="M3 12h4l3-8 4 16 3-8h4"/>',
    network: '<rect x="9" y="3" width="6" height="5"/><rect x="3" y="16" width="6" height="5"/><rect x="15" y="16" width="6" height="5"/><path d="M12 8v4M6 16v-4h12v4"/>',
    box: '<path d="m12 3 8 4.5v9L12 21l-8-4.5v-9z"/><path d="m4 7.5 8 4.5 8-4.5M12 12v9"/>',
    alert: '<path d="M12 4 3 20h18z"/><path d="M12 10v4M12 17h.01"/>'
  };
  const icon = (n, cls) => '<svg class="ic' + (cls ? ' ' + cls : '') + '" viewBox="0 0 24 24" aria-hidden="true">' + (ICONS[n] || '') + '</svg>';
  document.querySelectorAll('svg.ic[data-ic]').forEach((s) => {
    s.setAttribute('viewBox', '0 0 24 24');
    s.setAttribute('aria-hidden', 'true');
    s.innerHTML = ICONS[s.dataset.ic] || '';
  });

  const esc = (s) => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  const hx2 = (n) => n.toString(16).padStart(2, '0');
  const fmtBytes = (n) => (n < 1024 ? n + ' B' : n < 1048576 ? (n / 1024).toFixed(1) + ' KB' : (n / 1048576).toFixed(1) + ' MB');

  /* ------------------------------ splash --------------------------------- */
  (function splash() {
    const el = $('splash'), fill = $('splash-fill'), stream = $('splash-hex');
    const reduce = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    const total = reduce ? 500 : 2600;
    let seed = 0x5eed, t0 = performance.now(), done = false;
    const rnd = () => (seed = (seed * 1664525 + 1013904223) >>> 0);
    const timer = setInterval(() => {
      const p = Math.min(1, (performance.now() - t0) / total);
      fill.style.width = (p * 100).toFixed(1) + '%';
      let s = '';
      for (let i = 0; i < 12; i++) s += hx2(rnd() >>> 24) + ' ';
      stream.textContent = s.trim();
      if (p >= 1) finish();
    }, 60);
    function finish() {
      if (done) return;
      done = true;
      clearInterval(timer);
      fill.style.width = '100%';
      $('app').hidden = false;
      el.classList.add('out');
      setTimeout(() => el.remove(), 800);
    }
    el.addEventListener('click', finish);
  })();

  /* ------------------------------ state ---------------------------------- */
  const state = {
    cap: null, name: '', packets: [], view: [], sel: -1, selNode: null, tree: null,
    filterText: '', pred: null, matches: [], matchSet: new Set(), matchPos: -1, animate: false,
    hexEls: [], ascEls: [], nodeEls: new Map(), range: { sel: null, hv: null }
  };

  const plist = $('plist'), vrows = $('vrows'), treeEl = $('tree'), hexEl = $('hex');

  /* ---------------------------- protocol style --------------------------- */
  function protoStyle(m) {
    const p = m.proto || '';
    if (p === 'TCP') return { cls: 'tcp', icon: 'tcp' };
    if (p === 'UDP') return { cls: 'udp', icon: 'send' };
    if (p === 'HTTP') return { cls: 'web', icon: 'globe' };
    if (/^(TLS|SSL)/.test(p)) return { cls: 'web', icon: 'lock' };
    if (p === 'DNS' || p === 'MDNS') return { cls: 'dns', icon: 'book' };
    if (p === 'ICMP' || p === 'ICMPv6') return { cls: 'icmp', icon: 'activity' };
    if (p === 'ARP') return { cls: 'icmp', icon: 'network' };
    return { cls: 'other', icon: 'box' };
  }

  /* ------------------------------ toasts --------------------------------- */
  function toast(msg, err) {
    const t = document.createElement('div');
    t.className = 'toast' + (err ? ' err' : '');
    t.textContent = msg;
    $('toasts').appendChild(t);
    setTimeout(() => { t.classList.add('out'); setTimeout(() => t.remove(), 300); }, err ? 6000 : 3500);
  }

  /* ----------------------------- file loading ---------------------------- */
  const nextFrame = () => new Promise((r) => requestAnimationFrame(() => r()));

  async function loadFile(file) {
    if (!file) return;
    try {
      const buf = await file.arrayBuffer();
      await loadBuffer(buf, file.name);
    } catch (e) {
      toast(e && e.message ? e.message : 'Could not read this file.', true);
      progress(null);
    }
  }

  function progress(p) {
    const bar = $('progress');
    if (p === null) { bar.hidden = true; $('progress-fill').style.width = '0'; return; }
    bar.hidden = false;
    $('progress-fill').style.width = (p * 100).toFixed(1) + '%';
  }

  async function loadBuffer(buf, name) {
    progress(0.02);
    await nextFrame();
    let cap;
    try { cap = TS.readCapture(buf); }
    catch (e) { progress(null); toast(e.message, true); return; }
    if (!cap.packets.length) { progress(null); toast('This capture contains no packets.', true); return; }

    const ft = new TS.FlowTracker(), pk = cap.packets, first = pk[0];
    for (let i = 0; i < pk.length; i++) {
      const p = pk[i];
      p.rel_t = (p.sec - first.sec) + (p.nsec - first.nsec) / 1e9;
      p.m = TS.dissect(p, false).m;
      ft.process(p);
      if (i % 1500 === 1499) { progress(0.05 + 0.9 * (i / pk.length)); await nextFrame(); }
    }
    state.cap = cap; state.name = name; state.packets = pk; state.sel = -1; state.selNode = null;
    state.matches = []; state.matchSet = new Set(); state.matchPos = -1;
    $('find').value = ''; $('find-count').textContent = '';
    $('empty').hidden = true; $('workspace').hidden = false; $('filterbar').hidden = false;
    $('fileinfo').hidden = false; $('btn-clear').hidden = false;
    $('fi-name').textContent = name;
    $('fi-format').textContent = (cap.format === 'pcapng' ? 'pcapng' : 'pcap ' + (cap.nano ? 'ns' : 'us') + ', ' + (cap.littleEndian ? 'little' : 'big') + '-endian') + ', ' + fmtBytes(cap.size);
    $('fi-link').textContent = TS.LINKTYPES[cap.linkType] || 'Link type ' + cap.linkType;
    state.animate = true;
    applyFilter($('filter').value, true);
    renderChips();
    if (state.view.length) selectView(0, false);
    progress(1);
    setTimeout(() => progress(null), 250);
    cap.warnings.forEach((w) => toast(w, true));
    plist.focus({ preventScroll: true });
  }

  function closeCapture() {
    state.cap = null; state.packets = []; state.view = []; state.sel = -1; state.selNode = null;
    $('workspace').hidden = true; $('filterbar').hidden = true; $('empty').hidden = false;
    $('fileinfo').hidden = true; $('btn-clear').hidden = true;
    $('filter').value = ''; $('find').value = '';
    treeEl.innerHTML = '<div class="pane-empty">Select a packet to inspect its layers.</div>';
    hexEl.innerHTML = '<div class="pane-empty">Bytes appear here.</div>';
    $('st-main').textContent = 'Ready. Open a capture to begin.';
    $('st-field').textContent = '';
  }

  const loadSample = () => loadBuffer(TS.generateSample(), 'TabShark sample capture.pcap');

  /* ============================ display filter ============================ */
  const portOf = (p, which) => (p.m.l4 === 'tcp' || p.m.l4 === 'udp') ? (which === 's' ? p.m.sp : which === 'd' ? p.m.dp : [p.m.sp, p.m.dp]) : undefined;
  const only = (p, proto, v) => (p.m.l4 === proto ? v : undefined);
  const flag = (bit) => (p) => (p.m.tcp ? !!(p.m.flags & bit) : undefined);
  const v4 = (p) => p.m.ipv === 4, v6 = (p) => p.m.ipv === 6;
  const FIELDS = {
    'frame.len': (p) => p.origLen, 'frame.cap_len': (p) => p.capLen, 'frame.number': (p) => p.no,
    'frame.time_relative': (p) => p.rel_t,
    'eth.src': (p) => p.m.ethSrc || undefined, 'eth.dst': (p) => p.m.ethDst || undefined,
    'eth.addr': (p) => (p.m.ethSrc ? [p.m.ethSrc, p.m.ethDst] : undefined),
    'ip.src': (p) => (v4(p) ? p.m.ipSrc : undefined), 'ip.dst': (p) => (v4(p) ? p.m.ipDst : undefined),
    'ip.addr': (p) => (v4(p) ? [p.m.ipSrc, p.m.ipDst] : undefined), 'ip.ttl': (p) => (v4(p) ? p.m.ttl : undefined),
    'ipv6.src': (p) => (v6(p) ? p.m.ipSrc : undefined), 'ipv6.dst': (p) => (v6(p) ? p.m.ipDst : undefined),
    'ipv6.addr': (p) => (v6(p) ? [p.m.ipSrc, p.m.ipDst] : undefined),
    'tcp.srcport': (p) => only(p, 'tcp', p.m.sp), 'tcp.dstport': (p) => only(p, 'tcp', p.m.dp),
    'tcp.port': (p) => only(p, 'tcp', [p.m.sp, p.m.dp]),
    'udp.srcport': (p) => only(p, 'udp', p.m.sp), 'udp.dstport': (p) => only(p, 'udp', p.m.dp),
    'udp.port': (p) => only(p, 'udp', [p.m.sp, p.m.dp]),
    'port': (p) => portOf(p, 'b'), 'srcport': (p) => portOf(p, 's'), 'dstport': (p) => portOf(p, 'd'),
    'tcp.len': (p) => (p.m.tcp ? p.m.tcp.len : undefined), 'tcp.seq': (p) => (p.rel ? p.rel.seq : undefined),
    'tcp.ack': (p) => (p.rel && (p.m.flags & 16) ? p.rel.ack : undefined), 'tcp.window_size': (p) => (p.m.tcp ? p.m.tcp.win : undefined),
    'tcp.flags.fin': flag(1), 'tcp.flags.syn': flag(2), 'tcp.flags.rst': flag(4), 'tcp.flags.reset': flag(4),
    'tcp.flags.psh': flag(8), 'tcp.flags.push': flag(8), 'tcp.flags.ack': flag(16), 'tcp.flags.urg': flag(32),
    'tcp.analysis.retransmission': (p) => (p.m.tcp ? !!p.m.retrans : undefined),
    'dns.qry.name': (p) => (p.m.dnsNames.length ? p.m.dnsNames : undefined),
    'http.request.method': (p) => p.m.method || undefined, 'http.host': (p) => p.m.host || undefined,
    'http.response.code': (p) => p.m.status || undefined,
    'tls.handshake.extensions_server_name': (p) => p.m.sni || undefined
  };
  const PROTO_ALIAS = { ipv4: 'ip', mdns: 'dns', https: 'tls' };
  const PROTOS = new Set(['eth', 'ip', 'ipv6', 'arp', 'tcp', 'udp', 'icmp', 'icmpv6', 'dns', 'http', 'tls', 'ssl', 'frame', 'ipv4', 'mdns', 'https']);

  const asArr = (v) => (Array.isArray(v) ? v : [v]);
  function eq(a, b) {
    if (typeof a === 'boolean') return a === (b === '1' || b.toLowerCase() === 'true');
    if (typeof a === 'number') return a === Number(b);
    return String(a).toLowerCase() === b.toLowerCase();
  }
  function relOp(a, op, b) {
    const x = Number(a), y = Number(b);
    if (isNaN(x) || isNaN(y)) return false;
    return op === '>' ? x > y : op === '<' ? x < y : op === '>=' ? x >= y : x <= y;
  }
  function haystack(p) {
    if (!p._h) p._h = (p.no + ' ' + p.m.src + ' ' + p.m.dst + ' ' + p.m.proto + ' ' + p.m.info + ' ' + p.m.dnsNames.join(' ') + ' ' + p.m.host + ' ' + p.m.sni).toLowerCase();
    return p._h;
  }

  function compileFilter(src) {
    const text = src.trim();
    if (!text) return null;
    const toks = [], re = /\s*(&&|\|\||==|!=|>=|<=|[()!<>]|"[^"]*"|[^\s()!<>=&|"]+)/y;
    while (re.lastIndex < text.length) {
      const at = re.lastIndex, m = re.exec(text);
      if (!m) throw new Error('Unexpected character near "' + text.slice(at, at + 8).trim() + '"');
      toks.push(m[1]);
    }
    let pos = 0;
    const peek = () => toks[pos], next = () => toks[pos++];
    const low = (t) => (t === undefined ? '' : t.toLowerCase());
    const OPS = ['==', '!=', '>', '<', '>=', '<=', 'contains'];
    const unq = (t) => (t[0] === '"' ? t.slice(1, -1) : t);

    function parseOr() {
      let l = parseAnd();
      while (peek() === '||' || low(peek()) === 'or') { next(); l = ((a, b) => (p) => a(p) || b(p))(l, parseAnd()); }
      return l;
    }
    function parseAnd() {
      let l = parseNot();
      while (peek() === '&&' || low(peek()) === 'and') { next(); l = ((a, b) => (p) => a(p) && b(p))(l, parseNot()); }
      return l;
    }
    function parseNot() {
      if (peek() === '!' || low(peek()) === 'not') { next(); const f = parseNot(); return (p) => !f(p); }
      return parsePrimary();
    }
    function parsePrimary() {
      const w = next();
      if (w === undefined) throw new Error('The filter ends unexpectedly');
      if (w === '(') {
        const f = parseOr();
        if (next() !== ')') throw new Error('Missing closing parenthesis');
        return f;
      }
      if (['&&', '||', ')', '==', '!=', '>', '<', '>=', '<='].includes(w)) throw new Error('Unexpected "' + w + '"');
      if (OPS.includes(low(peek()))) {
        const field = FIELDS[low(w)];
        if (!field) throw new Error('Unknown field "' + w + '"');
        const op = low(next());
        const raw = next();
        if (raw === undefined) throw new Error('Missing value after "' + op + '"');
        const val = unq(raw);
        return (p) => {
          const v = field(p);
          if (op === '!=') return v === undefined ? true : !asArr(v).some((x) => eq(x, val));
          if (v === undefined) return false;
          if (op === '==') return asArr(v).some((x) => eq(x, val));
          if (op === 'contains') return asArr(v).some((x) => String(x).toLowerCase().includes(val.toLowerCase()));
          return asArr(v).some((x) => relOp(x, op, val));
        };
      }
      const lw = low(w);
      if (lw === 'error' || lw === 'errors') return (p) => p.m.error;
      if (lw === 'retransmission') return (p) => p.m.retrans;
      if (PROTOS.has(lw)) { const k = PROTO_ALIAS[lw] || lw; return (p) => p.m.protos.includes(k); }
      if (FIELDS[lw]) return (p) => { const v = FIELDS[lw](p); return v !== undefined && v !== false && v !== 0; };
      const needle = unq(w).toLowerCase();
      return (p) => haystack(p).includes(needle);
    }
    const f = parseOr();
    if (pos < toks.length) throw new Error('Unexpected "' + toks[pos] + '"');
    return f;
  }

  let filterTimer = 0;
  function applyFilter(text, quiet) {
    const field = $('filter-field'), msg = $('filter-msg');
    let pred = null;
    try { pred = compileFilter(text); }
    catch (e) {
      field.classList.add('bad'); field.classList.remove('ok');
      msg.textContent = e.message; msg.classList.add('show');
      return;
    }
    msg.classList.remove('show');
    field.classList.remove('bad');
    field.classList.toggle('ok', !!pred);
    $('filter-clear').hidden = !text;
    state.filterText = text.trim();
    state.pred = pred;
    const v = [];
    const pk = state.packets;
    for (let i = 0; i < pk.length; i++) if (!pred || pred(pk[i])) v.push(i);
    state.view = v;
    vrows.style.height = v.length * ROW + 'px';
    $('list-empty').hidden = v.length > 0;
    $('list-empty').style.marginTop = '0';
    $('list-meta').textContent = v.length.toLocaleString() + ' of ' + pk.length.toLocaleString() + ' packets';
    if (!quiet) plist.scrollTop = 0;
    renderRows();
    renderChips();
    runFind(false);
    updateStatus();
  }

  const CHIPS = [
    ['TCP', 'tcp', '--c-tcp'], ['UDP', 'udp', '--c-udp'], ['DNS', 'dns', '--c-dns'], ['HTTP', 'http', '--c-web'],
    ['TLS', 'tls', '--c-web'], ['ICMP', 'icmp', '--c-icmp'], ['ARP', 'arp', '--c-icmp'], ['Errors', 'error', '--c-err'],
    ['SYN', 'tcp.flags.syn && !tcp.flags.ack', '--c-tcp']
  ];
  function renderChips() {
    const box = $('chips');
    const cur = state.filterText;
    const preset = CHIPS.some((c) => c[1] === cur);
    box.innerHTML = CHIPS.map((c) => '<button type="button" class="chip' + (c[1] === cur ? ' on' : '') + '" style="--c:var(' + c[2] + ')" data-f="' + esc(c[1]) + '"><i></i>' + c[0] + '</button>').join('') +
      (cur && !preset ? '<button type="button" class="chip active-filter" data-clear="1" title="Remove this filter">' + esc(cur.length > 48 ? cur.slice(0, 47) + '...' : cur) + icon('x') + '</button>' : '');
  }
  $('chips').addEventListener('click', (e) => {
    const b = e.target.closest('.chip');
    if (!b) return;
    const f = b.dataset.clear ? '' : b.dataset.f === state.filterText ? '' : b.dataset.f;
    setFilter(f);
  });
  function setFilter(f) { $('filter').value = f; applyFilter(f); }

  $('filter').addEventListener('input', (e) => {
    clearTimeout(filterTimer);
    $('filter-clear').hidden = !e.target.value;
    filterTimer = setTimeout(() => applyFilter(e.target.value), 140);
  });
  $('filter').addEventListener('keydown', (e) => {
    if (e.key === 'Enter') { clearTimeout(filterTimer); applyFilter(e.target.value); plist.focus(); }
    if (e.key === 'Escape') { setFilter(''); e.target.blur(); }
  });
  $('filter-clear').addEventListener('click', () => { setFilter(''); $('filter').focus(); });

  /* ============================== packet list ============================= */
  let rafPending = false;
  function renderRows() {
    rafPending = false;
    const n = state.view.length;
    if (!n) { vrows.innerHTML = ''; return; }
    const top = plist.scrollTop, h = plist.clientHeight;
    const first = Math.max(0, Math.floor(top / ROW) - 4);
    const last = Math.min(n - 1, Math.ceil((top + h - HEAD) / ROW) + 4);
    const anim = state.animate;
    let html = '';
    for (let vi = first; vi <= last; vi++) {
      const idx = state.view[vi], p = state.packets[idx], m = p.m, st = protoStyle(m);
      const cls = 'row p-' + (m.error ? 'err' : st.cls) + (idx === state.sel ? ' sel' : '') + (state.matchSet.has(idx) ? ' match' : '') + (anim ? ' enter' : '');
      const d = anim ? ' --d:' + Math.min(420, (vi - first) * 16) + 'ms;' : '';
      html += '<div class="' + cls + '" role="row" data-v="' + vi + '" style="top:' + vi * ROW + 'px;' + d + '">' +
        '<div class="c-no">' + p.no + '</div><div class="c-time">' + p.rel_t.toFixed(6) + '</div>' +
        '<div class="c-src" title="' + esc(m.src) + '">' + esc(m.src) + '</div><div class="c-dst" title="' + esc(m.dst) + '">' + esc(m.dst) + '</div>' +
        '<div><span class="badge b-' + st.cls + '">' + icon(st.icon) + esc(m.proto) + '</span></div>' +
        '<div class="c-len">' + p.origLen + '</div>' +
        '<div class="c-info" title="' + esc(m.info) + '">' + (m.error ? icon('alert', 'eic') : '') + esc(m.info) + '</div></div>';
    }
    vrows.innerHTML = html;
    if (anim) { state.animate = false; }
  }
  const scheduleRows = () => { if (!rafPending) { rafPending = true; requestAnimationFrame(renderRows); } };
  plist.addEventListener('scroll', scheduleRows, { passive: true });
  new ResizeObserver(scheduleRows).observe(plist);

  vrows.addEventListener('click', (e) => {
    const r = e.target.closest('.row');
    if (r) selectView(+r.dataset.v, false);
  });

  function ensureVisible(vi) {
    const h = plist.clientHeight;
    if (vi * ROW < plist.scrollTop) plist.scrollTop = vi * ROW;
    else if (HEAD + (vi + 1) * ROW > plist.scrollTop + h) plist.scrollTop = HEAD + (vi + 1) * ROW - h;
  }

  function selectView(vi, scroll) {
    if (vi < 0 || vi >= state.view.length) return;
    const idx = state.view[vi];
    state.sel = idx;
    if (scroll !== false) ensureVisible(vi);
    renderRows();
    showPacket(state.packets[idx]);
    updateStatus();
  }
  const selectedViewIndex = () => state.view.indexOf(state.sel);

  plist.addEventListener('keydown', (e) => {
    const cur = selectedViewIndex(), n = state.view.length;
    const page = Math.max(1, Math.floor(plist.clientHeight / ROW) - 2);
    let t = null;
    if (e.key === 'ArrowDown') t = cur + 1;
    else if (e.key === 'ArrowUp') t = cur - 1;
    else if (e.key === 'PageDown') t = cur + page;
    else if (e.key === 'PageUp') t = cur - page;
    else if (e.key === 'Home') t = 0;
    else if (e.key === 'End') t = n - 1;
    if (t === null) return;
    e.preventDefault();
    selectView(Math.max(0, Math.min(n - 1, t)));
  });

  function updateStatus() {
    if (!state.cap) return;
    const p = state.sel >= 0 ? state.packets[state.sel] : null;
    $('st-main').textContent = 'Packets: ' + state.packets.length.toLocaleString() + '   Displayed: ' + state.view.length.toLocaleString() +
      (p ? '   Selected: frame ' + p.no + ', ' + p.origLen + ' bytes' : '');
  }

  /* ============================ protocol tree ============================= */
  function showPacket(pkt) {
    const r = TS.dissect(pkt, true);
    state.tree = r.root;
    state.selNode = null;
    state.nodeEls = new Map();
    treeEl.innerHTML = '';
    r.root.children.forEach((n, i) => treeEl.appendChild(buildNode(n, 0, i === 0)));
    buildHex(pkt.data);
    $('hex-meta').textContent = pkt.capLen + ' bytes';
    $('st-field').textContent = '';
  }

  function buildNode(n, depth, collapsed) {
    const wrap = document.createElement('div');
    wrap.className = 'tnode' + (depth === 0 ? ' layer' : '') + (n.bit ? ' bit' : '') + (depth === 0 && !collapsed ? ' open' : '');
    const row = document.createElement('div');
    row.className = 'trow' + (n.err ? ' err' : '');
    row.style.paddingLeft = depth * 16 + 4 + 'px';
    row.setAttribute('role', 'treeitem');
    const has = n.children.length > 0;
    row.innerHTML = '<span class="tw' + (has ? ' has' : '') + '">' + (has ? icon('right') : '') + '</span><span class="tl">' + esc(n.label) + '</span>' + (n.value ? '<span class="tv">' + esc(n.value) + '</span>' : '');
    wrap.appendChild(row);
    row._n = n;
    state.nodeEls.set(n, { wrap, row });
    if (has) {
      const kids = document.createElement('div'), inner = document.createElement('div');
      kids.className = 'tkids';
      n.children.forEach((c) => inner.appendChild(buildNode(c, depth + 1, true)));
      kids.appendChild(inner);
      wrap.appendChild(kids);
    }
    return wrap;
  }

  treeEl.addEventListener('click', (e) => {
    const row = e.target.closest('.trow');
    if (!row) return;
    const wrap = row.parentElement;
    if (e.target.closest('.tw.has')) { wrap.classList.toggle('open'); return; }
    selectNode(row._n, false);
  });
  treeEl.addEventListener('dblclick', (e) => {
    const row = e.target.closest('.trow');
    if (row && row._n.children.length) row.parentElement.classList.toggle('open');
  });
  treeEl.addEventListener('mouseover', (e) => {
    const row = e.target.closest('.trow');
    if (row) setRange('hv', row._n.start, row._n.end);
  });
  treeEl.addEventListener('mouseleave', () => setRange('hv', 0, 0));
  treeEl.addEventListener('keydown', (e) => {
    const n = state.selNode;
    if (!n) return;
    const els = state.nodeEls.get(n);
    if (e.key === 'ArrowRight' && n.children.length) { els.wrap.classList.add('open'); e.preventDefault(); }
    if (e.key === 'ArrowLeft') { els.wrap.classList.remove('open'); e.preventDefault(); }
    if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
      const rows = Array.from(treeEl.querySelectorAll('.trow')).filter((r) => r.offsetParent !== null && r.getClientRects().length && r.getBoundingClientRect().height > 0);
      const i = rows.indexOf(els.row), t = rows[i + (e.key === 'ArrowDown' ? 1 : -1)];
      if (t) { selectNode(t._n, false); e.preventDefault(); }
    }
  });
  $('tree-expand').addEventListener('click', () => treeEl.querySelectorAll('.tnode').forEach((w) => { if (w.querySelector(':scope > .tkids')) w.classList.add('open'); }));
  $('tree-collapse').addEventListener('click', () => treeEl.querySelectorAll('.tnode').forEach((w) => w.classList.remove('open')));

  function selectNode(n, fromHex) {
    if (state.selNode) { const o = state.nodeEls.get(state.selNode); if (o) o.row.classList.remove('sel'); }
    state.selNode = n;
    const els = state.nodeEls.get(n);
    if (els) {
      els.row.classList.add('sel');
      for (let p = n.parent; p; p = p.parent) { const pe = state.nodeEls.get(p); if (pe) pe.wrap.classList.add('open'); }
      if (fromHex) els.row.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
    }
    setRange('sel', n.start, n.end);
    const len = n.end - n.start;
    $('st-field').textContent = n.label.replace(/\s+/g, ' ').slice(0, 90) + (len > 0 ? '  |  ' + len + (len === 1 ? ' byte' : ' bytes') + '  |  offset ' + n.start + (len > 1 ? '-' + (n.end - 1) : '') : '');
    if (len > 0 && state.hexEls[n.start]) state.hexEls[n.start].scrollIntoView({ block: 'nearest', behavior: 'smooth' });
  }

  /* =========================== hex and ASCII viewer ======================= */
  function buildHex(d) {
    let h = '';
    for (let off = 0; off < d.length; off += 16) {
      let hx = '', as = '';
      for (let i = 0; i < 16; i++) {
        const k = off + i;
        if (k < d.length) {
          const c = d[k];
          hx += '<span class="hb" data-i="' + k + '">' + hx2(c) + '</span>';
          as += '<span class="ab" data-i="' + k + '">' + (c >= 32 && c < 127 ? esc(String.fromCharCode(c)) : '.') + '</span>';
        } else hx += '<span class="hb">&nbsp;&nbsp;</span>';
      }
      h += '<div class="hrow"><span class="off">' + off.toString(16).padStart(4, '0') + '</span><span class="hx">' + hx + '</span><span class="asc">' + as + '</span></div>';
    }
    hexEl.innerHTML = h;
    state.hexEls = new Array(d.length); state.ascEls = new Array(d.length);
    hexEl.querySelectorAll('.hb[data-i]').forEach((e) => { state.hexEls[+e.dataset.i] = e; });
    hexEl.querySelectorAll('.ab').forEach((e) => { state.ascEls[+e.dataset.i] = e; });
    state.range = { sel: null, hv: null };
  }

  function setRange(kind, s, e) {
    const old = state.range[kind];
    if (old) for (let i = old[0]; i < old[1]; i++) { if (state.hexEls[i]) { state.hexEls[i].classList.remove(kind); state.ascEls[i].classList.remove(kind); } }
    if (e > s) {
      if (kind === 'sel') void hexEl.offsetWidth; /* restart the glow animation */
      for (let i = s; i < e && i < state.hexEls.length; i++) { state.hexEls[i].classList.add(kind); state.ascEls[i].classList.add(kind); }
      state.range[kind] = [s, Math.min(e, state.hexEls.length)];
    } else state.range[kind] = null;
  }

  function deepest(n, i, skipFirst) {
    for (let k = skipFirst ? 1 : 0; k < n.children.length; k++) {
      const c = n.children[k];
      if (c.bit || c.end <= c.start) continue;
      if (c.start <= i && i < c.end) return deepest(c, i, false) || c;
    }
    return null;
  }
  const byteOf = (e) => { const t = e.target.closest('[data-i]'); return t ? +t.dataset.i : -1; };

  hexEl.addEventListener('click', (e) => {
    const i = byteOf(e);
    if (i < 0 || !state.tree) return;
    const n = deepest(state.tree, i, true);
    if (n) selectNode(n, true);
  });
  hexEl.addEventListener('mouseover', (e) => {
    const i = byteOf(e);
    if (i < 0 || !state.tree) return;
    const n = deepest(state.tree, i, true);
    if (n) setRange('hv', n.start, n.end);
    $('st-field').textContent = 'Offset 0x' + i.toString(16).padStart(4, '0') + ' (' + i + ')' + (n ? '  |  ' + n.label.replace(/\s+/g, ' ').slice(0, 70) : '');
  });
  hexEl.addEventListener('mouseleave', () => {
    setRange('hv', 0, 0);
    const n = state.selNode;
    $('st-field').textContent = n ? n.label.replace(/\s+/g, ' ').slice(0, 90) : '';
  });

  /* ================================= find ================================= */
  function payloadText(p) {
    if (!p._a) { let s = ''; const d = p.data; for (let i = 0; i < d.length; i++) s += d[i] >= 32 && d[i] < 127 ? String.fromCharCode(d[i]) : '.'; p._a = s.toLowerCase(); }
    return p._a;
  }
  function runFind(jump) {
    const q = $('find').value.trim().toLowerCase();
    state.matches = []; state.matchSet = new Set(); state.matchPos = -1;
    if (q) {
      state.view.forEach((idx, vi) => {
        const p = state.packets[idx];
        if (haystack(p).includes(q) || payloadText(p).includes(q)) { state.matches.push(vi); state.matchSet.add(idx); }
      });
    }
    $('find-count').textContent = q ? (state.matches.length ? '0 / ' + state.matches.length : 'No matches') : '';
    if (jump && state.matches.length) stepFind(1);
    else renderRows();
  }
  function stepFind(dir) {
    const m = state.matches;
    if (!m.length) return;
    const cur = selectedViewIndex();
    let pos;
    if (state.matchPos < 0) pos = dir > 0 ? m.findIndex((v) => v >= cur) : m.length - 1 - m.slice().reverse().findIndex((v) => v <= cur);
    else pos = state.matchPos + dir;
    if (pos < 0 || pos >= m.length || (state.matchPos < 0 && pos === -1)) pos = (pos + m.length) % m.length;
    state.matchPos = pos;
    $('find-count').textContent = (pos + 1) + ' / ' + m.length;
    selectView(m[pos]);
  }
  $('find').addEventListener('input', () => runFind(true));
  $('find').addEventListener('keydown', (e) => {
    if (e.key === 'Enter') { e.preventDefault(); stepFind(e.shiftKey ? -1 : 1); }
    if (e.key === 'Escape') { e.target.value = ''; runFind(false); e.target.blur(); }
  });
  $('find-next').addEventListener('click', () => stepFind(1));
  $('find-prev').addEventListener('click', () => stepFind(-1));

  /* ============================== splitters =============================== */
  function dragSplit(el, move) {
    el.addEventListener('pointerdown', (e) => {
      e.preventDefault();
      el.setPointerCapture(e.pointerId);
      el.classList.add('drag');
      const mv = (ev) => move(ev.clientX, ev.clientY);
      const up = () => { el.classList.remove('drag'); el.removeEventListener('pointermove', mv); el.removeEventListener('pointerup', up); };
      el.addEventListener('pointermove', mv);
      el.addEventListener('pointerup', up);
    });
  }
  const clamp = (v, a, b) => Math.max(a, Math.min(b, v));
  const root = document.documentElement;
  const moveH = (x, y) => { const r = $('workspace').getBoundingClientRect(); root.style.setProperty('--list-h', clamp(y - r.top, 110, r.height - 150) + 'px'); };
  const moveV = (x, y) => {
    const r = $('lower').getBoundingClientRect();
    if (getComputedStyle($('lower')).flexDirection === 'column') root.style.setProperty('--tree-w', clamp(y - r.top, 80, r.height - 80) + 'px');
    else root.style.setProperty('--tree-w', clamp(x - r.left, 240, r.width - 240) + 'px');
  };
  dragSplit($('split-h'), moveH);
  dragSplit($('split-v'), moveV);
  [['split-h', 'h'], ['split-v', 'v']].forEach(([id, k]) => $(id).addEventListener('keydown', (e) => {
    const step = { ArrowUp: -24, ArrowLeft: -24, ArrowDown: 24, ArrowRight: 24 }[e.key];
    if (!step) return;
    e.preventDefault();
    const r = $(id).getBoundingClientRect();
    if (k === 'h') moveH(0, r.top + step); else moveV(r.left + step, r.top + step);
  }));

  /* ============================= onboarding =============================== */
  const STEPS = [
    { ic: 'shield', tab: 'Open', title: 'Drag and drop, 100% private',
      text: 'Drop a .pcap or .pcapng file anywhere on this page. TabShark reads it with your browser and parses every byte locally. There is no upload, no server and no account.',
      demo: '<button class="btn primary" data-act="open">' + icon('upload') + '<span>Open capture</span></button><button class="btn" data-act="sample">' + icon('zap') + '<span>Load Sample Capture</span></button><span class="note">The sample holds ARP, DNS, a TCP handshake, HTTP, UDP, ICMP, TLS and a TCP reset.</span>' },
    { ic: 'filter', tab: 'Filter', title: 'Filter packets',
      text: 'Type in the filter bar, or tap a chip. Combine terms with && and ||, negate with !, compare with ==, !=, > and <. Plain words search the packet list. Try one:',
      demo: ['tcp', 'dns', 'tcp.port == 80', 'ip.addr == 93.184.216.34 && http', 'error', 'frame.len > 200'].map((f) => '<button class="btn" data-act="filter" data-f="' + esc(f) + '">' + esc(f) + '</button>').join('') + '<span class="note">Each button loads the sample capture if needed and applies the filter.</span>' },
    { ic: 'layers', tab: 'Inspect', title: 'Inspect protocol layers',
      text: 'Select a packet in the list. The protocol tree shows every layer from Ethernet up to the application, with each field decoded. Use the arrows to expand a layer, or Expand all.',
      demo: '<button class="btn" data-act="show-syn">Show a TCP SYN packet</button><button class="btn" data-act="show-dns">Show a DNS response</button><button class="btn" data-act="show-tls">Show a TLS Client Hello</button>' },
    { ic: 'code', tab: 'Bytes', title: 'Cross-highlight hex bytes',
      text: 'Click any layer or field in the tree and its exact bytes light up in the hex and ASCII view. It works both ways: click a byte and the tree jumps to the field that owns it.',
      demo: '<button class="btn" data-act="hl-flags">Highlight the TCP flags</button><button class="btn" data-act="hl-ip">Highlight an IPv4 address</button><button class="btn" data-act="hl-sni">Highlight the TLS server name</button>' }
  ];
  let step = 0;
  (function buildSteps() {
    $('steps-nav').innerHTML = STEPS.map((s, i) => '<button type="button" role="tab" data-s="' + i + '">' + icon(s.ic) + '<span>' + s.tab + '</span></button>').join('');
    $('steps').innerHTML = STEPS.map((s) => '<div class="step"><h3>' + s.title + '</h3><p>' + s.text + '</p><div class="demo">' + s.demo + '</div></div>').join('');
  })();
  function showStep(i) {
    step = clamp(i, 0, STEPS.length - 1);
    document.querySelectorAll('#steps-nav button').forEach((b, k) => { b.classList.toggle('on', k === step); b.setAttribute('aria-selected', k === step); });
    document.querySelectorAll('.step').forEach((s, k) => s.classList.toggle('on', k === step));
    $('step-prev').disabled = step === 0;
    $('step-prev').style.visibility = step === 0 ? 'hidden' : 'visible';
    const last = step === STEPS.length - 1;
    $('step-next').querySelector('span').textContent = last ? 'Done' : 'Next';
  }
  function openModal() { showStep(0); $('modal').hidden = false; $('step-next').focus(); }
  function closeModal() { $('modal').hidden = true; }
  $('btn-help').addEventListener('click', openModal);
  $('modal').addEventListener('click', (e) => { if (e.target.closest('[data-close]')) closeModal(); });
  $('steps-nav').addEventListener('click', (e) => { const b = e.target.closest('button'); if (b) showStep(+b.dataset.s); });
  $('step-prev').addEventListener('click', () => showStep(step - 1));
  $('step-next').addEventListener('click', () => (step === STEPS.length - 1 ? closeModal() : showStep(step + 1)));

  function findNode(n, test) {
    for (const c of n.children) { if (test(c)) return c; const r = findNode(c, test); if (r) return r; }
    return null;
  }
  async function ensureSample() {
    if (!state.cap || state.cap.packets.length !== 27 || !/sample/i.test(state.name)) await loadSample();
    if (state.filterText) setFilter('');
  }
  function gotoPacket(no) {
    const vi = state.view.findIndex((i) => state.packets[i].no === no);
    if (vi >= 0) selectView(vi);
  }
  function gotoNode(no, test) {
    gotoPacket(no);
    const n = state.tree && findNode(state.tree, test);
    if (n) selectNode(n, true);
  }
  $('steps').addEventListener('click', async (e) => {
    const b = e.target.closest('[data-act]');
    if (!b) return;
    const a = b.dataset.act;
    if (a === 'open') { closeModal(); $('file').click(); return; }
    if (a === 'sample') { closeModal(); await loadSample(); return; }
    closeModal();
    if (a === 'filter') { await ensureSample(); setFilter(b.dataset.f); $('filter').focus(); return; }
    await ensureSample();
    if (a === 'show-syn') gotoNode(5, (n) => /^Transmission/.test(n.label));
    else if (a === 'show-dns') gotoNode(4, (n) => /^Domain Name/.test(n.label));
    else if (a === 'show-tls') gotoNode(25, (n) => /Record Layer/.test(n.label));
    else if (a === 'hl-flags') gotoNode(5, (n) => n.label === 'Flags' && n.parent && /^Transmission/.test(n.parent.label));
    else if (a === 'hl-ip') gotoNode(5, (n) => n.label === 'Source Address');
    else if (a === 'hl-sni') gotoNode(25, (n) => n.label === 'Server Name');
  });

  /* ============================ wiring and events ========================= */
  $('btn-open').addEventListener('click', () => $('file').click());
  $('empty-open').addEventListener('click', (e) => { e.stopPropagation(); $('file').click(); });
  $('btn-sample').addEventListener('click', loadSample);
  $('empty-sample').addEventListener('click', (e) => { e.stopPropagation(); loadSample(); });
  $('btn-clear').addEventListener('click', closeCapture);
  $('file').addEventListener('change', (e) => { loadFile(e.target.files[0]); e.target.value = ''; });
  $('drop-target').addEventListener('click', () => $('file').click());
  $('drop-target').addEventListener('keydown', (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); $('file').click(); } });

  let dragDepth = 0;
  const hasFiles = (e) => e.dataTransfer && Array.from(e.dataTransfer.types || []).includes('Files');
  window.addEventListener('dragenter', (e) => { if (!hasFiles(e)) return; e.preventDefault(); dragDepth++; $('dropveil').hidden = false; $('drop-target').classList.add('over'); });
  window.addEventListener('dragover', (e) => { if (hasFiles(e)) e.preventDefault(); });
  window.addEventListener('dragleave', (e) => { if (!hasFiles(e)) return; if (--dragDepth <= 0) { dragDepth = 0; $('dropveil').hidden = true; $('drop-target').classList.remove('over'); } });
  window.addEventListener('drop', (e) => {
    if (!hasFiles(e)) return;
    e.preventDefault(); dragDepth = 0;
    $('dropveil').hidden = true; $('drop-target').classList.remove('over');
    loadFile(e.dataTransfer.files[0]);
  });

  document.addEventListener('keydown', (e) => {
    const tag = (e.target.tagName || '').toLowerCase();
    if (e.key === 'Escape' && !$('modal').hidden) { closeModal(); return; }
    if (tag === 'input' || e.ctrlKey || e.metaKey || e.altKey) return;
    if (e.key === '/' && state.cap) { e.preventDefault(); $('filter').focus(); $('filter').select(); }
    if (e.key === '?' ) openModal();
  });

  showStep(0);
  renderChips();
})();
