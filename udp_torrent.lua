local proto = "udpTorrent"

local p = Proto(proto, "UDP Torrent");

p.fields.magic = ProtoField.uint64(proto .. ".magic", "Magic", base.HEX, {[0x41727101980]="valid"})
p.fields.action = ProtoField.uint32(proto .. ".action", "Direction", base.DEC, { [0] = "connect", [1] = "announce" })
p.fields.transid = ProtoField.uint32(proto .. ".transaction_id", "Transaction ID", base.DEC)
p.fields.connid = ProtoField.uint32(proto .. ".connection_id", "Connection ID", base.DEC)
p.fields.infohash = ProtoField.bytes(proto .. ".info_hash", "Info Hash")
p.fields.peerid = ProtoField.bytes(proto .. ".peer_id", "Peer ID")
p.fields.downloaded = ProtoField.uint64(proto .. ".downloaded", "Downloaded")
p.fields.left = ProtoField.uint64(proto .. ".left", "Left")
p.fields.uploaded = ProtoField.uint64(proto .. ".uploaded", "Uploaded")
p.fields.event = ProtoField.uint32(proto .. ".event", "Event", base.DEC, {[0]="none", [1]="completed", [2]="started", [3]="stopped"})
p.fields.ipaddr = ProtoField.ipv4(proto .. ".ipaddr", "IP Address", base.HEX, {[0]="default"})
p.fields.key = ProtoField.uint32(proto .. ".key", "Key")
p.fields.want = ProtoField.uint32(proto .. ".num_want", "Num Want", base.DEC, {[-1]="default"})
p.fields.port = ProtoField.uint16(proto .. ".port", "Port")
p.fields.interval = ProtoField.uint32(proto .. ".interval", "Interval")
p.fields.leechers = ProtoField.uint32(proto .. ".leechers", "Leechers")
p.fields.seeders = ProtoField.uint32(proto .. ".seeders", "Seeders")

p.fields.peers = ProtoField.none(proto .. ".peers", "Peers")
p.fields.peer = ProtoField.none(proto .. ".peers.peer", "Peer")
p.fields.peeraddr = ProtoField.ipv4(proto .. ".peer.ipaddr", "IP Address")
p.fields.peerport = ProtoField.uint16(proto .. ".peer.port", "TCP Port")

local data_dis = Dissector.get("data")

function p.dissector(buf, pkt, tree)

    if buf:len() <= 12 then return end

    if buf(0,4):uint() == 1 then
        local t = tree:add(p, buf())
        t:add(p.fields.action, buf(0,4))
        t:add(p.fields.transid, buf(4,4))
        t:add(p.fields.interval, buf(8,4))
        t:add(p.fields.leechers, buf(12,4))
        t:add(p.fields.seeders, buf(16,4))
        

        local len = buf:len()
        local nums = (len - 20) / 6
        local peers = t:add(p.fields.peers, buf(20,len-20))
        for i=0,nums-1,1 do
            local subtree = peers:add(p.fields.peer, buf(20+i*6,6))
            subtree:add(p.fields.peeraddr, buf(20+i*6,4))
            subtree:add(p.fields.peerport, buf(24+i*6,2))
        end
        return
    end

    if buf(0,4):uint() ~= 0x417 then return end
    if buf(4,4):uint() ~= 0x27101980 then return end
    
    local t = tree:add(p, buf())
    
    t:add(p.fields.magic, buf(0,8))
    t:add(p.fields.action, buf(8,4))
    
    local action = buf(8,4):uint()

    if action == 0 then
        t:add(p.fields.transid, buf(12,4))
    elseif action == 1 then
        t:add(p.fields.transid, buf(12,4))
        t:add(p.fields.infohash, buf(16,20))
        t:add(p.fields.peerid, buf(36,20))
        t:add(p.fields.downloaded, buf(56,8))
        t:add(p.fields.left, buf(64,8))
        t:add(p.fields.uploaded, buf(72,8))
        t:add(p.fields.event, buf(80,4))
        t:add(p.fields.ipaddr, buf(84,4))
        t:add(p.fields.key, buf(88,4))
        t:add(p.fields.want, buf(92,4))
        t:add(p.fields.port, buf(96,2))
    end

end

local udp_encap_table = DissectorTable.get("udp.port")

udp_encap_table:add(6969, p)
