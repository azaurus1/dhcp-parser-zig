const std = @import("std");
const cli = @import("cli");

const dhcp_parser_zig = @import("dhcp_parser_zig");

var config = struct {
    pcap_input: bool = false,
}{};

const DHCP_OP = enum(u8) {
    BOOTREQUEST = 1,
    BOOTREPLY = 2,
    _,

    pub fn label(self: DHCP_OP) []const u8 {
        return switch (self) {
            .BOOTREQUEST => "BOOTREQUEST",
            .BOOTREPLY => "BOOTREPLY",
            _ => "Unkown",
        };
    }
};

const DhcpOption = enum(u8) {
    pad = 0,
    subnet_mask = 1,
    time_offset = 2,
    router = 3,
    time_server = 4,
    name_server = 5,
    domain_name_server = 6,
    log_server = 7,
    cookie_server = 8,
    lpr_server = 9,
    impress_server = 10,
    resource_location_server = 11,
    host_name = 12,
    boot_file_size = 13,
    merit_dump_file = 14,
    domain_name = 15,
    swap_server = 16,
    root_path = 17,
    extensions_path = 18,
    ip_forwarding = 19,
    non_local_source_routing = 20,
    policy_filter = 21,
    max_datagram_reassembly_size = 22,
    default_ip_ttl = 23,
    path_mtu_aging_timeout = 24,
    path_mtu_plateau_table = 25,
    interface_mtu = 26,
    all_subnets_local = 27,
    broadcast_address = 28,
    perform_mask_discovery = 29,
    mask_supplier = 30,
    perform_router_discovery = 31,
    router_solicitation_address = 32,
    static_route = 33,
    trailer_encapsulation = 34,
    arp_cache_timeout = 35,
    ethernet_encapsulation = 36,
    tcp_default_ttl = 37,
    tcp_keepalive_interval = 38,
    tcp_keepalive_garbage = 39,
    nis_domain = 40,
    nis_servers = 41,
    ntp_servers = 42,
    vendor_specific = 43,
    netbios_name_server = 44,
    netbios_datagram_server = 45,
    netbios_node_type = 46,
    netbios_scope = 47,
    x_window_font_server = 48,
    x_window_display_manager = 49,
    requested_ip = 50,
    lease_time = 51,
    option_overload = 52,
    message_type = 53,
    server_identifier = 54,
    parameter_request_list = 55,
    message = 56,
    max_message_size = 57,
    renewal_time = 58,
    rebinding_time = 59,
    vendor_class_identifier = 60,
    client_identifier = 61,
    nis_plus_domain = 64,
    nis_plus_servers = 65,
    tftp_server_name = 66,
    bootfile_name = 67,
    mobile_ip_home_agent = 68,
    smtp_server = 69,
    pop3_server = 70,
    nntp_server = 71,
    default_www_server = 72,
    default_finger_server = 73,
    default_irc_server = 74,
    streettalk_server = 75,
    streettalk_directory_server = 76,
    user_class = 77,
    fqdn = 81,
    dhcp_agent_options = 82,
    nds_servers = 85,
    nds_tree_name = 86,
    nds_context = 87,
    bcms_controller_names = 88,
    bcms_controller_address = 89,
    client_system = 93,
    client_ndi = 94,
    ldap = 95,
    uuid_guid = 97,
    user_auth = 98,
    netinfo_address = 112,
    netinfo_tag = 113,
    url = 114,
    auto_config = 116,
    name_service_search = 117,
    subnet_selection = 118,
    domain_search = 119,
    classless_static_route = 121,
    cablelabs_client_configuration = 122,
    end = 255,
    _,

    pub fn label(self: DhcpOption) []const u8 {
        return switch (self) {
            .pad => "Pad",
            .subnet_mask => "Subnet Mask",
            .time_offset => "Time Offset",
            .router => "Router",
            .time_server => "Time Server",
            .name_server => "Name Server",
            .domain_name_server => "Domain Name Server",
            .log_server => "Log Server",
            .cookie_server => "Cookie Server",
            .lpr_server => "LPR Server",
            .impress_server => "Impress Server",
            .resource_location_server => "Resource Location Server",
            .host_name => "Host Name",
            .boot_file_size => "Boot File Size",
            .merit_dump_file => "Merit Dump File",
            .domain_name => "Domain Name",
            .swap_server => "Swap Server",
            .root_path => "Root Path",
            .extensions_path => "Extensions Path",
            .ip_forwarding => "IP Forwarding",
            .non_local_source_routing => "Non-Local Source Routing",
            .policy_filter => "Policy Filter",
            .max_datagram_reassembly_size => "Max Datagram Reassembly Size",
            .default_ip_ttl => "Default IP TTL",
            .path_mtu_aging_timeout => "Path MTU Aging Timeout",
            .path_mtu_plateau_table => "Path MTU Plateau Table",
            .interface_mtu => "Interface MTU",
            .all_subnets_local => "All Subnets Local",
            .broadcast_address => "Broadcast Address",
            .perform_mask_discovery => "Perform Mask Discovery",
            .mask_supplier => "Mask Supplier",
            .perform_router_discovery => "Perform Router Discovery",
            .router_solicitation_address => "Router Solicitation Address",
            .static_route => "Static Route",
            .trailer_encapsulation => "Trailer Encapsulation",
            .arp_cache_timeout => "ARP Cache Timeout",
            .ethernet_encapsulation => "Ethernet Encapsulation",
            .tcp_default_ttl => "TCP Default TTL",
            .tcp_keepalive_interval => "TCP Keepalive Interval",
            .tcp_keepalive_garbage => "TCP Keepalive Garbage",
            .nis_domain => "NIS Domain",
            .nis_servers => "NIS Servers",
            .ntp_servers => "NTP Servers",
            .vendor_specific => "Vendor Specific",
            .netbios_name_server => "NetBIOS Name Server",
            .netbios_datagram_server => "NetBIOS Datagram Server",
            .netbios_node_type => "NetBIOS Node Type",
            .netbios_scope => "NetBIOS Scope",
            .x_window_font_server => "X Window Font Server",
            .x_window_display_manager => "X Window Display Manager",
            .requested_ip => "Requested IP Address",
            .lease_time => "Lease Time",
            .option_overload => "Option Overload",
            .message_type => "DHCP Message Type",
            .server_identifier => "Server Identifier",
            .parameter_request_list => "Parameter Request List",
            .message => "Message",
            .max_message_size => "Max Message Size",
            .renewal_time => "Renewal Time",
            .rebinding_time => "Rebinding Time",
            .vendor_class_identifier => "Vendor Class Identifier",
            .client_identifier => "Client Identifier",
            .nis_plus_domain => "NIS+ Domain",
            .nis_plus_servers => "NIS+ Servers",
            .tftp_server_name => "TFTP Server Name",
            .bootfile_name => "Bootfile Name",
            .mobile_ip_home_agent => "Mobile IP Home Agent",
            .smtp_server => "SMTP Server",
            .pop3_server => "POP3 Server",
            .nntp_server => "NNTP Server",
            .default_www_server => "Default WWW Server",
            .default_finger_server => "Default Finger Server",
            .default_irc_server => "Default IRC Server",
            .streettalk_server => "StreetTalk Server",
            .streettalk_directory_server => "StreetTalk Directory Server",
            .user_class => "User Class",
            .fqdn => "Fully Qualified Domain Name",
            .dhcp_agent_options => "DHCP Agent Options",
            .nds_servers => "NDS Servers",
            .nds_tree_name => "NDS Tree Name",
            .nds_context => "NDS Context",
            .bcms_controller_names => "BCMS Controller Names",
            .bcms_controller_address => "BCMS Controller Address",
            .client_system => "Client System",
            .client_ndi => "Client NDI",
            .ldap => "LDAP",
            .uuid_guid => "UUID/GUID",
            .user_auth => "User Auth",
            .netinfo_address => "NetInfo Address",
            .netinfo_tag => "NetInfo Tag",
            .url => "URL",
            .auto_config => "Auto Config",
            .name_service_search => "Name Service Search",
            .subnet_selection => "Subnet Selection",
            .domain_search => "Domain Search",
            .classless_static_route => "Classless Static Route",
            .cablelabs_client_configuration => "CableLabs Client Configuration",
            .end => "End",
            _ => "Unknown",
        };
    }
};

const DHCPPacket = extern struct {
    op: DHCP_OP,
    htype: u8,
    hlen: u8,
    hops: u8,
    xid: u32,
    secs: u16,
    flags: u16,
    ciaddr: u32,
    yiaddr: u32,
    siaddr: u32,
    giaddr: u32,
    chaddr: [16]u8,
    sname: [64]u8,
    file: [128]u8,
    // options: DhcpOption,

    fn print_hex(self: DHCPPacket) void {
        std.debug.print("++++ Hex ++++\n", .{});
        std.debug.print("op:      {x}\n", .{self.op});
        std.debug.print("htype:   {x}\n", .{self.htype});
        std.debug.print("hlen:    {x}\n", .{self.hlen});
        std.debug.print("hops:    {x}\n", .{self.hops});
        std.debug.print("xid:     {x}\n", .{self.xid});
        std.debug.print("secs:    {x}\n", .{self.secs});
        std.debug.print("flags:   {x}\n", .{self.flags});
        std.debug.print("ciaddr:  {x}\n", .{self.ciaddr});
        std.debug.print("yiaddr:  {x}\n", .{self.yiaddr});
        std.debug.print("siaddr:  {x}\n", .{self.siaddr});
        std.debug.print("giaddr:  {x}\n", .{self.giaddr});
        std.debug.print("chaddr:  {x}\n", .{self.chaddr});
        std.debug.print("sname:   {x}\n", .{self.sname});
        std.debug.print("file:    {x}\n", .{self.file});
        // std.debug.print("options: {x}\n", .{self.options});
    }

    fn print_string(self: DHCPPacket) !void {

        // OP
        const op = @tagName(self.op);
        std.debug.print("op: {s}\n", .{op});

        // htype
        std.debug.print("htype: {d}\n", .{self.htype});

        // hlen
        std.debug.print("hlen: {d}\n", .{self.hlen});

        // xid
        std.debug.print("xid: {d}\n", .{self.xid});

        // secs
        std.debug.print("secs: {d}\n", .{self.secs});

        // flags
        const broadcast = (self.flags >> 15) & 1 == 1;
        if (broadcast) {
            std.debug.print("flags: BROADCAST\n", .{});
        } else {
            std.debug.print("flags: NOT BROADCAST\n", .{});
        }

        // ciaddr
        var ciaddr_buf: [16]u8 = undefined;
        const ciaddr = try bin_to_ip(self.ciaddr, &ciaddr_buf);
        std.debug.print("ciaddr: {s}\n", .{ciaddr});

        // yiaddr
        var yiaddr_buf: [16]u8 = undefined;
        const yiaddr = try bin_to_ip(self.yiaddr, &yiaddr_buf);
        std.debug.print("yiaddr: {s}\n", .{yiaddr});

        // siaddr
        var siaddr_buf: [16]u8 = undefined;
        const siaddr = try bin_to_ip(self.siaddr, &siaddr_buf);
        std.debug.print("siaddr: {s}\n", .{siaddr});

        // giaddr
        var giaddr_buf: [16]u8 = undefined;
        const giaddr = try bin_to_ip(self.giaddr, &giaddr_buf);
        std.debug.print("giaddr: {s}\n", .{giaddr});

        // chaddr
        var chaddr_buf: [18]u8 = undefined;
        const chaddr = try std.fmt.bufPrint(&chaddr_buf, "{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}", .{
            self.chaddr[0], self.chaddr[1], self.chaddr[2],
            self.chaddr[3], self.chaddr[4], self.chaddr[5],
        });
        std.debug.print("chaddr: {s}\n", .{chaddr});

        // sname
        std.debug.print("sname: {s}\n", .{self.sname});

        // file
        std.debug.print("file: {s}\n", .{self.file});

        // options
        // const options = @tagName(self.options);
        // std.debug.print("options: {s}\n", .{options});
    }
};

pub fn bin_to_ip(bin_addr: u32, buf: []u8) ![]u8 {
    return std.fmt.bufPrint(buf, "{d}.{d}.{d}.{d}", .{
        (bin_addr >> 24) & 0xFF,
        (bin_addr >> 16) & 0xFF,
        (bin_addr >> 8) & 0xFF,
        (bin_addr >> 0) & 0xFF,
    });
}

pub fn main(init: std.process.Init) !void {
    var r = cli.AppRunner.init(&init);

    defer r.deinit();

    const app = cli.App{ .command = cli.Command{ .name = "dhcp-parser", .options = try r.allocOptions(&.{
        .{
            .long_name = "pcap_input",
            .help = "use if the input file is a pcap file",
            .value_ref = r.mkRef(&config.pcap_input),
        },
    }), .target = cli.CommandTarget{
        .action = cli.CommandAction{ .exec = run },
    } } };

    return r.run(&app);
}

fn run() !void {
    if (config.pcap_input) {
        return run_pcap();
    }
    return run_raw();
}

fn run_pcap() !void {
    std.debug.print("running in pcap mode!\n", .{});
    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    const gpa = debug_allocator.allocator();

    var threaded: std.Io.Threaded = .init(gpa, .{});
    defer threaded.deinit();

    // reader layer takes bytes from stdin
    const io = threaded.io();
    const stdin = std.Io.File.stdin();
    var buf: [4096]u8 = undefined;
    var reader = stdin.reader(io, &buf);
    var r = &reader.interface;

    var bytes: [300]u8 = undefined; // max size of a packet is 590 bytes but we have skipped options so only read 300 bytes

    var pcap_global: [24]u8 = undefined; // strips off the global pcap header 24 bytes - https://www.ietf.org/archive/id/draft-gharris-opsawg-pcap-01.html
    _ = try r.readSliceShort(&pcap_global);

    while (true) {
        var pcap_pkt: [16]u8 = undefined;
        const ph = try r.readSliceShort(&pcap_pkt);
        if (ph < 16) break;

        var frame_headers: [42]u8 = undefined;
        _ = try r.readSliceShort(&frame_headers);

        const n = try r.readSliceShort(&bytes);

        if (n < @sizeOf(DHCPPacket)) break;

        const packet = @as(DHCPPacket, @bitCast(bytes[0..@sizeOf(DHCPPacket)].*));

        const options = bytes[@sizeOf(DHCPPacket)..n];

        // packet.print_hex();
        std.debug.print("\n", .{});
        try packet.print_string();
        try parse_options(options);
    }
}

fn run_raw() !void {
    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    const gpa = debug_allocator.allocator();

    var threaded: std.Io.Threaded = .init(gpa, .{});
    defer threaded.deinit();

    // reader layer takes bytes from stdin
    const io = threaded.io();
    const stdin = std.Io.File.stdin();
    var buf: [4096]u8 = undefined;
    var reader = stdin.reader(io, &buf);
    var r = &reader.interface;

    var bytes: [300]u8 = undefined; // max size of a packet is 590 bytes but we have skipped options so only read 300 bytes

    while (true) {
        const n = try r.readSliceShort(&bytes);

        if (n < @sizeOf(DHCPPacket)) break;

        const packet = @as(DHCPPacket, @bitCast(bytes[0..@sizeOf(DHCPPacket)].*));

        const options = bytes[@sizeOf(DHCPPacket)..n];

        // packet.print_hex();
        std.debug.print("\n", .{});
        try packet.print_string();
        try parse_options(options);
    }
}

fn printable(byte: u8) bool {
    return '!' <= byte and byte <= '~';
}

fn parse_options(data: []const u8) !void {
    var i: usize = 4; // skip magic cookie

    while (i < data.len) {
        const opt_type: DhcpOption = @enumFromInt(data[i]);

        if (opt_type == .pad) {
            i += 1;
            continue;
        }
        if (opt_type == .end) break;

        i += 1;
        if (i >= data.len) break;
        const len = data[i];
        i += 1;
        if (i + len > data.len) break;
        const value = data[i .. i + len];
        std.debug.print("Option: {s}: {any}\n", .{ opt_type.label(), value });
        i += len;
    }
}
