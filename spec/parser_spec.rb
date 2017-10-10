require "spec_helper"

RSpec.describe ProxyProtocol::Parser do

  let(:subject) { ProxyProtocol::Parser.new }

  context 'v2' do
    let(:valid_signature) { "\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A" }

    let(:version) { 0x20 } # v2
    let(:cmd_local) { 0x0 }
    let(:cmd_proxy) { 0x1 }
    let(:cmd_invalid) { 0x2 }

    let(:t_unspec) { 0x0 }
    let(:t_tcp_ipv4) { 0x11 }
    let(:t_udp_ipv4) { 0x12 }
    let(:t_tcp_ipv6) { 0x21 }
    let(:t_udp_ipv6) { 0x22 }
    let(:t_unix_stream) { 0x31 }
    let(:t_unix_datagram) { 0x32 }

    context 'full tcp_ipv4' do

      let(:input_data) do
        data = ''
        data << valid_signature
        data << [(version | cmd_proxy)].pack('C')
        data << [t_tcp_ipv4].pack('C')

        proxy_addr = [127, 0, 0, 1].pack('CCCC') + [127, 0, 0, 1].pack('CCCC') + [80].pack('n') + [8081].pack('n')
        data << [proxy_addr.bytesize].pack('n')
        data << proxy_addr

        data
      end

      it 'parse and return proxy protocol data' do
        parsed, tail = subject.parse(input_data)

        expect(parsed).to eql(input_data.bytesize)
        expect(tail).to eql(0)

        expect(subject.complete?).to eql(true)

        proxy_data = subject.proxy_data
        expect(proxy_data.version).to eql 2
        expect(proxy_data.command).to eql cmd_proxy
        expect(proxy_data.address_family).to eql 1 # IPv4
        expect(proxy_data.transport_protocol).to eql 1 # TCP
        expect(proxy_data.address_length).to eql 12 # TCP

        proxy_addr = proxy_data.proxy_addr
        expect(proxy_addr[:src_addr]).to eql '127.0.0.1'
        expect(proxy_addr[:src_port]).to eql '80'
        expect(proxy_addr[:dst_addr]).to eql '127.0.0.1'
        expect(proxy_addr[:dst_port]).to eql '8081'
      end

    end

  end

end
