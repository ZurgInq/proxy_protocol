module ProxyProtocol

  class ProxyData
    attr_accessor :version, :command, :address_family, :transport_protocol, :address_length, :proxy_addr, :full_length
  end

  class NotImplemented < StandardError
  end

  class Parser

    attr_accessor :proxy_data

    HEADER_SIZE = 16

    def initialize
      @complete          = false
      @buf               = String.new('', capacity: HEADER_SIZE+216) # header size + max proxy_addr size
      @tlv_buf           = ''
      @proxy_data        = ProxyData.new
      @header_parsed     = false
      @proxy_addr_parsed = false
      @first_parse       = true
      @offset            = 0
    end

    def parse(data)
      data_size = data.bytesize
      return [0, data_size] if @complete

      if !@header_parsed && data_size >=16
        check_sign!(data)

        parse_header(data, @proxy_data)
        @header_parsed = true

        parse_proxy_addr(data, @proxy_data)
        @proxy_addr_parsed = true
      end

      if @first_parse
        @first_parse = false
        if data_size >= @proxy_data.full_length
          @complete = true
          @offset   = @proxy_data.full_length
          return [@proxy_data.full_length, data_size - @proxy_data.full_length]
        else
          @offset = data_size
          return [data_size, 0]
        end
      else # second call parse on incomplete data
        if @offset + data_size >= @proxy_data.full_length
          @complete = true
          parsed    = (@offset + data_size) - @proxy_data.full_length
          @offset   = @proxy_data.full_length
          return [parsed, data_size - @proxy_data.full_length]
        end
      end
    end

    def complete?
      @complete
    end

    private

    def check_sign!(buf)
      if buf[0..11] != "\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A"
        raise StandardError, 'invalid proxy protocol signature'
      end
    end

    def parse_header(buf, proxy_data)
      ver_cmd            = buf[12].unpack('C')[0]
      proxy_data.version = (ver_cmd & 0b11110000) >> 4
      proxy_data.command = ver_cmd & 0b00001111

      addr_tr_protocol              = buf[13].unpack('C')[0]
      proxy_data.address_family     = (addr_tr_protocol & 0b11110000) >> 4
      proxy_data.transport_protocol = (addr_tr_protocol & 0b00001111)

      proxy_data.address_length = buf[14..15].unpack('n')[0]
      proxy_data.full_length    = HEADER_SIZE+@proxy_data.address_length
    end

    def parse_proxy_addr(buf, proxy_data)
      case proxy_data.command
      when 0 #LOCAL
        return
      when 1 #PROXY
        proxy_data.proxy_addr = {}
        case proxy_data.address_family
        when 0 #unspec
          #
        when 1 #IPv4
          proxy_data.proxy_addr[:src_addr] = buf[HEADER_SIZE+0..HEADER_SIZE+3].unpack('CCCC').join('.')
          proxy_data.proxy_addr[:dst_addr] = buf[HEADER_SIZE+4..HEADER_SIZE+7].unpack('CCCC').join('.')
          proxy_data.proxy_addr[:src_port] = buf[HEADER_SIZE+8..HEADER_SIZE+9].unpack('n')[0].to_s
          proxy_data.proxy_addr[:dst_port] = buf[HEADER_SIZE+10..HEADER_SIZE+11].unpack('n')[0].to_s
        when 2 #IPv6
          raise NotImplemented, 'IPv6 address family'
        when 3 #unix
          raise NotImplemented, 'unix address family'
        else
          raise StandardError, "invalid address_family #{proxy_data.address_family}"
        end
      else
        raise StandardError, "invalid command field #{proxy_data.command}"
      end
    end

  end

end