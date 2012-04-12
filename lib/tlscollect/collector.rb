module TLSCollect
  class CollectException < Exception
  end
  
  class Collector
    
    attr_accessor :host, :addr, :port, :default_cipher, :protocols, :ciphers,
                  :certificate, :verified, :timestamp, :totals
  
    @@default_ca_cert_path = "certs/ca-bundle.crt"

    @@protocols = [:TLSv1, :SSLv3, :SSLv2]
    @@basic_ciphers = [
                       ['RC4-MD5', 'TLSv1/SSLv3', 128, 128],
                       ['RC4-MD5', 'SSLv2', 128, 128],
                       ['RC4-SHA', 'TLSv1/SSLv3', 128, 128],
                       ['DES-CBC3-SHA', 'TLSv1/SSLv3', 168, 168],
                       ['DHE-RSA-AES256-SHA', 'TLSv1/SSLv3', 256, 256],
                       ['DHE-RSA-AES128-SHA', 'TLSv1/SSLv3', 128, 128],
                       ['AES256-SHA', 'TLSv1/SSLv3', 256, 256],
                       ['AES128-SHA', 'TLSv1/SSLv3', 128, 128],
                       ['EXP-RC4-MD5', 'SSLv2', 40, 128]
                      ]
  
    def initialize(params)
      @ca_cert_path = (params[:ca_cert_path] ? params[:ca_cert_path] : @@default_ca_cert_path)
      puts "CA CERT PATH IS #{@ca_cert_path}"
      
      @host = params[:host]
      @addr = (params[:addr] ? params[:addr] : addr = TCPSocket.gethostbyname(host)[3])
      @port = params[:port]
      @default_cipher = nil
      @verified = false
      @protocols = []
      @ciphers = []
      @candidate_ciphers = []
      #@totals = {'null' => 0, 'export' => 0, 'low' => 0,
      #           'medium' => 0, 'high' => 0, 'dhe' => 0}
    end
  
    def to_h
      begin
        i = 0
        h = { 'summ' => { 'collected_at' => timestamp,
                          'tls1_2'   => tls1_2?,
                          'tls1_1'   => tls1_1?,
                          'tls1_0'   => tls1_0?,
                          'ssl3_0'   => ssl3_0?,
                          'ssl2_0'   => ssl2_0?
                        },
              'certificate' => certificate.to_h,
              'ciphers' => ciphers.collect {|c| 
                c.order = i
                i += 1
                c.to_h
              }
        }
      rescue StandardError => e
        puts "ERROR: #{e}"
      end
      h
    end
  
    def tls1_2?
      protocols.include?("TLSv1.2") #|| tls1_1?
    end
  
    def tls1_1?
      protocols.include?("TLSv1.1") #|| tls1_0?
    end
  
    def tls1_0?
      protocols.include?("TLSv1")
    end
  
    def ssl3_0?
      protocols.include?("SSLv3")
    end
  
    def ssl2_0?
      protocols.include?("SSLv2")
    end
  
    def pci_ready?
      Cipher.pci_ready?(ciphers) &&
      !(protocols.include?("SSLv2") && protocols.length == 1)
    end
  
    def collect
      @timestamp = Time.now
      unless init_context
        raise CollectException.new, "Failed to initialize collection context."
      end
      @verified = certificate_verified?
      @_default_cipher, @certificate = gather_defaults
      unless @_default_cipher && @certificate
        raise CollectException.new, "Could not determine default cipher and certificate."
      end
      test_ciphers
      test_cipher_order
    end
  
    def init_context
      sock = get_sock
      return nil unless sock
      ssl = OpenSSL::SSL::SSLSocket.new(sock)
      @candidate_ciphers = ssl.context.ciphers.collect { |c| Cipher.parse(c) }
      [["NULL-MD5", "SSLv2", 0, 0],["NULL-MD5", "SSLv2", 0, 0],
       ["NULL-MD5", "TLSv1/SSLv3", 0, 0],["NULL-MD5", "TLSv1/SSLv3", 0, 0]].each do |c|
        @candidate_ciphers << Cipher.parse(c)
      end
      [["ECDHE-RSA-RC4-SHA", "TLSv1/SSLv3", 128, 128], ["ECDHE-RSA-RC4-MD5", "TLSv1/SSLv3", 128, 128],
       ["ECDHE-RSA-AES256-SHA", "TLSv1/SSLv3", 256, 256], ["ECDHE-RSA-AES128-SHA", "TLSv1/SSLv3", 128, 128],
       ["ECDHE-ECDSA-AES256-SHA", "TLSv1/SSLv3", 256, 256], ["ECDHE-ECDSA-AES128-SHA", "TLSv1/SSLv3", 128, 128],
       ["ECDHE-RSA-DES-CBC3-SHA", "TLSv1/SSLv3", 168, 168],  ["ECDHE-ECDSA-DES-CBC3-SHA", "TLSv1/SSLv3", 168, 168]].each do |c|
         @candidate_ciphers << Cipher.parse(c)
      end
    end

    def get_sock
      begin
        timeout(30) do
          #puts "getting socket for #{addr} on port #{port}"
          TCPSocket.open(addr, port)
        end
      rescue Timeout::Error
        nil
      end
    end

    def connect(ssl)
      begin
        timeout(30) do
          ssl.connect
        end
      rescue
        nil
      end
    end
  
    def certificate_verified?
      sock = get_sock
      return false unless sock
      context = OpenSSL::SSL::SSLContext.new()
      context.ciphers = @@basic_ciphers
      context.ca_file = @ca_cert_path
      context.verify_depth = 16
      context.verify_mode = OpenSSL::SSL::VERIFY_PEER
      ssl = OpenSSL::SSL::SSLSocket.new(sock, context)
      begin
        ssl.connect
      rescue
        puts "Certificate for #{@host} is unverified"
        return false
      end
    
      true
    end
  
    def try_protocol(protocol, sock)
      begin
        context = OpenSSL::SSL::SSLContext.new(protocol)
        context.ciphers = @@basic_ciphers
        ssl = OpenSSL::SSL::SSLSocket.new(sock, context)
        ssl.connect
      rescue Exception => e
        #unless e.message.length > 1
        #  raise CollectException.new, "OpenSSL/Ruby protocol selection bug.  Argh."
        #end
        nil
      end
    end
  
    def gather_defaults
      d = c = nil
      @@protocols.each do |p|
        return [ nil, nil ] unless (sock = get_sock)
        ssl = try_protocol(p, sock)
        @protocols << p.to_s if ssl
      end
      return [ nil, nil ] unless sock = get_sock
      ssl = OpenSSL::SSL::SSLSocket.new(sock)
      if ssl.connect
        d = Cipher.parse(ssl.cipher) unless d
        c = Certificate.parse(:raw => ssl.peer_cert, :verified => verified) unless c
      end
          
      puts "Failure while gathering defaults" unless (d && c)
      return [ d, c ]
    end
  
    def test_protocols
      @@protocols.each do |protocol|
        sock = get_sock
        context = OpenSSL::SSL::SSLContext.new(protocol)
        ssl = OpenSSL::SSL::SSLSocket.new(sock, context)
        @protocols << protocol.to_s if connect(ssl)
      end
    end
  
    def test_ciphers
      @candidate_ciphers.each do |cipher|
        sock = get_sock
        context = OpenSSL::SSL::SSLContext.new()
        begin
          context.ciphers = [cipher.to_a]
        rescue
          nil
        end
        ssl = OpenSSL::SSL::SSLSocket.new(sock, context)
        if connect(ssl) 
          p_check = false
          cipher.protocols.each do |p|
            if @protocols.include?(p)
              p_check = true
            end
          end
          unless p_check
            #puts "Protocol check is false for #{cipher.cipher}"
            next
          end
        
          @ciphers << cipher
          #@totals[cipher.strength] += 1
        end
      end
    end

    def test_cipher_order
      t_ciphers = @ciphers.collect {|c| c.to_a}
      @ciphers = []
      (0..(t_ciphers.length - 1)).each do |i|
        sock = get_sock
        context = OpenSSL::SSL::SSLContext.new()
        begin
          context.ciphers = t_ciphers
        rescue
          nil
        end
        ssl = OpenSSL::SSL::SSLSocket.new(sock, context)
        if connect(ssl)
          t_ciphers, d_ciphers = delete_cipher(t_ciphers, ssl.cipher)
          d_ciphers.each do |d|
            tc = Cipher.parse(d)
            if j = included_cipher?(tc)
              #puts "Adding protocols #{tc.protocols.join(', ')} to #{@ciphers[j].cipher}"
              @ciphers[j].protocols << tc.protocols if supported_protocol?(tc.protocols)
              @ciphers[j].protocols.flatten!
            else 
              @ciphers << tc if supported_protocol?(tc.protocols)
            end
          end
        end
      end
      @default_cipher = @ciphers.first
      @ciphers
    end
  
    def included_cipher?(cipher)
      @ciphers.each do |c|
        if c.cipher == cipher.cipher
          return @ciphers.index(c)
        end
      end
      nil
    end
  
    def supported_protocol?(protocol)
      protocols.each {|p| return true if @protocols.include?(p)}
      false
    end
  
    def delete_cipher(ciphers, cipher)
      cipher = Cipher.parse(cipher).cipher
      d = []
      ciphers.each { |c|
        d << ciphers.delete(c) if Cipher.parse(c).cipher == cipher
      }
    
      [ciphers, d]
    end
  end
end