module TLSCollect
  class Cipher
    
    attr_accessor :name, :kx_alg, :auth_alg, :bulk_alg, :hash_alg, :protocols, :alg_bits, :key_length, :order
  
    def self.parse(cipher_a)
      c = cipher_a[0].split('-')
      if cipher_a[0].match(/^ECDH-/) ||
         cipher_a[0].match(/^ECDHE-/) ||
         cipher_a[0].match(/^DHE-/) ||
         cipher_a[0].match(/^EXP-EDH-/) ||
         cipher_a[0].match(/^EXP-DHE-/) ||
         cipher_a[0].match(/^EDH-/)
        c.shift if cipher_a[0].match(/^EXP-/)
        c[0] = 'DHE' if c[0] == 'EDH'
        n_kx = c[0]
        c.shift
        n_auth = c[0]
        c.shift
      else
        n_kx = n_auth = "RSA"
      end
    
      if c[0] == 'EXP'
        c.shift
        exp = true
      else
        exp = false
      end
      n_hash = c.last
      n_bulk = c[0..(c.length - 2)].join('-')
      n_cipher = cipher_a[0]
      n_protocols = [cipher_a[-3].split('/')].flatten
      n_key_length = cipher_a[-2]
      exp = true if n_key_length < 128
      n_alg_bits = cipher_a.last
    
      self.new(:cipher => n_cipher,
               :kx_alg => n_kx,
               :auth_alg => n_auth,
               :bulk_alg => n_bulk,
               :hash_alg => n_hash,
               :protocols => n_protocols,
               :key_length => n_key_length,
               :alg_bits => n_alg_bits,
               :export => exp)
    end
  
    def initialize(params)
      @name = params[:cipher]
      @kx_alg = params[:kx_alg]
      @auth_alg = params[:auth_alg]
      @bulk_alg = params[:bulk_alg]
      @hash_alg = params[:hash_alg]
      @protocols = params[:protocols]
      @key_length = params[:key_length]
      @export = params[:export]
      @alg_bits = params[:alg_bits]
      @order = 0
    end
  
    def cipher
      name
    end

    def to_s
      cipher + " " + protocols.join('/')
    end
  
    def to_a
      [cipher, protocols.join('/'), key_length, alg_bits]
    end
  
    def to_h
      {
       'name'     => cipher,
       'kx_alg'   => kx_alg,
       'auth_alg' => auth_alg,
       'bulk_alg' => bulk_alg,
       'hash_alg' => hash_alg,
       'tls1_2'   => tls1_2?,
       'tls1_1'   => tls1_1?,
       'tls1_0'   => tls1_0?,
       'ssl3_0'   => ssl3_0?,
       'ssl2_0'   => ssl2_0?,
       'key_length' => key_length,
       'preference' => order
       }      
    end
  
    def tls1_2?
      protocols.include?("TLSv1.2") || tls1_1?
    end
  
    def tls1_1?
      protocols.include?("TLSv1.1") || tls1_0?
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
  
  end
end