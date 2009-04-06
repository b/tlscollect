module TLSCollect
  class Certificate
    
    attr_accessor :signature_algorithm, :hash_algorithm, :encryption_algorithm,
                  :subject, :public_key, :raw, :verified
  
    def self.parse(params)
      pkey = params[:raw].public_key
    
      self.new(:raw => params[:raw],
               :verified => params[:verified],
               :public_key => pkey)
    end
  
    def initialize(params)
      @raw = params[:raw]
      @verified = params[:verified]
      @public_key = params[:public_key]
      @subject = hash_subject(@raw.subject)
      # ecdsa-with-SHA1
      s_alg = @raw.signature_algorithm.to_s
      if s_alg.match(Regexp.new("^ec"))
        @encryption_algorithm, @hash_algorithm = s_alg.split("-with-")
      else
        @hash_algorithm, @encryption_algorithm = s_alg.split("With")
      end
      @hash_algorithm.upcase!
    end
  
    def certificate
      raw
    end
  
    def to_xml
      r = REXML::Element.new "certificate"
      r.text = raw.to_s
    
      r
    end
  
    def to_json
      to_h.to_json
    end
  
    #t.integer   :site_result_id, :null => false
    #t.datetime  :not_before, :null => false
    #t.datetime  :not_after,  :null => false
    #t.string    :cn, :null => false
    #t.string    :issuer, :null => false
    #t.integer   :key_length, :null => false
    #t.string    :hash_alg, :null => false
    #t.string    :enc_alg, :null => false
    #t.binary    :raw, :null => false
  
    def to_h 
      { 'raw' => raw.to_s,
        'key_length' => key_length,
        'hash_alg' => hash_algorithm,
        'enc_alg' => encryption_algorithm,
        'issuer' => issuing_ca,
        'cn' => hash_subject(raw.subject)['CN'],
        'not_before' => raw.not_before,
        'not_after' => raw.not_after,
        'verified' => verified,
        'good_longevity' => longevity? }
    end
  
    def cn
      hash_subject(raw.subject)['CN']  
    end
    
    def splitter(pair)
      if pair.split('=').length == 2 
        return pair.split('=')
      end
      nil
    end
  
    def hash_subject(subject)
      a = []
      subject.to_s.split('/').each do |nv|
        if t = splitter(nv)
          a << t
        end
      end
      Hash[*a.collect { |v| [v, v*2] }.flatten]
    end
  
    def valid?(hostname)
      (hostname.match(subject['CN'].gsub('*', '.*'))) &&
      !expired? &&
      raw.not_before < Time.now
    end
  
    def issuing_ca
      if i = hash_subject(raw.issuer)['CN']
        return i
      else
        if hash_subject(raw.issuer)['OU'] == 'www.verisign.com'
          return "VeriSign International Server CA - Class 3"
        else
          return hash_subject(raw.issuer)['OU']
        end
      end
    end
  
    def key_length
      public_key.n.num_bytes * 8
    end

    def expired?
      raw.not_after < Time.now
    end

    def longevity?
      # allow 25 months, give or take
      (raw.not_after.tv_sec - raw.not_before.tv_sec) <=  65836800
    end
  
    def invalid?(hostname)
      !valid?(hostname) || !verified
    end
  
  end
end