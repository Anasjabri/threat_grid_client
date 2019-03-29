module ThreatGridClient

  module OEM
    def create_organization(options={})
      raise ArgumentError, 'login must be present'  if options[:login].nil? || options[:login].empty?
      raise ArgumentError, 'shared secret must be present' if @api_credentials[:oem_key].nil? || @api_credentials[:oem_key].empty?
      raise ArgumentError, 'oem name must be present' if @api_credentials[:oem_name].nil? || @api_credentials[:oem_name].empty?
      raise ArgumentError, 'email must be prsent'     if options[:email].nil? || options[:email].empty?
      raise ArgumentError, 'organization name must be present' if options[:organization_name].nil? || options[:organization_name].empty?


      url_encoded = URI.encode_www_form([['login', options[:login]],
                                         ['name', options[:name]],
                                         ['organization_name', options[:organization_name]],
                                         ['oem_name', @api_credentials[:oem_name]],
                                         ['day', Time.now.strftime("%Y-%m-%d")]])

      secret = @api_credentials[:oem_key]
      email  = options[:email]
      #hashing: secret#params
      #note only email is not url-encoded, everything else seems to be
      url_hash = Digest::SHA256.hexdigest "#{secret}#email=#{email}&#{url_encoded}"
      ssl_args = { open_timeout: 60, timeout: 90, ssl_version: :TLSv1_2 }
      payload  =  "email=#{email}&#{url_encoded}&url_hash=#{url_hash}"
      args = ssl_args.merge method: :post, url: api_url_v2("oem/users"), payload: payload, headers: {content_type: 'application/x-www-form-urlencoded'}
      response = RestClient::Request.execute args
      JSON.parse(response, symbolize_names: true)
    end
  end
end

