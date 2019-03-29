module Url
  module Util
    def sanitize(url)
      begin
        @uri = URI.parse(url)
        if @uri.query
          query = CGI::parse(@uri.query)

          keys = query.keys.select { |key| %w(api_key oem_user oem_key).include?(key) }
          keys.each do |key|
            query[key] = 'REDACTED'
          end

          @uri.query = URI.encode_www_form(query)
        end
        @uri.password = 'REDACTED' if @uri.password
        @uri.to_s
      rescue URI::InvalidURIError
        # An attacker may be able to manipulate the URL to be
        # invalid, which could force disclosure of a password if
        # we show any of the un-parsed URL here.
        '[invalid uri]'
      end
    end
  end
end