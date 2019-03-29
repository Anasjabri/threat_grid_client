require 'threat_grid_client/api'
require 'threat_grid_client/oem'
require 'threat_grid_client/stream'
require 'json'

module ThreatGridClient
  class APIResourceNotFound   < StandardError; end
  class APIServiceError       < StandardError; end
  class InvalidAPIKey         < StandardError; end
  class InvalidResponse       < StandardError; end

  class Client
    include ThreatGridClient::API
    include ThreatGridClient::OEM

    attr_reader :login

    def initialize(api_credentials)
      raise ArgumentError, 'An API path must be present'     if @@api_v2_path.nil? || @@api_v2_path.empty?
      raise ArgumentError, 'Api credential must be a hash'   unless api_credentials.kind_of? Hash
      raise ArgumentError, 'An API host must be supplied.'   unless api_credentials[:api_host]
      raise ArgumentError, 'The API host must be a string'   unless api_credentials[:api_host].kind_of? String

      @api_credentials = api_credentials
      @login = @api_credentials[:login]
      @api_host = @api_credentials[:api_host].chomp("/")
    end

    def execute(method, url, payload={}, stream=false, &block)
      params = payload
      params = params.merge api_key: @api_credentials[:api_key] if @api_credentials.has_key? :api_key
      args = @@config_args.merge method: method, url: url, payload: params, raw_response: stream
      if stream
        response = ThreatGridClient::Stream.execute args, &block
      else
        response = RestClient::Request.execute args
      end

    rescue RestClient::ResourceNotFound => exception        #404
      raise APIResourceNotFound, exception.http_body
    rescue RestClient::InternalServerError => exception     #500
      raise APIServiceError, exception.http_body
    rescue RestClient::Unauthorized => exception            #401
      raise InvalidAPIKey, exception.http_body
    end


    def get_json(url, payload={})
      response = execute(:get, url, payload)
      JSON.parse( response, symbolize_names: true )
    rescue => exception
      error = "Error ThreatGridClient:: response: #{response}, payload: #{payload}, url: #{url}, exception: #{exception}"
      raise InvalidResponse, error
    end

    def api_url_v2(path)
      "https://#{@api_host}/#{@@api_v2_path}/#{path}"
    end

    def api_url_v3(path)
      "https://#{@api_host}/#{@@api_v3_path}/#{path}"
    end

    def api_key_valid?
      payload = {
        limit: 1,
        offset: 0,
        user_only: '',
        org_only: 'true'
      }
      begin
        execute(:get, api_url_v2("samples"), payload)
      rescue InvalidAPIKey
        return false
      end
      true
    end

    # Note: Important! this is only used to initialize global configuration and is not used for initializing ThreatGridClient::Client
    def self.init(conf)
      default_args   = {
          open_timeout: 60,
          timeout:      90, # read timeout
          ssl_version:  :TLSv1_2
      }

      @@api_v2_path                = conf[:api_v2_path]  || "api/v2"
      @@api_v3_path                = conf[:api_v3_path]  || "api/v3"

      @@config_args = {}
      @@config_args[:open_timeout] = conf[:open_timeout] || default_args[:open_timeout]
      @@config_args[:timeout]      = conf[:timeout]      || default_args[:timeout]
      @@config_args[:ssl_version]  = conf[:ssl_version]  || default_args[:ssl_version]
      @@config_args[:ssl_ca_file]  = conf[:ssl_ca_file]  if conf[:ssl_ca_file]
      @@config_args[:verify_ssl]   = conf[:verify_ssl]   if conf[:verify_ssl]

      RestClient.log = conf[:logger] if conf[:logger]
    end
  end
end
