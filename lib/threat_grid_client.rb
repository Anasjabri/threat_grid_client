require 'threat_grid_client/version'
require 'threat_grid_client/client'
require 'logging/rest_client_log_subscriber'
require 'logging/datadog'
require 'logging/url'
require 'rest_client'
require 'active_support'

module RestClient
  class Request
    include ActiveSupport::NumberHelper

    def log_request
      @start_time = Time.now

      if @block_response
        ActiveSupport::Notifications.instrument('log.rest-client',
                                                JanusPayload.new(self,
                                                                 @start_time).to_hash)
      end
    end

    def log_response(response)
      ActiveSupport::Notifications.instrument('log.rest-client',
                                              JanusPayload.new(self,
                                                               @start_time,
                                                               response,
                                                               Time.now).to_hash)
    end
  end
end

module ThreatGridClient
  def self.init(conf={})
    Client.init(conf)
  end

  def self.create(conf)
    Client.new conf
  end
end

class JanusPayload
  include Url::Util

  def initialize(request, start_time, response=nil, end_time=nil)
    @request    = request
    @response   = response
    @start_time = start_time
    @end_time   = end_time
    @hash       = generate_hash
  end

  def to_hash
    @hash
  end

  private

  def generate_hash
    hash = {
        url:         sanitize(@request.url),
        http_method: @request.method.to_s.downcase.to_sym,
        headers:     @request.headers,
        start_time:  @start_time,
    }

    hash.merge!(response: {
        code:           @response.code.to_i,
        message:        @response.message,
        end_datetime:   @end_time,
        latency_in_ms:  ((@end_time - @start_time) * 1000.0).round,
        content_length: @response.content_length
    }) if @response
    hash
  end
end
