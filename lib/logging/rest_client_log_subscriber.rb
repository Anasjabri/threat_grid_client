require 'active_support'
require 'logging/url'
require 'logging/datadog'

module RestClient
  class LogSubscriber
    include Url::Util
    include Datadog::Metric

    def self.init_subscription
      self.new.activate_log_notifier
    end

    def activate_log_notifier
      ActiveSupport::Notifications.subscribe('log.rest-client')do |name, start, finish, id, payload|
        if RestClient.log
          out = []
          out << log(payload)
          out << metrics(payload)
          RestClient.log << out.flatten.join("\n") + "\n"
        end
      end
    end

    def log(payload)
      log  = "TGClient::RestClient.#{payload[:http_method]} #{payload[:url]} [#{payload[:start_time]}] "
      log += "code=#{payload[:response][:code]} message=#{payload[:response][:message]} latency=#{payload[:response][:latency_in_ms]} content_length=#{payload[:response][:content_length]}" if payload[:response]
      log
    end
  end
end

RestClient::LogSubscriber.init_subscription