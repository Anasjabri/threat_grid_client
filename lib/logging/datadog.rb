module Datadog
  module Metric
    def metrics(payload)
      metrics = []
      return metrics if (response = payload[:response]).nil? # We do not want to record anything without a response

      unix_timestamp = payload[:start_time].to_i
      name           = metric_name_prefix(payload[:url], payload[:http_method])

      metrics << add_request_counter_metric(["#{name}_request", 'tg.api_calls_total'], unix_timestamp)
      metrics << metric("#{name}_request_latency", unix_timestamp, response[:latency_in_ms], {metric_type: MetricType::GAUGE,   unit: Unit::MILLISECOND})

      if payload[:response][:code].between?(200, 399)
        metrics << add_request_counter_metric(["#{name}_request_success", 'tg.api_calls_success'], unix_timestamp)
      elsif payload[:response][:code].between?(400, 499)
        metrics << add_request_counter_metric(["#{name}_request_client_error", 'tg.api_calls_client_error'], unix_timestamp)
      else
        metrics << add_request_counter_metric(["#{name}_request_server_error", 'tg.api_calls_server_error'], unix_timestamp)
      end
      metrics.flatten
    end

    # Datadog log format ==> metric unix_timestamp value [attribute1=v1 attributes2=v2 ...]
    def metric(name, time, value, attributes_hash={})
      formatted_attributes = attributes_hash.map{|k, v| "#{k}=#{v}"}.join(' ')
      "#{name} #{time.to_i} #{value} #{formatted_attributes}"
    end

    def metric_name_prefix(url, method=:get)
      name = case url
               when TG_REGEX::USER_RATE_LIMIT
                 'user_rate_limit'
               when TG_REGEX::SAMPLES
                 match?(method, :post) ? 'sample_submit' : 'sample_search'
               when TG_REGEX::SAMPLE
                 'sample'
               when TG_REGEX::SAMPLE_STATE
                 'sample_state'
               when TG_REGEX::SAMPLE_REPORT
                 'sample_report'
               when TG_REGEX::SAMPLE_ANALYSIS
                 'sample_analysis'
               when TG_REGEX::SAMPLE_NETWORK_PCAP
                 'sample_network_pcap'
               when TG_REGEX::SAMPLE_REGISTRY
                 'sample_registry'
               when TG_REGEX::SAMPLE_WARNINGS
                 'sample_warnings'
               when TG_REGEX::SAMPLE_IOC_ANALYSIS
                 'sample_ioc_analysis'
               when TG_REGEX::SAMPLE_SUMMARY
                 'sample_summary'
               when TG_REGEX::SAMPLE_THREAT_SCORE
                 'sample_threat_score'
               when TG_REGEX::WHOAMI
                 'whoami'
               when TG_REGEX::USER_DETAILS
                 'user_details'
               when TG_REGEX::SAMPLE_VIDEO
                 'sample_video'
               when TG_REGEX::SAMPLE_ANALYSIS_ARTIFACTS
                 'sample_analysis_artifacts'
               when TG_REGEX::SUBMISSIONS
                 'submission_search'
               when TG_REGEX::ARTIFACT_DOWNLOAD
                 'artifact_download'
               else
                 'unexpected_api_call'
             end
      "tg.#{name}"
    end

    def match?(method, expected_method)
      method.downcase.to_sym == expected_method
    end

    private

    def add_request_counter_metric(metric_name_or_names, unix_timestamp)
      metric_name_or_names = [metric_name_or_names] if metric_name_or_names.is_a? String
      metric_name_or_names.map do |metric_name|
        metric(metric_name, unix_timestamp, increment_counter_metric(metric_name), {metric_type: MetricType::COUNTER, unit: Unit::REQUEST})
      end
    end

    # With Datadog counters we need to persist the increment in order to get a proper graph and realize the amount of requests over time etc.
    def increment_counter_metric(metric_name)
      var_name = "@@#{metric_name}".gsub(/\./, '_')

      unless self.class.class_variable_defined? var_name
        self.class.class_variable_set(var_name, 0)
      end

      self.class.class_variable_set(var_name, self.class.class_variable_get(var_name) + 1)
    end
  end

  module MetricType
    COUNTER = 'counter'
    GAUGE   = 'gauge'
  end

  module Unit
    REQUEST     = 'request'
    MILLISECOND = 'ms'
  end

  module TG_REGEX
    SAMPLES = /\/samples[^\/]*$/
    SAMPLE_STATE  = /\/samples\/\w+\/state[^\/]*$/
    SAMPLE_REPORT = /\/samples\/\w+\/report.html/
    SAMPLE_ANALYSIS = /\/samples\/\w+\/analysis.json/
    SAMPLE_NETWORK_PCAP = /\/samples\/\w+\/network.pcap/
    SAMPLE_REGISTRY = /\/samples\/\w+\/registry.json/
    SAMPLE_WARNINGS = /\/samples\/\w+\/warnings.json/
    SAMPLE_IOC_ANALYSIS = /\/samples\/\w+\/analysis\/iocs[^\/]*$/
    SAMPLE  = /\/samples\/\w+[^\/]*$/
    SAMPLE_SUMMARY  = /\/samples\/\w+\/summary[^\/]*$/
    SAMPLE_THREAT_SCORE = /\/samples\/\w+\/threat[^\/]*$/
    SAMPLE_VIDEO = /\/samples\/\w+\/video.webm/
    SAMPLE_ANALYSIS_ARTIFACTS = /\/samples\/\w+\/analysis\/artifacts[^\/]*$/
    SUBMISSIONS   = /\/search\/submissions[^\/]*$/
    USER_RATE_LIMIT = /\/users\/[a-z0-9\.\-_]+\/rate-limit[^\/]*$/
    USER_DETAILS    = /\/users\/[a-z0-9\.\-_]+[^\/]*$/
    WHOAMI = /\/session\/whoami[^\/]*$/
    ARTIFACT_DOWNLOAD = /\/artifacts\/\w+\/download[^\/]*$/
  end
end
