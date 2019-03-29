require 'spec_helper'

describe Datadog::Metric do
  let(:subject) { TestClass.new }
  let(:rate_limit_url) { 'https://sandcastle.threatgrid.com/api/v3/users/some.login/rate-limit' }

  context '#metric' do
    it 'convert to datadog metric canonical log format' do
      name       = 'some.metric.name'
      time       = Time.now
      value      = 'some.metric.value'
      attributes = {metric_type: 'counter', unit: 'request'}

      actual = subject.metric(name, time, value, attributes)

      expect(actual).to eql("#{name} #{time.to_i} #{value} metric_type=counter unit=request")
    end
  end

  context '#add_metrics' do
    before(:each) do
      subject.class.class_variable_set('@@tg_user_rate_limit_request', 0)
      subject.class.class_variable_set('@@tg_user_rate_limit_request_success', 0)
      subject.class.class_variable_set('@@tg_api_calls_total', 0)
      subject.class.class_variable_set('@@tg_api_calls_success', 0)
    end

    it 'should add metrics' do
      start_time = Time.now
      end_time   = Time.now + 60 * 60

      expect(subject).to receive(:metric).with('tg.user_rate_limit_request',         start_time.to_i, 1,                                      { metric_type: 'counter', unit: 'request'}).once
      expect(subject).to receive(:metric).with('tg.api_calls_total',                 start_time.to_i, 1,                                      { metric_type: 'counter', unit: 'request'}).once
      expect(subject).to receive(:metric).with('tg.user_rate_limit_request_latency', start_time.to_i, ((end_time - start_time) * 1000).round, { metric_type: 'gauge',   unit: 'ms'}).once
      expect(subject).to receive(:metric).with('tg.user_rate_limit_request_success', start_time.to_i, 1,                                      { metric_type: 'counter', unit: 'request'}).once
      expect(subject).to receive(:metric).with('tg.api_calls_success', start_time.to_i, 1,                                      { metric_type: 'counter', unit: 'request'}).once

      payload = payload(rate_limit_url, 'GET', start_time, end_time, 200, 'OK', 239)
      expect(subject.metrics(payload).count).to eql(5)
    end

    it 'should add metrics with incremented counter' do
      start_time = Time.now
      end_time   = Time.now + 60 * 60

      expect(subject).to receive(:metric).with('tg.user_rate_limit_request',         start_time.to_i, 1,                                      { metric_type: 'counter', unit: 'request'}).once
      expect(subject).to receive(:metric).with('tg.user_rate_limit_request',         start_time.to_i, 2,                                      { metric_type: 'counter', unit: 'request'}).once
      expect(subject).to receive(:metric).with('tg.user_rate_limit_request',         start_time.to_i, 3,                                      { metric_type: 'counter', unit: 'request'}).once
      expect(subject).to receive(:metric).with('tg.api_calls_total',                 start_time.to_i, 1,                                      { metric_type: 'counter', unit: 'request'}).once
      expect(subject).to receive(:metric).with('tg.api_calls_total',                 start_time.to_i, 2,                                      { metric_type: 'counter', unit: 'request'}).once
      expect(subject).to receive(:metric).with('tg.api_calls_total',                 start_time.to_i, 3,                                      { metric_type: 'counter', unit: 'request'}).once
      expect(subject).to receive(:metric).with('tg.user_rate_limit_request_latency', start_time.to_i, ((end_time - start_time) * 1000).round, { metric_type: 'gauge',   unit: 'ms'}).exactly(3).times
      expect(subject).to receive(:metric).with('tg.user_rate_limit_request_success', start_time.to_i, 1,                                      { metric_type: 'counter', unit: 'request'}).once
      expect(subject).to receive(:metric).with('tg.user_rate_limit_request_success', start_time.to_i, 2,                                      { metric_type: 'counter', unit: 'request'}).once
      expect(subject).to receive(:metric).with('tg.user_rate_limit_request_success', start_time.to_i, 3,                                      { metric_type: 'counter', unit: 'request'}).once
      expect(subject).to receive(:metric).with('tg.api_calls_success', start_time.to_i, 1,                                      { metric_type: 'counter', unit: 'request'}).once
      expect(subject).to receive(:metric).with('tg.api_calls_success', start_time.to_i, 2,                                      { metric_type: 'counter', unit: 'request'}).once
      expect(subject).to receive(:metric).with('tg.api_calls_success', start_time.to_i, 3,                                      { metric_type: 'counter', unit: 'request'}).once

      payload = payload(rate_limit_url, 'GET', start_time, end_time, 200, 'OK', 239)
      expect(subject.metrics(payload).count).to eql(5)
      expect(subject.metrics(payload).count).to eql(5)
      expect(subject.metrics(payload).count).to eql(5)
    end

    it 'should not add metrics without response' do
      start_time = Time.now

      expect(subject).to_not receive(:metric)

      payload = payload(rate_limit_url, 'GET', start_time)
      expect(subject.metrics(payload).count).to eql(0)
    end
  end

  context '#metric_name_prefix' do
    let(:post_samples_url) { 'https://panacea.threatgrid.com/api/v2/samples' }
    let(:sample_state_url) { 'https://panacea.threatgrid.com/api/v2/samples/7462c120eee19b30ac2511f960cbab3a/state' }
    let(:sample_report_url) { 'https://panacea.threatgrid.com/api/v2/samples/7462c120eee19b30ac2511f960cbab3a/report.html' }
    let(:sample_analysis_url) { 'https://panacea.threatgrid.com/api/v2/samples/7462c120eee19b30ac2511f960cbab3a/analysis.json' }
    let(:sample_ioc_analysis_url) { 'https://panacea.threatgrid.com/api/v2/samples/7462c120eee19b30ac2511f960cbab3a/analysis/iocs' }
    let(:sample_network_pcap_url) { 'https://panacea.threatgrid.com/api/v2/samples/bc11e6883485349bd15ddd550342bf64/network.pcap' }
    let(:sample_registry_url) { 'https://panacea.threatgrid.com/api/v2/samples/bc11e6883485349bd15ddd550342bf64/registry.json' }
    let(:sample_warnings_url) { 'https://panacea.threatgrid.com/api/v2/samples/bc11e6883485349bd15ddd550342bf64/warnings.json' }
    let(:fetch_samples_url) { 'https://panacea.threatgrid.com/api/v2/samples' }
    let(:fetch_sample_url) { 'https://panacea.threatgrid.com/api/v2/samples/7462c120eee19b30ac2511f960cbab3a' }
    let(:sample_summary_url) { 'https://panacea.threatgrid.com/api/v2/samples/7462c120eee19b30ac2511f960cbab3a/summary' }
    let(:sample_threat_score_url) { 'https://panacea.threatgrid.com/api/v2/samples/7462c120eee19b30ac2511f960cbab3a/threat' }
    let(:sample_video_url) { 'https://panacea.threatgrid.com/api/v2/samples/7462c120eee19b30ac2511f960cbab3a/video.webm' }
    let(:sample_analysis_artifacts_url) { 'https://panacea.threatgrid.com/api/v2/samples/7e45036ffc071a6b087350ea180e4d4d/analysis/artifacts?api_key=REDACTED' }
    let(:search_submissions_url) { 'https://panacea.threatgrid.com/api/v2/search/submissions?limit=51&offset=0&advanced=true&user_only=&org_only=false&q=sha256%3A00b32c3428362e39e4df2a0c3e0950947c147781fdd3d2ffd0bf5f96989bb002&state=succ&api_key=REDACTED' }
    let(:user_details_url) { 'https://panacea.threatgrid.com/api/v3/users/amp-07a28118-3f43-4b68-b534-2507bb516e27' }
    let(:whoami_url) { 'https://panacea.threatgrid.com/api/v3/session/whoami?api_key=REDACTED' }
    let(:artifact_download_url) { 'https://panacea.threatgrid.com/api/v2/artifacts/20f5a67aa41f35fc160d4f0b059195bc3d43747fbb4b542d9b808d50d8528185/download' }

    it 'add metrics based on given payload' do
      expect(subject.metric_name_prefix('some.unexpected.url')).to         eql('tg.unexpected_api_call')
      expect(subject.metric_name_prefix(post_samples_url, :post)).to       eql('tg.sample_submit')
      expect(subject.metric_name_prefix(fetch_samples_url)).to             eql('tg.sample_search')
      expect(subject.metric_name_prefix(fetch_sample_url)).to              eql('tg.sample')
      expect(subject.metric_name_prefix(sample_state_url)).to              eql('tg.sample_state')
      expect(subject.metric_name_prefix(sample_report_url)).to             eql('tg.sample_report')
      expect(subject.metric_name_prefix(sample_analysis_url)).to           eql('tg.sample_analysis')
      expect(subject.metric_name_prefix(sample_network_pcap_url)).to       eql('tg.sample_network_pcap')
      expect(subject.metric_name_prefix(sample_registry_url)).to           eql('tg.sample_registry')
      expect(subject.metric_name_prefix(sample_warnings_url)).to           eql('tg.sample_warnings')
      expect(subject.metric_name_prefix(sample_ioc_analysis_url)).to       eql('tg.sample_ioc_analysis')
      expect(subject.metric_name_prefix(sample_summary_url)).to            eql('tg.sample_summary')
      expect(subject.metric_name_prefix(sample_threat_score_url)).to       eql('tg.sample_threat_score')
      expect(subject.metric_name_prefix(sample_video_url)).to              eql('tg.sample_video')
      expect(subject.metric_name_prefix(sample_analysis_artifacts_url)).to eql('tg.sample_analysis_artifacts')
      expect(subject.metric_name_prefix(whoami_url)).to                    eql('tg.whoami')
      expect(subject.metric_name_prefix(user_details_url)).to              eql('tg.user_details')
      expect(subject.metric_name_prefix(rate_limit_url)).to                eql('tg.user_rate_limit')
      expect(subject.metric_name_prefix(search_submissions_url)).to        eql('tg.submission_search')
      expect(subject.metric_name_prefix(artifact_download_url)).to         eql('tg.artifact_download')
    end
  end

  def payload(url, method, start_time, end_time = nil, http_code = nil, message = nil, content_length=0)
    response = end_time ? double('rest-client-response', {code: http_code, message: message, content_length: content_length}) : nil
    JanusPayload.new(RestClient::Request.new({url: url, method: method}), start_time, response, end_time).to_hash
  end
end

class TestClass
  include Datadog::Metric
end
