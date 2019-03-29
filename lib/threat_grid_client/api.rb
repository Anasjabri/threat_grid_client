module ThreatGridClient
  module API
    def submit_sample(file, options={})
      raise ArgumentError, 'file must be present' if file.nil?

      api_path = 'samples'
      payload = { sample:   file,
                  tags:     options[:tags]     || '',
                  os:       options[:os]       || '',
                  osver:    options[:osver]    || '',
                  source:   options[:source]   || '',
                  vm:       options[:vm]       || '',
                  private:  options[:private]  || 'true'
                }
      response = execute :post, api_url_v2(api_path), payload
      JSON.parse(response, symbolize_names: true)
    end

    def state(sample_id)
      raise ArgumentError, 'sample id must be present' if sample_id.nil? || sample_id.empty?
      api_path = "samples/#{sample_id}/state"
      get_json api_url_v2(api_path)
    end

    def html_report(sample_id)
      raise ArgumentError, 'sample id must be present' if sample_id.nil? || sample_id.empty?
      api_path = "samples/#{sample_id}/report.html"
      execute :get, api_url_v2(api_path)
    end

    # Useful json attributes
    # id: ["data"]["id"],
    # md5: ["data"]["md5"],
    # state: ["data"]["state"],
    # filename: ["data"]["filename"],
    # status: ["data"]["status"],
    # sha256: ["data"]["sha256"]
    def sample(sample_id)
      raise ArgumentError, 'sample id must be present' if sample_id.nil? || sample_id.empty?
      api_path = "samples/#{sample_id}"
      get_json api_url_v2(api_path)
    end

    def samples(options={})
      api_path = "samples"
      payload = {
                  limit:      options[:limit]     || 50,
                  offset:     options[:offset]    || 0,
                  user_only:  options[:user_only] ||  '',
                  org_only:   options[:org_only]  || 'true'
                }
      response = get_json api_url_v2(api_path), payload
    end

    #https://panacea.threatgrid.com/api/v2/search/submissions?q=sha256:abcc2a2d828b1624459cf8c4d2ccdfdcde62c8d1ab51e438db200ab3c5c8cd17&advanced=true&limit=26&offset=0&org_only=false&state=succ&api_key=&
    def samples_by_sha(options={})
      api_path = "search/submissions"
      payload = {
                  limit:      options[:limit]     || 50,
                  offset:     options[:offset]    || 0,
                  advanced:   options[:advanced]  || 'true',
                  user_only:  options[:user_only] ||  '',      # not used
                  org_only:   options[:org_only]  || 'false'
                }

      payload.merge!({q: "sha256:#{options[:sha256].strip.downcase}"}) if valid?(options[:sha256])
      payload.merge!({state: 'succ'})
      get_json api_url_v2(api_path), payload
    end

    #sample_states 404s for now
    def analysis(sample_id) #way too big to parse anything useful from, other functions more effective
      raise ArgumentError, 'sample id must be present' if sample_id.nil? || sample_id.empty?
      api_path = "samples/#{sample_id}/analysis.json"
      get_json api_url_v2(api_path)
    end

    def processes(sample_id) #crazy huge, likely not needed
      raise ArgumentError, 'sample id must be present' if sample_id.nil? || sample_id.empty?
      api_path = "samples/#{sample_id}/processes.json"
      get_json api_url_v2(api_path)
    end

    #pcap file
    def network_pcap(sample_id, &block)
      raise ArgumentError, 'sample id must be present' if sample_id.nil? || sample_id.empty?
      stream_content "samples/#{sample_id}/network.pcap", &block
    end

    def registry(sample_id) #invalid json
      raise ArgumentError, 'sample id must be present' if sample_id.nil? || sample_id.empty?
      api_path = "samples/#{sample_id}/registry.json"
      get_json api_url_v2(api_path)
    end

    def warnings(sample_id) #invalid json for multiple warnings
      raise ArgumentError, 'sample id must be present' if sample_id.nil? || sample_id.empty?
      api_path = "samples/#{sample_id}/warnings.json"
      get_json api_url_v2(api_path)
    end

    #behavioral indicators
    def iocs(sample_id)
      raise ArgumentError, 'sample id must be present' if sample_id.nil? || sample_id.empty?
      api_path = "samples/#{sample_id}/analysis/iocs"
      get_json api_url_v2(api_path)
    end

    # Useful Attributes
    # id: ["data"]["sample"],
    # filename: ["data"]["filename"],
    # sha256: ["data"]["sha256"]
    def summary(sample_id)
      raise ArgumentError, 'sample id must be present' if sample_id.nil? || sample_id.empty?
      api_path = "samples/#{sample_id}/summary"
      get_json api_url_v2(api_path)
    end

    # Useful Attribtues
    # id: ["data"]["sample"],
    # score: ["data"]["score"],
    # max_confidence: ["data"]["max-confidence"],
    # max_severity: ["data"]["max-severity"]
    def threat_score(sample_id)
      raise ArgumentError, 'sample id must be present' if sample_id.nil? || sample_id.empty?
      api_path = "samples/#{sample_id}/threat"
      get_json api_url_v2(api_path)
    end

    def rate_limit
      api_path = "users/#{self.login}/rate-limit"
      get_json api_url_v3(api_path)
    end

    def whoami
      api_path = 'session/whoami'
      get_json api_url_v3(api_path)
    end

    def user_details(login)
      raise ArgumentError, 'login must be present' if login.to_s.strip.length == 0

      api_path = "users/#{login}"
      get_json api_url_v3(api_path)
    end

    def video(sample_id, &block)
      raise ArgumentError, 'sample id must be present' if sample_id.nil? || sample_id.empty?
      stream_content "samples/#{sample_id}/video.webm", &block
    end

    def original_sample(sample_id, &block)
      raise ArgumentError, 'sample id must be present' if sample_id.nil? || sample_id.empty?
      stream_content "samples/#{sample_id}/sample.zip", &block
    end

    def search(options={})
      api_path = "search/submissions"
      payload = {
                  limit:      options[:limit]     || 50,
                  offset:     options[:offset]    || 0,
                  # advanced:   options[:advanced]  || 'true',   # enable full Elastic Search
                  user_only:  options[:user_only] ||  '',      # not used
                  org_only:   options[:org_only]  || 'true'
                }
      payload.merge!({q: options[:query].strip.downcase}) if valid?(options[:query])
      payload.merge!({state: 'succ'}) if options.has_key?(:org_only) && options[:org_only] == 'false'
      get_json api_url_v2(api_path), payload
    end

    #https://test.threatgrid.com/api/v2/search/submissions?after=2018-09-02T23%3A59%3A59%2B03%3A00&before=2018-10-02T23%3A59%3A59%2B03%3A00&limit=10&offset=0&sort_order=asc&sort_by=threat
    def top_submissions(options={})
      api_path = "search/submissions"
      payload = {
                  limit:      options[:limit]     || 5,
                  offset:     options[:offset]    || 0,
                  org_only:   options[:org_only]  || 'true',
                  user_only:  options[:user_only] ||  '',      # not used
                  after: options[:period_start] || (Time.now - (60 * 60 * 24)).iso8601,
                  before: options[:period_end] || Time.now.iso8601,
                  sort_order: options[:sort_order] || 'desc',
                  sort_by: options[:sort_by] || 'threat'
                }
      payload.merge!({threatscore: options[:threatscore]}) if options.has_key?(:threatscore)
      payload.merge!({state: 'succ'}) if options.has_key?(:org_only) && options[:org_only] == 'false'
      get_json api_url_v2(api_path), payload
    end

    def artifacts(sample_id)
      raise ArgumentError, 'sample id must be present' if sample_id.nil? || sample_id.empty?
      api_path = "samples/#{sample_id}/analysis/artifacts"
      get_json api_url_v2(api_path)
    end

    def download_artifact(sha256, &block)
      raise ArgumentError, 'sha256 be present' if sha256.nil? || sha256.empty?
      stream_content "artifacts/#{sha256}/download", &block
    end

    def stream_content(api_path, &block)
      if block.present?
        execute :get, api_url_v2(api_path) ,{} ,true, &block
      else
        Enumerator.new do |yielder|
          stream_content(api_path) do |chunk|
            yielder.yield(chunk)
          end
        end
      end
    end

    def valid?(value)
      value && !value.strip.empty?
    end
  end
end
