require 'spec_helper'

describe ThreatGridClient::API do
  let(:api_key  )     { 'api_key'  }
  let(:api_host )     { 'api_host' }
  let(:login )        { 'login' }
  let(:response)      { { state: "succ"} }
  let(:str_response)  { "{\"state\":\"succ\"}" }
  let(:file_object)   { "file_content" }
  let(:html)          { "<b>helloworld</b>"}
  let(:sha256)        { "a9ce12417d202515d6a8f6b19f8568e365e024a3601312173c5cfa2338ebb8f4" }
  let(:sample_id)     { "6fa2fe39c509703b042b60ff51e38be9" }

  before { ThreatGridClient.init() }

  describe 'Client' do
    let!(:client)  { ThreatGridClient.create({api_key: api_key, login: login, api_host: api_host}) }

    context 'rate-limit' do
      it 'retrieves rate limit for given login name and api key' do
        expect(client).to receive(:get_json).with(client.api_url_v3("users/#{login}/rate-limit")) { response }

        ret = client.rate_limit
        expect(ret).to eql(response)
      end
    end

    context 'whoami' do
      it 'retrieves user details' do
        expect(client).to receive(:get_json).with(client.api_url_v3('session/whoami')) { response }

        ret = client.whoami
        expect(ret).to eql(response)
      end
    end

    context "#submit_sample" do
      it 'raises ArgumentError' do
        expect { client.submit_sample(nil) }.to raise_error ArgumentError
      end

      it 'posts a file and returns a json response' do
        test_file = File.new(File.join( File.dirname(File.expand_path(__FILE__)), 'testfile'))

        expect(client).to receive(:execute).with(:post, client.api_url_v2("samples"),
                                    {sample: test_file,
                                     tags:    '',
                                     os:      '',
                                     osver:   '',
                                     source:  '',
                                     vm:      '',
                                     private:  'true' } ) { str_response }

        ret = client.submit_sample(test_file)
        expect(ret).to eql(response)
      end
    end

    context "#samples_by_sha" do
      it "searches samples by sha" do
        expect(client).to receive(:get_json).with(client.api_url_v2("search/submissions"), {limit:  26, offset: 0, advanced: 'true',
                                                                        user_only: '', org_only: 'false', q: "sha256:#{sha256}", state: 'succ'}) { response }
        ret = client.samples_by_sha({sha256: sha256, limit: 26, org_only: 'false'})

        expect(ret).to eql(response)
      end
    end

    context "#search" do
      it "gets list of private sample when query is blank" do
        expect(client).to receive(:get_json).with(client.api_url_v2("search/submissions"), {limit:  50, offset: 0, user_only: '', org_only: 'true'}) { response }
        ret = client.search({})

        expect(ret).to eql(response)
      end

      it "gets list of public samples when query is blank" do
        expect(client).to receive(:get_json).with(client.api_url_v2("search/submissions"), {limit:  26, offset: 0, user_only: '', org_only: 'false', state: 'succ'}) { response }
        ret = client.search({limit: 26, org_only: 'false'})

        expect(ret).to eql(response)
      end

      it "gets searches when query is present" do
        expect(client).to receive(:get_json).with(client.api_url_v2("search/submissions"), {limit:  26, offset: 0, user_only: '', org_only: 'true', q: 'keyword'}) { response }
        ret = client.search({query: 'keyword', limit: 26, org_only: 'true'})

        expect(ret).to eql(response)
      end

      it "gets list when query is nil" do
        expect(client).to receive(:get_json).with(client.api_url_v2("search/submissions"), {limit:  26, offset: 0, user_only: '', org_only: 'false', state: 'succ'}) { response }
        ret = client.search({query: nil, limit: 26, org_only: 'false'})

        expect(ret).to eql(response)
      end

      it "gets list when query is blank" do
        expect(client).to receive(:get_json).with(client.api_url_v2("search/submissions"), {limit:  26, offset: 0, user_only: '', org_only: 'false', state: 'succ'}) { response }
        ret = client.search({query: "    ", limit: 26, org_only: 'false'})

        expect(ret).to eql(response)
      end

      it "submits lowercase" do
        expect(client).to receive(:get_json).with(client.api_url_v2("search/submissions"), {limit:  26, offset: 0, user_only: '', org_only: 'false', q: 'keyword', state: 'succ'}) { response }
        ret = client.search({query: "  KEYWORD   ", limit: 26, org_only: 'false'})

        expect(ret).to eql(response)
      end

    end

    context "#top_submissions" do
      before do
        allow(Time).to receive(:now).and_return(Time.parse("2018-10-02T00:00:00+03:00"))
      end

      it "gets list of private sample when params is empty" do
        expect(client).to receive(:get_json).with(client.api_url_v2("search/submissions"), {
          limit:  5, offset: 0, user_only: '', org_only: 'true', after: "2018-10-01T00:00:00+03:00", before: "2018-10-02T00:00:00+03:00",sort_order: 'desc', sort_by: 'threat'
        }) { response }
        ret = client.top_submissions({})
        expect(ret).to eql(response)
      end

      it "gets list of private sample when params present" do
        expect(client).to receive(:get_json).with(client.api_url_v2("search/submissions"), {
          limit:  1, offset: 0, user_only: '', org_only: 'true', after: "2019-10-01T00:00:00+03:00", before: "2019-10-02T00:00:00+03:00", sort_order: 'asc', sort_by: 'submitted_at'
        }) { response }
        ret = client.top_submissions({limit: 1, period_start: "2019-10-01T00:00:00+03:00", period_end: "2019-10-02T00:00:00+03:00", sort_order: 'asc', sort_by: 'submitted_at'})
        expect(ret).to eql(response)
      end

      it "gets list of submissions when threatscore param present" do
        expect(client).to receive(:get_json).with(client.api_url_v2("search/submissions"), {
          limit:  1, offset: 0, user_only: '', org_only: 'true', after: "2019-10-01T00:00:00+03:00", before: "2019-10-02T00:00:00+03:00",
          sort_order: 'asc', sort_by: 'submitted_at', threatscore: 'low, medium',
        }) { response }
        ret = client.top_submissions({limit: 1, period_start: "2019-10-01T00:00:00+03:00", period_end: "2019-10-02T00:00:00+03:00",
                                      sort_order: 'asc', sort_by: 'submitted_at', threatscore: 'low, medium'})
        expect(ret).to eql(response)
      end
    end

    context "#state" do
      it 'returns the state of the sample' do
        expect(client).to receive(:get_json).with(client.api_url_v2("samples/#{sample_id}/state")) { response }
        ret = client.state(sample_id)

        expect(ret).to eql(response)
      end

      it 'raises error when sample_id is blank' do
        expect { client.state("") }.to raise_error ArgumentError
      end
    end

    context "#html_report" do
      it 'raises argument error when sample_id is blank' do
        expect { client.html_report("") }.to raise_error ArgumentError
      end

      it 'returns html report' do
        expect(client).to receive(:execute).with(:get, client.api_url_v2("samples/#{sample_id}/report.html")) { html }
        ret = client.html_report(sample_id)

        expect(ret).to eql(html)
      end
    end

    context "#sample" do
      it 'raises error when sample_id is blank' do
        expect { client.sample("") }.to raise_error ArgumentError
      end

      it 'returns information about a single sample' do
        expect(client).to receive(:get_json).with(client.api_url_v2("samples/#{sample_id}")) { response }
        ret = client.sample(sample_id)

        expect(ret).to eql(response)
      end

    end

    context "#iocs" do
      it 'raises error when sample_id is blank' do
        expect { client.iocs("") }.to raise_error ArgumentError
      end

      it 'returns behavioral indicators' do
        expect(client).to receive(:get_json).with(client.api_url_v2("samples/#{sample_id}/analysis/iocs")) { response }
        ret = client.iocs(sample_id)

        expect(ret).to eql(response)
      end

    end

    context "#threat_score" do
      it 'raises argument error when sample_id is blank' do
        expect { client.threat_score("") }.to raise_error ArgumentError
      end

      it 'gets json response from threat grid' do
        expect(client).to receive(:get_json).with(client.api_url_v2("samples/#{sample_id}/threat")) { response }
        ret = client.threat_score(sample_id)

        expect(ret).to eql(response)
      end
    end

    context "#network_pcap" do
      it 'raises argument error when sample_id is blank' do
        expect { client.network_pcap("") }.to raise_error ArgumentError
      end

      it 'downloads pcap file' do
        expect(client).to receive(:stream_content).with("samples/#{sample_id}/network.pcap") { "pcap response" }
        ret = client.network_pcap(sample_id)

        expect(ret).to eql("pcap response")
      end
    end

    context "#download_artifact" do
      it 'raises argument error when sha256 is blank' do
        expect { client.download_artifact("") }.to raise_error ArgumentError
      end

      it 'downloads the artifact' do
        expect(client).to receive(:stream_content).with("artifacts/#{sha256}/download") { "text response" }
        ret = client.download_artifact(sha256)

        expect(ret).to eql("text response")
      end

    end

    context "#artifacts" do
      it 'raises argument error when sample_id is blank' do
        expect { client.artifacts("") }.to raise_error ArgumentError
      end

      it 'gets artifact json response from threat grid' do
        expect(client).to receive(:get_json).with(client.api_url_v2("samples/#{sample_id}/analysis/artifacts")) { response }
        ret = client.artifacts(sample_id)

        expect(ret).to eql(response)
      end
    end

    context '#user_details' do
      it 'should argument error when login is blank' do
        expect { client.user_details('   ') }.to raise_error ArgumentError
        expect { client.user_details(nil) }.to raise_error ArgumentError
      end

      it 'gets api key json response from threat grid' do
        expect(client).to receive(:get_json).with(client.api_url_v3('users/api.login')) { response }
        ret = client.user_details('api.login')

        expect(ret).to eql(response)
      end
    end
  end
end
