require 'spec_helper'

describe ThreatGridClient do
  let(:api_key  )       { 'api_key'  }
  let(:api_host )       { 'api_host' }
  let(:str_response)    { "{\"data\":{\"state\":\"succ\"},\"id\":1398736,\"api_version\":2}" }
  let(:http_code)       { 200 }
  let(:json)            { {state: 'status code'}.to_json }
  let(:response)        { double('rest-client-response') }
  let(:method)          { :get }
  let(:params)          { {} }
  let(:execute_args)    { {open_timeout: 60, timeout: 90, ssl_version: :TLSv1_2,
                                method: method, url: "url",
                                payload: {api_key: api_key}.merge(params),
                                raw_response: false
                        }}

  before { ThreatGridClient.init() }

  describe 'Client' do
    let!(:client)  { ThreatGridClient.create({api_key: api_key, api_host: api_host}) }

    describe '#api_url_v2' do
      it 'returns the correct url' do
        expect(client.api_url_v2('blah')).to eql("https://#{api_host}/api/v2/blah")
      end
    end

    describe '#api_url_v3' do
      it 'returns the correct url' do
        expect(client.api_url_v3('blah')).to eql("https://#{api_host}/api/v3/blah")
      end
    end

    context "#execute" do

      context "#execute get" do
        let(:method)   { :get }
        it 'executes a get request' do
          expect(RestClient::Request).to receive(:execute).with(execute_args) { str_response }
          res = client.execute :get, "url"
          expect(res).to eq str_response
        end
      end

      context "#execute post" do
        let(:method)    { :post }
        let(:params)    { {param1: "val1"} }
        it 'executes a post request' do
          expect(RestClient::Request).to receive(:execute).with(execute_args) { str_response }
          res = client.execute :post, "url", params
          expect(res).to eq str_response
        end
      end

      context "handle 404 error" do
        it 'raises APIResourceNotFound' do
          allow(response)
          allow(RestClient::Request).to receive(:execute).with(execute_args).and_raise RestClient::ResourceNotFound
          expect{ client.execute(:get, "url") }.to raise_error ThreatGridClient::APIResourceNotFound
        end
      end

      context "handle 401 error" do
        it 'raises InvalidAPIKey' do
          expect(RestClient::Request).to receive(:execute).with(execute_args).and_raise RestClient::Unauthorized
          expect{ client.execute(:get, "url") }.to raise_error ThreatGridClient::InvalidAPIKey
        end
      end

      context "handle 500 error" do
        it 'raises APIServiceError' do
          expect(RestClient::Request).to receive(:execute).with(execute_args).and_raise RestClient::InternalServerError
          expect{ client.execute(:get, "url") }.to raise_error ThreatGridClient::APIServiceError
        end
      end

    end

    context "#get_json" do
      it 'get response in json format' do
        expect(client).to receive(:execute).with(:get, "url", {} ) { str_response }
        res = client.get_json("url")
        expect(res).to eq JSON.parse(str_response, symbolize_names: true)
      end

      it 'raise invalid response' do
        expect(client).to receive(:execute).with(:get, "url", {} ) { "{a=>b}" }
        expect { client.get_json("url") }.to raise_error ThreatGridClient::InvalidResponse
      end
    end

    describe '#api_key_valid?' do
      context 'tg responds with 200' do
        it 'returns true if response is a 200' do
          allow(RestClient::Request).to receive(:execute) { response }
          expect(client.api_key_valid?).to be_truthy
        end
      end
      context 'tg responds with 401' do
        let(:http_code) { 401 }
        it 'returns false if response is a 401' do
          allow(RestClient::Request).to receive(:execute).and_raise ThreatGridClient::InvalidAPIKey
          expect(client.api_key_valid?).to be_falsey
        end
      end
    end
  end

end
