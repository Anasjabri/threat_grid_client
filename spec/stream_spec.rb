require 'spec_helper'

describe ThreatGridClient::Stream do
  describe '#stringify_headers' do
    let(:headers) { 
      {:accept=>"*/*; q=0.5, application/xml", :accept_encoding=>"gzip, deflate"}
    }
    it 'returns a capitalized string of headers' do
      stream = ThreatGridClient::Stream.new({url: 'some_url', method: 'get'})
      expect(stream.stringify_headers(headers)).to eq({"Accept"=>", ", "Accept-Encoding"=>"gzip, deflate"})
    end
  end
end