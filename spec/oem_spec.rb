require 'spec_helper'
require 'threat_grid_client'

describe ThreatGridClient::API do
  let(:oem_name  )     { 'oem_name'  }
  let(:oem_key   )     { 'oem_key'   }
  let(:api_host  )     { 'api_host'  }
  let(:response)       { { api_key: "key"} }
  let(:str_response)   { "{\"api_key\":\"key\"}" }

  before { ThreatGridClient.init() }

  describe 'OEM Client' do
    let!(:oem_client)    { ThreatGridClient.create({oem_name: oem_name, oem_key: oem_key, api_host: api_host}) }

    context "#create_organization" do
      it 'raises error when params are blank' do
        expect { oem_client.create_organization({login: ""}) }.to raise_error ArgumentError
      end

      it 'creates a new organization' do
        login = "login"
        email = "email"
        organization_name = "org_name"
        day = Time.now.strftime("%Y-%m-%d")
        params = "email=email&login=login&name=name&organization_name=org_name&oem_name=#{oem_name}&day=#{day}"
        url_hash = Digest::SHA256.hexdigest "#{oem_key}##{params}"
        payload  =  "#{params}&url_hash=#{url_hash}"
        expect(RestClient::Request).to receive(:execute).with(method: :post,
                                          url: oem_client.api_url_v2("oem/users"),
                                          payload: payload,
                                          open_timeout: 60, timeout: 90, ssl_version: :TLSv1_2,
                                          headers: {content_type: "application/x-www-form-urlencoded"}) { str_response }

        ret = oem_client.create_organization({login: "login", name: 'name', email: "email", organization_name: "org_name"})
        expect(ret).to eq response
      end

    end
  end
end
