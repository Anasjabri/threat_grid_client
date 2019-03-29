require 'logging/url'

describe Url::Util do
  let(:subject) { TestClass.new }
  let(:rate_limit_url) { 'https://sandcastle.threatgrid.com/api/v3/users/some.login/rate-limit' }
  let(:rate_limit_url_with_password) { 'https://username:password@sandcastle.threatgrid.com/api/v3/users/some.login/rate-limit?api_key=some.api.key&oem_user=some.oem.user&oem_key=some.oem.key' }

  context '#sanitize_url' do
    it 'should sanitize url' do
      actual = subject.sanitize(rate_limit_url_with_password)

      expect(actual.include?('username:REDACTED@')).to be_truthy
      expect(actual.include?('api_key=REDACTED')).to be_truthy
      expect(actual.include?('oem_user=REDACTED')).to be_truthy
      expect(actual.include?('oem_key=REDACTED')).to be_truthy
    end

    it 'should handle duplicate params' do
      url = "#{rate_limit_url}?api_key=some.api.key&api_key=some.other.api.key&oem_user=some.oem.user&oem_user=some.other.user&oem_key=some.oem.key&oem_key=some.other.oem.key"
      actual = subject.sanitize(url)

      expect(actual).to end_with '?api_key=REDACTED&oem_user=REDACTED&oem_key=REDACTED'
    end
  end
end

class TestClass
  include Url::Util
end