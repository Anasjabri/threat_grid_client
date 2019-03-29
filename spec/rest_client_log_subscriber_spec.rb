require 'logging/rest_client_log_subscriber'

describe  RestClient::LogSubscriber do
  let(:rate_limit_url) { 'https://sandcastle.threatgrid.com/api/v3/users/some.login/rate-limit' }
end