# ThreatGridClient

Ruby Client to connect to ThreatGrid API.

## Installation

Add this line to your application's Gemfile:

    gem 'threat_grid_client'

And then execute:

    $ bundle

Or install it yourself as:

    $ gem install threat_grid_client

## Usage

```ruby
# Initializer

ThreatGridClient.init(
  open_timeout: 15.seconds,
  timeout: 25.seconds,
  logger: logger
)

# OEM client

ThreatGridClient.create( oem_name: "<YOUR OEM NAME>",
                         oem_key:  "<YOUR OEM API KEY>",
                         api_host: "API Host"
                        )
oem_client.create_organization( email: "<USER EMAIL>",
                                name: "<USER NAME>",
                                login: "<USER LOGIN>",
                                organization_name: "<ORG NAME>"
                            )


# Admin API Client
ThreatGridClient.create( login:  "<ADMIN API LOGIN>",
                        api_key:  "<ADMIN API KEY>",
                        api_host: "API Host"
                       )

admin_api_client.user_details("<LOGIN NAME>")

# Samples API Client


samples_client = ThreatGridClient.create(
        api_key: "<API KEY>",
        login: "<LOGIN>",
        api_host: "<HOST>"
      )

#submit sample

file = File.open("/path/to/file", "rb")
sample_id = samples_client.submit_sample(file, vm: 'win10')[:data][:id]
sample = samples_client.sample(sample_id)

#check status
state = sample[:data][:state] # succ | unknown | fail

#artifacts
artifacts = samples_client.artifacts(sample_id)[:data][:items]

#Indicators
iocs = samples_client.iocs(sample_id)

#find by SHA-256
samples = samples_client.samples_by_sha(limit: <limit>,
                                        offset: <offset>,
                                        sha256: "<SHA-256>",
                                        org_only: true, # true | false
      )

#top submissions by the org
samples = samples_client.top_submissions(
        period_start: 1.week.ago,
        period_end: Time.now,
        limit: 10,
        org_only: true,
        sort_by: 'threat',
        sort_order: 'desc',
        threatscore: 'high,medium,low'
      )
```

## Development

After checking out the repo, run `bin/setup` to install dependencies. Then, run `bin/rspec` or `bin/rake` to run the tests.

## Contributing

1. Fork it
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'Added some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create new Pull Request

## License

The gem is available as open source under the terms of the [MIT License](https://opensource.org/licenses/MIT).
