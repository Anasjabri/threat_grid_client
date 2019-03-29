# coding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'threat_grid_client/version'

Gem::Specification.new do |spec|
  spec.name          = 'threat_grid_client'
  spec.version       = ThreatGridClient::VERSION
  spec.authors       = ['Cisco Systems Inc.']

  spec.description   = %q{ThreatGrid REST API Client}
  spec.summary       = %q{ThreatGrid REST API Client}
  spec.homepage      = 'https://github.com/Cisco-AMP/threat_grid_client'
  spec.license       = "MIT"

  spec.files         = `git ls-files -z`.split("\x0").reject { |f| f.match(%r{^(test|spec|features)/}) }
  spec.executables   = spec.files.grep(%r{^bin/}).map{ |f| File.basename(f) }
  spec.test_files    = spec.files.grep(%r{^(test|spec|features)/})
  spec.require_paths = ['lib']

  spec.add_runtime_dependency 'rest-client', '~> 2.0.1'
  spec.add_runtime_dependency 'railties',    '>= 4.2.5.1'

  spec.add_development_dependency 'rspec',  '~> 3.4.0'
  spec.add_development_dependency 'rake',   '~> 10.4.2'
  spec.add_development_dependency 'geminabox-release'
end
