require 'rspec/core/rake_task'
require 'geminabox-release'

GeminaboxRelease.patch(:host => "https://gemdist.immunet.com")

RSpec::Core::RakeTask.new(:spec)
task default: :spec

task :clean do
  sh "rm -fr pkg"
end
