require 'rubygems'
require 'rake/gempackagetask'
require 'rubygems/specification'
require 'date'
require 'spec/rake/spectask'

GEM = "tlscollect"
GEM_VERSION = "0.0.4"
AUTHOR = "Benjamin Black"
EMAIL = "b@b3k.us"
HOMEPAGE = "http://blog.b3k.us"
SUMMARY = "TLS server configuration collection and reporting.  Derived from the TLS Report."

spec = Gem::Specification.new do |s|
  s.name = GEM
  s.version = GEM_VERSION
  s.platform = Gem::Platform::RUBY
  s.has_rdoc = true
  s.summary = SUMMARY
  s.description = s.summary
  s.author = AUTHOR
  s.email = EMAIL
  s.homepage = HOMEPAGE
  
  s.add_dependency "json"
  s.bindir = "bin"
  s.executables = %w(tlscollect)
  
  s.require_path = 'lib'
  s.autorequire = GEM
  s.files = %w(LICENSE README.rdoc Rakefile) + Dir.glob("{lib,bin,spec}/**/*")
end

task :default => :spec

desc "Run specs"
Spec::Rake::SpecTask.new do |t|
  t.spec_files = FileList['spec/**/*_spec.rb']
  t.spec_opts = %w(-fs --color)
end


Rake::GemPackageTask.new(spec) do |pkg|
  pkg.gem_spec = spec
end

desc "install the gem locally"
task :install => [:package] do
  sh %{sudo gem install pkg/#{GEM}-#{GEM_VERSION}}
end

desc "create a gemspec file"
task :make_spec do
  File.open("#{GEM}.gemspec", "w") do |file|
    file.puts spec.to_ruby
  end
end