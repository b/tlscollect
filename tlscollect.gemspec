require 'rubygems'
require 'rubygems/specification'

GEM = "tlscollect"
GEM_VERSION = "0.0.2"
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
  s.files = %w(LICENSE README.rdoc Rakefile) + Dir.glob("{lib,bin,spec}/**/*")
end
