Description = "A F# implementation of the Hawk authentication protocol. Few dependencies. No cruft."

require 'bundler/setup'
require 'albacore'
require 'albacore/tasks/release'
require 'albacore/tasks/versionizer'

Configuration = 'Release'

Albacore::Tasks::Versionizer.new :versioning

task :paket_replace do
  system 'git submodule update --init'
  Dir.chdir 'src/vendor/hawk.js' do
    system 'npm install'
    #system 'npm test'
  end
  sh %{ruby -pi.bak -e "gsub(/module YoLo/, 'module internal Logibit.Hawk.YoLo')" paket-files/haf/YoLo/YoLo.fs}
  sh %{ruby -pi.bak -e "gsub(/namespace Logary.Facade/, 'namespace Logibit.Hawk.Logging')" paket-files/logary/logary/src/Logary.Facade/Facade.fs}
end

desc 'create assembly infos'
asmver_files :assembly_info do |a|
  a.files = FileList['**/*proj'] # optional, will find all projects recursively by default

  a.attributes assembly_description: Description,
               assembly_configuration: Configuration,
               assembly_company: 'Logibit AB',
               assembly_copyright: "(c) 2014 by Henrik Feldt",
               assembly_version: ENV['LONG_VERSION'],
               assembly_file_version: ENV['LONG_VERSION'],
               assembly_informational_version: ENV['BUILD_VERSION']
end

desc 'Perform fast build (warn: doesn\'t d/l deps)'
build :quick_compile do |b|
  b.prop 'Configuration', Configuration
  b.logging = 'detailed'
  b.sln     = 'src/Logibit.Hawk.sln'
end

task :paket_bootstrap do
  system 'tools/paket.bootstrapper.exe', clr_command: true unless File.exists? 'tools/paket.exe'
end

task :paket_restore do
  system 'tools/paket.exe', 'restore', clr_command: true
end

desc 'restore all nugets as per the packages.config files'
task :paket => [:paket_bootstrap, :paket_restore, :paket_replace]

desc 'Perform full build'
build :compile => [:paket, :versioning, :assembly_info] do |b|
  b.prop 'Configuration', Configuration
  b.sln     = 'src/Logibit.Hawk.sln'
end

directory 'build/pkg'

desc 'package nugets - finds all projects and package them'
nugets_pack :create_nugets => ['build/pkg', :compile] do |p|
  p.configuration = Configuration
  p.files   = FileList['src/**/*.{csproj,fsproj,nuspec}'].
    exclude(/[tT]ests/)
  p.out     = 'build/pkg'
  p.exe     = 'packages/NuGet.CommandLine/tools/NuGet.exe'
  p.with_metadata do |m|
    m.description = 'A F# implementation of the Hawk authentication protocol. Few dependencies. No cruft.'
    m.authors     = 'Henrik Feldt, Logibit AB'
    m.project_url = 'https://github.com/logibit/Logibit.Hawk'
    m.tags        = 'fsharp hawk authentication authorization security hawknet'
    m.version     = ENV['NUGET_VERSION']
    m.icon_url    = 'https://raw.githubusercontent.com/logibit/Logibit.Hawk/master/tools/hawk.png'
  end
end

namespace :tests do
  task :hawk do
    system "src/Logibit.Hawk.tests/bin/#{Configuration}/Logibit.Hawk.tests.exe", %w|--sequenced|, clr_command: true
  end

  task :suave do
    system "src/Logibit.Hawk.suave.tests/bin/#{Configuration}/Logibit.Hawk.suave.tests.exe", %w|--sequenced|, clr_command: true
  end

  task :unit => [:hawk, :suave]
end

task :tests => [:compile, :'tests:unit']

task :default => [ :tests, :create_nugets ]

task :ensure_nuget_key do
  raise 'missing env NUGET_KEY value' unless ENV['NUGET_KEY']
end

Albacore::Tasks::Release.new :release,
                             pkg_dir: 'build/pkg',
                             depend_on: [:tests, :create_nugets, :ensure_nuget_key],
                             nuget_exe: 'packages/NuGet.CommandLine/tools/NuGet.exe',
                             api_key: ENV['NUGET_KEY']
