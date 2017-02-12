unless ENV["NO_COVERAGE"] == "true"
  require "simplecov"
  require "simplecov-rcov"
  SimpleCov.formatters = [
    SimpleCov::Formatter::HTMLFormatter,
    SimpleCov::Formatter::RcovFormatter
  ]
  SimpleCov.start do
    add_filter "lib/diaspora_federation/logging.rb"
    add_filter "spec"
    add_filter "test"
  end
end

ENV["RAILS_ENV"] ||= "test"
require File.join(File.dirname(__FILE__), "..", "test", "dummy", "config", "environment")

require "rspec/rails"
require "webmock/rspec"
require "rspec/json_expectations"


# load factory girl factories
require "factories"

# load test entities
require "entities"

# some helper methods

def alice
  @alice ||= Person.find_by(diaspora_id: "alice@localhost:3000")
end

def bob
  @bob ||= Person.find_by(diaspora_id: "bob@localhost:3000")
end

def expect_callback(*opts)
  expect(DiasporaFederation.callbacks).to receive(:trigger).with(*opts)
end

def add_signatures(hash, klass=described_class)
  properties = klass.new(hash).send(:enriched_properties)
  hash[:author_signature] = properties[:author_signature]
  hash[:parent_author_signature] = properties[:parent_author_signature]
end

# Requires supporting files with custom matchers and macros, etc,
# in ./support/ and its subdirectories.
fixture_builder_file = "#{File.dirname(__FILE__)}/support/fixture_builder.rb"
support_files = Dir["#{File.dirname(__FILE__)}/support/**/*.rb"] - [fixture_builder_file]
support_files.each {|f| require f }
require fixture_builder_file

RSpec.configure do |config|
  config.include JSON::SchemaMatchers
  config.json_schemas[:entity_schema] = "app/schemas/federation_entities.json"

  config.example_status_persistence_file_path = "spec/rspec-persistance.txt"

  config.infer_spec_type_from_file_location!

  config.render_views

  config.expect_with :rspec do |expect_config|
    expect_config.syntax = :expect
  end

  config.include FactoryGirl::Syntax::Methods
  config.use_transactional_fixtures = true

  # load fixtures
  config.fixture_path = "#{::Rails.root}/test/fixtures"
  config.global_fixtures = :all

  config.filter_run_excluding rails4: true if Rails::VERSION::MAJOR == 5

  # whitelist codeclimate.com so test coverage can be reported
  config.after(:suite) do
    WebMock.disable_net_connect!(allow: "codeclimate.com")
  end

  config.mock_with :rspec do |mocks|
    # Prevents you from mocking or stubbing a method that does not exist on
    # a real object. This is generally recommended, and will default to
    # `true` in RSpec 4.
    mocks.verify_partial_doubles = true
  end

  # Many RSpec users commonly either run the entire suite or an individual
  # file, and it's useful to allow more verbose output when running an
  # individual spec file.
  if config.files_to_run.one?
    # Use the documentation formatter for detailed output,
    # unless a formatter has already been configured
    # (e.g. via a command-line flag).
    config.default_formatter = "doc"
  end

  # Print the 10 slowest examples and example groups at the
  # end of the spec run, to help surface which specs are running
  # particularly slow.
  config.profile_examples = 10

  # Run specs in random order to surface order dependencies. If you find an
  # order dependency and want to debug it, you can fix the order by providing
  # the seed, which is printed after each run.
  #     --seed 1234
  config.order = :random

  # Seed global randomization in this process using the `--seed` CLI option.
  # Setting this allows you to use `--seed` to deterministically reproduce
  # test failures related to randomization by passing the same `--seed` value
  # as the one that triggered the failure.
  Kernel.srand config.seed
end
