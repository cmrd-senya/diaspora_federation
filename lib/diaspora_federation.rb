require "diaspora_federation/engine"
require "diaspora_federation/logging"

require "diaspora_federation/web_finger"

##
# diaspora* federation rails engine
module DiasporaFederation
  extend Logging

  class << self
    ##
    # the pod url
    #
    # Example:
    #   config.server_uri = URI("http://localhost:3000/")
    # or
    #   config.server_uri = AppConfig.pod_uri
    attr_accessor :server_uri

    ##
    # the class to use as +Person+
    #
    # Example:
    #   config.person_class = Person.to_s
    #
    # This class must have the following methods:
    #
    # *find_local_by_diaspora_handle*
    # This should return a +Person+, which is on this pod and the account is not closed.
    #
    # *find_local_by_guid*
    # This should return a +Person+, which is on this pod and the account is not closed.
    #
    # *webfinger_hash*
    # This should return a +Hash+ with the following information:
    #   {
    #     acct_uri:    "acct:user@server.example",
    #     alias_url:   "https://server.example/people/0123456789abcdef",
    #     hcard_url:   "https://server.example/hcard/users/0123456789abcdef",
    #     seed_url:    "https://server.example/",
    #     profile_url: "https://server.example/u/user",
    #     atom_url:    "https://server.example/public/user.atom",
    #     salmon_url:  "https://server.example/receive/users/0123456789abcdef",
    #     guid:        "0123456789abcdef",
    #     pubkey:      "-----BEGIN PUBLIC KEY-----\nABCDEF==\n-----END PUBLIC KEY-----"
    #   }
    #
    # *hcard_profile_hash*
    # This should return a +Hash+ with the following information:
    #   {
    #     guid:             "0123456789abcdef",
    #     nickname:         "user",
    #     full_name:        "User Name",
    #     url:              "https://server.example/",
    #     photo_large_url:  "https://server.example/uploads/f.jpg",
    #     photo_medium_url: "https://server.example/uploads/m.jpg",
    #     photo_small_url:  "https://server.example/uploads/s.jpg",
    #     pubkey:           "-----BEGIN PUBLIC KEY-----\nABCDEF==\n-----END PUBLIC KEY-----",
    #     searchable:       true,
    #     first_name:       "User",
    #     last_name:        "Name"
    #   }
    attr_accessor :person_class
    def person_class
      const_get(@person_class)
    end

    ##
    # configure the federation engine
    #
    #   DiasporaFederation.configure do |config|
    #     config.server_uri = "http://localhost:3000/"
    #   end
    def configure
      yield self
    end

    ##
    # validates if the engine is configured correctly
    #
    # called from after_initialize
    # @raise [ConfigurationError] if the configuration is incomplete or invalid
    def validate_config
      configuration_error "missing server_uri" unless @server_uri.respond_to? :host
      validate_class(@person_class, "person_class", %i(
        find_local_by_diaspora_handle
        find_local_by_guid
        diaspora_handle
        alias_url
        hcard_url
        seed_url
        profile_url
        atom_url
        salmon_url
        guid
        public_key
        hcard_profile_hash
      ))
      logger.info "successfully configured the federation engine"
    end

    private

    def validate_class(klass, name, methods)
      configuration_error "missing #{name}" unless klass
      entity = const_get(klass)

      return logger.warn "table for #{entity} doesn't exist, skip validation" unless entity.table_exists?

      methods.each {|method| entity_respond_to?(entity, name, method) }
    end

    def entity_respond_to?(entity, name, method)
      valid = entity.respond_to?(method) || entity.column_names.include?(method.to_s) || entity.method_defined?(method)
      configuration_error "the configured class #{entity} for #{name} doesn't respond to #{method}" unless valid
    end

    def configuration_error(message)
      logger.fatal("diaspora federation configuration error: #{message}")
      raise ConfigurationError, message
    end
  end

  # raised, if the engine is not configured correctly
  class ConfigurationError < RuntimeError
  end
end
