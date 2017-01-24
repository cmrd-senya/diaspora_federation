module DiasporaFederation
  # +Entity+ is the base class for all other objects used to encapsulate data
  # for federation messages in the diaspora* network.
  # Entity fields are specified using a simple {PropertiesDSL DSL} as part of
  # the class definition.
  #
  # Any entity also provides the means to serialize itself and all nested
  # entities to XML (for deserialization from XML to +Entity+ instances, see
  # {Salmon::XmlPayload}).
  #
  # @abstract Subclass and specify properties to implement various entities.
  #
  # @example Entity subclass definition
  #   class MyEntity < Entity
  #     property :prop
  #     property :optional, default: false
  #     property :dynamic_default, default: -> { Time.now }
  #     property :another_prop, xml_name: :another_name
  #     entity :nested, NestedEntity
  #     entity :multiple, [OtherEntity]
  #   end
  #
  # @example Entity instantiation
  #   nentity = NestedEntity.new
  #   oe1 = OtherEntity.new
  #   oe2 = OtherEntity.new
  #
  #   entity = MyEntity.new(prop: 'some property',
  #                         nested: nentity,
  #                         multiple: [oe1, oe2])
  #
  # @note Entity properties can only be set during initialization, after that the
  #   entity instance becomes frozen and must not be modified anymore. Instances
  #   are intended to be immutable data containers, only.
  class Entity
    extend PropertiesDSL
    include Logging

    # Invalid XML characters
    # @see https://www.w3.org/TR/REC-xml/#charsets "Extensible Markup Language (XML) 1.0"
    INVALID_XML_REGEX = /[^\x09\x0A\x0D\x20-\uD7FF\uE000-\uFFFD\u{10000}-\u{10FFFF}]/

    # Initializes the Entity with the given attribute hash and freezes the created
    # instance it returns.
    #
    # After creation, the entity is validated against a Validator, if one is defined.
    # The Validator needs to be in the {DiasporaFederation::Validators} namespace and
    # named like "<EntityName>Validator". Only valid entities can be created.
    #
    # @see DiasporaFederation::Validators
    #
    # @note Attributes not defined as part of the class definition ({PropertiesDSL#property},
    #       {PropertiesDSL#entity}) get discarded silently.
    #
    # @param [Hash] data entity data
    # @return [Entity] new instance
    def initialize(data)
      logger.debug "create entity #{self.class} with data: #{data}"
      raise ArgumentError, "expected a Hash" unless data.is_a?(Hash)

      entity_data = self.class.resolv_aliases(data)
      validate_missing_props(entity_data)

      self.class.default_values.merge(entity_data).each do |name, value|
        instance_variable_set("@#{name}", instantiate_nested(name, nilify(value))) if setable?(name, value)
      end

      freeze
      validate
    end

    # Returns a Hash representing this Entity (attributes => values).
    # Nested entities are also converted to a Hash.
    # @return [Hash] entity data (mostly equal to the hash used for initialization).
    def to_h
      enriched_properties.map {|key, value|
        type = self.class.class_props[key]

        if type.instance_of?(Symbol) || value.nil?
          [key, value]
        elsif type.instance_of?(Class)
          [key, value.to_h]
        elsif type.instance_of?(Array)
          [key, value.map(&:to_h)]
        end
      }.to_h
    end

    # Returns the XML representation for this entity constructed out of
    # {http://www.rubydoc.info/gems/nokogiri/Nokogiri/XML/Element Nokogiri::XML::Element}s
    #
    # @see Nokogiri::XML::Node.to_xml
    # @see XmlPayload#pack
    #
    # @return [Nokogiri::XML::Element] root element containing properties as child elements
    def to_xml
      doc = Nokogiri::XML::DocumentFragment.new(Nokogiri::XML::Document.new)
      Nokogiri::XML::Element.new(self.class.entity_name, doc).tap do |root_element|
        xml_elements.each do |name, value|
          add_property_to_xml(doc, root_element, name, value)
        end
      end
    end

    # Construct a new instance of the given Entity and populate the properties
    # with the attributes found in the XML.
    # Works recursively on nested Entities and Arrays thereof.
    #
    # @param [Nokogiri::XML::Element] root_node xml nodes
    # @return [Entity] instance
    def self.from_xml(root_node)
      from_xml_sanity_validation(root_node)

      populate_entity {|name, type|
        parse_element_from_node(name, type, root_node)
      }
    end

    # Makes an underscored, lowercase form of the class name
    #
    # @see .entity_class
    #
    # @return [String] entity name
    def self.entity_name
      name.rpartition("::").last.tap do |word|
        word.gsub!(/(.)([A-Z])/, '\1_\2')
        word.downcase!
      end
    end

    # Transform the given String from the lowercase underscored version to a
    # camelized variant and returns the Class constant.
    #
    # @see .entity_name
    #
    # @param [String] entity_name "snake_case" class name
    # @return [Class] entity class
    def self.entity_class(entity_name)
      raise InvalidEntityName, "'#{entity_name}' is invalid" unless entity_name =~ /\A[a-z]*(_[a-z]*)*\z/
      class_name = entity_name.sub(/\A[a-z]/, &:upcase)
      class_name.gsub!(/_([a-z])/) { Regexp.last_match[1].upcase }

      raise UnknownEntity, "'#{class_name}' not found" unless Entities.const_defined?(class_name)

      Entities.const_get(class_name)
    end

    # @return [String] string representation of this object
    def to_s
      "#{self.class.name.rpartition('::').last}#{":#{guid}" if respond_to?(:guid)}"
    end

    # Might be used to modify entity JSON object just before serialization
    # @return [Hash] Returns a hash that is equal by structure to the entity in JSON format
    def to_json_hash
      {
        entity_class: self.class.entity_name,
        entity_data:  json_data
      }
    end

    # @return [String] Renders the entity to the JSON representation
    def to_json
      to_json_hash.to_json
    end

    # Deserialization of an Entity object from JSON format
    # @param [String] json
    # @return [Entity] instance
    def self.from_json(json)
      from_json_hash(JSON.parse(json))
    end

    # Creates an instance of self, filling it with data from a provided hash of properties.
    #
    # The hash format is described as following:
    # 1) Properties of the hash are representation of the entity's class properties
    # 2) Possible values of the hash properties depend on the types of the entity's class properties
    # 3) Basic properties, such as booleans, strings, integers and timestamps can be represented by a string value
    # 4) Beside that, integers and booleans can be represented by integer and boolean values respectively
    # 5) Nested hashes are allowed to represent nested entities. Nested hashes follow the same format . Thus, the nested
    # hashes are instantiated as Entities of the expected type using .from_hash method with the nested hash as an
    # argument.
    # 6) Arrays are allowed to represent array of nested entities. They are instantiated the same way as in point 5.
    # The difference is that they are mapped to the array of entities instead.
    # @param [Hash] properties_hash A hash of the expected format
    # @return [Entity] instance
    def self.from_hash(properties_hash)
      return if properties_hash.nil?

      populate_entity {|name, type|
        parse_element_from_value(type, properties_hash[name.to_s])
      }
    end

    # Creates an instance of self by parsing a hash in the format of JSON serialized object (which usually means
    # data from a parsed JSON input).
    def self.from_json_hash(json_hash)
      from_json_sanity_validation(json_hash)
      from_hash(*extract_json_hash(json_hash))
    end

    private

    def validate_missing_props(entity_data)
      missing_props = self.class.missing_props(entity_data)
      raise ValidationError, "missing required properties: #{missing_props.join(', ')}" unless missing_props.empty?
    end

    def setable?(name, val)
      type = self.class.class_props[name]
      return false if type.nil? # property undefined

      setable_property?(type, val) || setable_nested?(type, val) || setable_multi?(type, val)
    end

    def setable_property?(type, val)
      setable_string?(type, val) || type == :timestamp && val.is_a?(Time)
    end

    def setable_string?(type, val)
      %i(string integer boolean).include?(type) && val.respond_to?(:to_s)
    end

    def setable_nested?(type, val)
      type.instance_of?(Class) && type.ancestors.include?(Entity) && (val.is_a?(Entity) || val.is_a?(Hash))
    end

    def setable_multi?(type, val)
      type.instance_of?(Array) && val.instance_of?(Array) &&
        (val.all? {|v| v.instance_of?(type.first) } || val.all? {|v| v.instance_of?(Hash) })
    end

    def nilify(value)
      return nil if value.respond_to?(:empty?) && value.empty? && !value.instance_of?(Array)
      value
    end

    def instantiate_nested(name, value)
      if value.instance_of?(Array)
        return value unless value.first.instance_of?(Hash)
        value.map {|hash| self.class.class_props[name].first.new(hash) }
      elsif value.instance_of?(Hash)
        self.class.class_props[name].new(value)
      else
        value
      end
    end

    def validate
      validator_name = "#{self.class.name.split('::').last}Validator"
      return unless Validators.const_defined? validator_name

      validator_class = Validators.const_get validator_name
      validator = validator_class.new self
      raise ValidationError, error_message(validator) unless validator.valid?
    end

    def error_message(validator)
      errors = validator.errors.map do |prop, rule|
        "property: #{prop}, value: #{public_send(prop).inspect}, rule: #{rule[:rule]}, with params: #{rule[:params]}"
      end
      "Failed validation for properties: #{errors.join(' | ')}"
    end

    # @return [Hash] hash with all properties
    def properties
      self.class.class_props.keys.each_with_object({}) do |prop, hash|
        hash[prop] = public_send(prop)
      end
    end

    def normalized_properties
      properties.map {|name, value| [name, normalize_property(name, value)] }.to_h
    end

    def normalize_property(name, value)
      case self.class.class_props[name]
      when :string
        value.to_s
      when :timestamp
        value.nil? ? "" : value.utc.iso8601
      else
        value
      end
    end

    # default: nothing to enrich
    def enriched_properties
      normalized_properties
    end

    # default: no special order
    def xml_elements
      enriched_properties
    end

    def add_property_to_xml(doc, root_element, name, value)
      if [String, TrueClass, FalseClass, Integer].any? {|c| value.is_a? c }
        root_element << simple_node(doc, name, value.to_s)
      else
        # call #to_xml for each item and append to root
        [*value].compact.each do |item|
          child = item.to_xml
          root_element << child if child
        end
      end
    end

    # Create simple node, fill it with text and append to root
    def simple_node(doc, name, value)
      xml_name = self.class.xml_names[name]
      Nokogiri::XML::Element.new(xml_name ? xml_name.to_s : name, doc).tap do |node|
        node.content = value.gsub(INVALID_XML_REGEX, "\uFFFD") unless value.empty?
      end
    end

    def json_data
      enriched_properties.map {|key, value|
        type = self.class.class_props[key]

        if type.instance_of?(Class) && value.respond_to?(:to_json_hash)
          entity_data = value.to_json_hash[:entity_data]
          [key, entity_data] unless entity_data.nil?
        else
          [key, value]
        end
      }.compact.to_h
    end

    # @return [Entity] instance
    private_class_method def self.populate_entity(&parser)
      new(entity_data(&parser))
    end

    # @yield
    # @return [Hash] entity data
    private_class_method def self.entity_data
      class_props.map {|name, type|
        value = yield(name, type)
        [name, value] unless value.nil?
      }.compact.to_h
    end

    private_class_method def self.parse_element_from_value(type, value)
      if %i(integer boolean).include?(type) && !value.is_a?(String)
        value
      elsif type.instance_of?(Symbol)
        parse_string(type, value)
      elsif type.instance_of?(Array)
        raise DeserializationError unless value.respond_to?(:map)
        value.map {|element|
          type.first.from_hash(element)
        }
      elsif type.ancestors.include?(Entity)
        type.from_hash(value)
      end
    end

    private_class_method def self.extract_json_hash(json_hash)
      [json_hash["entity_data"]]
    end

    # @param [String] name property name to parse
    # @param [Class, Symbol] type target type to parse
    # @param [Nokogiri::XML::Element] root_node XML node to parse
    # @return [Object] parsed data
    private_class_method def self.parse_element_from_node(name, type, root_node)
      if type.instance_of?(Symbol)
        parse_string_from_node(name, type, root_node)
      elsif type.instance_of?(Array)
        parse_array_from_node(type.first, root_node)
      elsif type.ancestors.include?(Entity)
        parse_entity_from_node(type, root_node)
      end
    end

    # Create simple entry in data hash
    #
    # @param [String] name xml tag to parse
    # @param [Class, Symbol] type target type to parse
    # @param [Nokogiri::XML::Element] root_node XML root_node to parse
    # @return [String] data
    private_class_method def self.parse_string_from_node(name, type, root_node)
      node = root_node.xpath(name.to_s)
      node = root_node.xpath(xml_names[name].to_s) if node.empty?
      parse_string(type, node.first.text) if node.any?
    end

    # @param [Symbol] type target type to parse
    # @param [String] text data as string
    # @return [String, Boolean, Integer, Time] data
    private_class_method def self.parse_string(type, text)
      case type
      when :timestamp
        begin
          Time.parse(text).utc
        rescue
          nil
        end
      when :integer
        text.to_i if text =~ /\A\d+\z/
      when :boolean
        return true if text =~ /\A(true|t|yes|y|1)\z/i
        false if text =~ /\A(false|f|no|n|0)\z/i
      else
        text
      end
    end

    # Create an entry in the data hash for the nested entity
    #
    # @param [Class] type target type to parse
    # @param [Nokogiri::XML::Element] root_node XML node to parse
    # @return [Entity] parsed child entity
    private_class_method def self.parse_entity_from_node(type, root_node)
      node = root_node.xpath(type.entity_name)
      type.from_xml(node.first) if node.any? && node.first.children.any?
    end

    # Collect all nested children of that type and create an array in the data hash
    #
    # @param [Class] type target type to parse
    # @param [Nokogiri::XML::Element] root_node XML node to parse
    # @return [Array<Entity>] array with parsed child entities
    private_class_method def self.parse_array_from_node(type, root_node)
      node = root_node.xpath(type.entity_name)
      node.select {|child| child.children.any? }.map {|child| type.from_xml(child) } unless node.empty?
    end

    private_class_method def self.assert_parsability_of(entity_class)
      raise InvalidRootNode, "'#{entity_class}' can't be parsed by #{name}" unless entity_class == entity_name
    end

    private_class_method def self.from_xml_sanity_validation(root_node)
      raise ArgumentError, "only Nokogiri::XML::Element allowed" unless root_node.instance_of?(Nokogiri::XML::Element)
      assert_parsability_of(root_node.name)
    end

    private_class_method def self.from_json_sanity_validation(json_hash)
      raise DeserializationError if json_hash["entity_class"].nil? || json_hash["entity_data"].nil?
      assert_parsability_of(json_hash["entity_class"])
    end

    # Raised, if entity is not valid
    class ValidationError < RuntimeError
    end

    # Raised, if the root node doesn't match the class name
    class InvalidRootNode < RuntimeError
    end

    # Raised, if the entity name in the XML is invalid
    class InvalidEntityName < RuntimeError
    end

    # Raised, if the entity contained within the XML cannot be mapped to a
    # defined {Entity} subclass.
    class UnknownEntity < RuntimeError
    end

    # TODO: documentation
    class DeserializationError < RuntimeError
    end
  end
end
