module DiasporaFederation
  module Parsers
    class JsonParser < BaseParser

      def parse_json(json_hash)
        from_json_sanity_validation(json_hash)
        parse_entity_data(json_hash["entity_data"])
      end

      protected

      def parse_entity_data(entity_data)
        hash = entity_data.map {|key, value|
          property = entity_type.find_property_for_xml_name(key)
          if property
            type = entity_type.class_props[property]
            [property, parse_element_from_value(type, entity_data[key])]
          else
            [key, value]
          end
        }.to_h

        [hash]
      end

      private

      def from_entity_data(type, entity_data)
        type.from_hash(*type.json_parser.parse_entity_data(entity_data))
      end

      def parse_element_from_value(type, value)
        if %i(integer boolean timestamp).include?(type) && !value.is_a?(String)
          value
        elsif type.instance_of?(Symbol)
          parse_string(type, value)
        elsif type.instance_of?(Array)
          return if value.nil?
          raise DeserializationError unless value.respond_to?(:map)
          value.map {|element|
            from_entity_data(type.first, element)
          }
        elsif type.ancestors.include?(Entity)
          from_entity_data(type, value)
        end
      end

      def from_json_sanity_validation(json_hash)
        raise DeserializationError if json_hash["entity_class"].nil? || json_hash["entity_data"].nil?
        assert_parsability_of(json_hash["entity_class"])
      end

      # TODO: documentation
      class DeserializationError < RuntimeError
      end
    end
  end
end
