module DiasporaFederation
  module Parsers
    class BaseParser
      def initialize(entity_type)
        @entity_type = entity_type
      end

      private

      # @param [Symbol] type target type to parse
      # @param [String] text data as string
      # @return [String, Boolean, Integer, Time] data
      def parse_string(type, text)
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

      def assert_parsability_of(entity_class)
        return if entity_class == entity_type.entity_name
        raise InvalidRootNode, "'#{entity_class}' can't be parsed by #{entity_type.name}"
      end

      attr_reader :entity_type

      def class_properties
        entity_type.class_props
      end

      # Raised, if the root node doesn't match the class name
      class InvalidRootNode < RuntimeError
      end
    end
  end
end
