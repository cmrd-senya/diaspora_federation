module DiasporaFederation
  module Parsers
    class XmlParser < BaseParser
      def parse_xml(root_node)
        from_xml_sanity_validation(root_node)

        hash = root_node.element_children.map {|child|
          xml_name = child.name
          property = entity_type.find_property_for_xml_name(xml_name)
          if property
            type = class_properties[property]
            value = parse_element_from_node(xml_name, type, root_node)
            [property, value] unless value.nil?
          else
            [xml_name, child.text]
          end
        }.compact.to_h

        [hash]
      end

      private

      # @param [String] name property name to parse
      # @param [Class, Symbol] type target type to parse
      # @param [Nokogiri::XML::Element] root_node XML node to parse
      # @return [Object] parsed data
      def parse_element_from_node(name, type, root_node)
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
      def parse_string_from_node(name, type, root_node)
        node = root_node.xpath(name.to_s)
        node = root_node.xpath(xml_names[name].to_s) if node.empty?
        parse_string(type, node.first.text) if node.any?
      end

      # Create an entry in the data hash for the nested entity
      #
      # @param [Class] type target type to parse
      # @param [Nokogiri::XML::Element] root_node XML node to parse
      # @return [Entity] parsed child entity
      def parse_entity_from_node(type, root_node)
        node = root_node.xpath(type.entity_name)
        type.from_xml(node.first) if node.any? && node.first.children.any?
      end

      # Collect all nested children of that type and create an array in the data hash
      #
      # @param [Class] type target type to parse
      # @param [Nokogiri::XML::Element] root_node XML node to parse
      # @return [Array<Entity>] array with parsed child entities
      def parse_array_from_node(type, root_node)
        node = root_node.xpath(type.entity_name)
        node.select {|child| child.children.any? }.map {|child| type.from_xml(child) } unless node.empty?
      end

      def from_xml_sanity_validation(root_node)
        raise ArgumentError, "only Nokogiri::XML::Element allowed" unless root_node.instance_of?(Nokogiri::XML::Element)
        assert_parsability_of(root_node.name)
      end
    end
  end
end
