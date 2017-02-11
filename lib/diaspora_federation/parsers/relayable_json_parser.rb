module DiasporaFederation
  module Parsers
    class RelayableJsonParser < JsonParser
      def parse_json(json_hash)
        super.push(json_hash["property_order"])
      end

      private

      def from_json_sanity_validation(json_hash)
        super
        raise DeserializationError if json_hash["property_order"].nil?
      end
    end
  end
end
