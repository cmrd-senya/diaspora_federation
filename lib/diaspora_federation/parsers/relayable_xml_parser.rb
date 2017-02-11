module DiasporaFederation
  module Parsers
    class RelayableXmlParser < XmlParser
      def parse_xml(*args)
        hash = super[0]
        [hash, hash.keys]
      end
    end
  end
end
