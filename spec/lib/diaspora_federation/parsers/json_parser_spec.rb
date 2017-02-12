module DiasporaFederation
  describe Parsers::JsonParser do
    describe ".parse_json" do
      let(:entity_class) { Entities::TestComplexEntity }
      let(:json_parser) { Parsers::JsonParser.new(entity_class) }

      it "raises error when the entity class doesn't match the entity_class property" do
        expect {
          json_parser.parse_json(JSON.parse(<<-JSON
{
  "entity_class": "unknown_entity",
  "entity_data": {}
}
JSON
          ))
        }.to raise_error DiasporaFederation::Parsers::BaseParser::InvalidRootNode,
                         "'unknown_entity' can't be parsed by #{entity_class}"
      end

      include_examples ".parse_json parse error", "entity_class is missing", '{"entity_data": {}}'
      include_examples ".parse_json parse error", "entity_data is missing", '{"entity_class": "test_complex_entity"}'

      xit "calls .from_hash with the entity_data of json hash" do
        expect(Entity).to receive(:from_hash).with(property: "value")
        Entity.from_json(
          "entity_class" => "entity",
          "entity_data"  => {
            property: "value"
          }
        )
      end
    end
  end
end
