module DiasporaFederation
  describe Entities::StatusMessage do
    let(:photo1) { FactoryGirl.build(:photo_entity, author: alice.diaspora_id) }
    let(:photo2) { FactoryGirl.build(:photo_entity, author: alice.diaspora_id) }
    let(:location) { FactoryGirl.build(:location_entity) }
    let(:data) {
      FactoryGirl.attributes_for(:status_message_entity).merge(
        author:                alice.diaspora_id,
        photos:                [photo1, photo2],
        location:              location,
        poll:                  nil,
        event:                 nil,
        provider_display_name: "something"
      )
    }

    let(:xml) { <<-XML }
<status_message>
  <diaspora_handle>#{data[:author]}</diaspora_handle>
  <guid>#{data[:guid]}</guid>
  <created_at>#{data[:created_at].utc.iso8601}</created_at>
  <provider_display_name>#{data[:provider_display_name]}</provider_display_name>
  <raw_message>#{data[:text]}</raw_message>
  <photo>
    <guid>#{photo1.guid}</guid>
    <diaspora_handle>#{photo1.author}</diaspora_handle>
    <public>#{photo1.public}</public>
    <created_at>#{photo1.created_at.utc.iso8601}</created_at>
    <remote_photo_path>#{photo1.remote_photo_path}</remote_photo_path>
    <remote_photo_name>#{photo1.remote_photo_name}</remote_photo_name>
    <text>#{photo1.text}</text>
    <status_message_guid>#{photo1.status_message_guid}</status_message_guid>
    <height>#{photo1.height}</height>
    <width>#{photo1.width}</width>
  </photo>
  <photo>
    <guid>#{photo2.guid}</guid>
    <diaspora_handle>#{photo2.author}</diaspora_handle>
    <public>#{photo2.public}</public>
    <created_at>#{photo2.created_at.utc.iso8601}</created_at>
    <remote_photo_path>#{photo2.remote_photo_path}</remote_photo_path>
    <remote_photo_name>#{photo2.remote_photo_name}</remote_photo_name>
    <text>#{photo2.text}</text>
    <status_message_guid>#{photo2.status_message_guid}</status_message_guid>
    <height>#{photo2.height}</height>
    <width>#{photo2.width}</width>
  </photo>
  <location>
    <address>#{location.address}</address>
    <lat>#{location.lat}</lat>
    <lng>#{location.lng}</lng>
  </location>
  <public>#{data[:public]}</public>
</status_message>
XML

    let(:string) { "StatusMessage:#{data[:guid]}" }

    it_behaves_like "an Entity subclass"

    it_behaves_like "an XML Entity"

    include_examples "#to_json output matches JSON schema"

    context "default values" do
      it "uses default values" do
        minimal_xml = <<-XML
<status_message>
  <author>#{data[:author]}</author>
  <guid>#{data[:guid]}</guid>
  <created_at>#{data[:created_at]}</created_at>
  <text>#{data[:text]}</text>
</status_message>
XML

        parsed_instance = DiasporaFederation::Salmon::XmlPayload.unpack(Nokogiri::XML::Document.parse(minimal_xml).root)
        expect(parsed_instance.photos).to eq([])
        expect(parsed_instance.location).to be_nil
        expect(parsed_instance.poll).to be_nil
        expect(parsed_instance.public).to be_falsey
        expect(parsed_instance.provider_display_name).to be_nil
      end
    end

    context "nested entities" do
      it "validates that nested photos have the same author" do
        invalid_data = data.merge(author: FactoryGirl.generate(:diaspora_id))
        expect {
          Entities::StatusMessage.new(invalid_data)
        }.to raise_error Entity::ValidationError
      end
    end
  end
end
