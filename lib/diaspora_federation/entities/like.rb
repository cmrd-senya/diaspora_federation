module DiasporaFederation
  module Entities
    class Like < Entity
      property :positive
      property :guid
      property :target_type
      property :parent_guid
      property :parent_author_signature
      property :author_signature
      property :diaspora_id, xml_name: :diaspora_handle
    end
  end
end