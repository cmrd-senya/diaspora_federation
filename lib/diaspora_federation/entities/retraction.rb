module DiasporaFederation
  module Entities
    # This entity represents a claim of deletion of a previously federated entity.
    #
    # @see Validators::RetractionValidator
    class Retraction < Entity
      # @!attribute [r] author
      #   The diaspora* ID of the person who deletes the entity
      #   @see Person#author
      #   @return [String] diaspora* ID
      property :author, :string, xml_name: :diaspora_handle

      # @!attribute [r] target_guid
      #   Guid of the entity to be deleted
      #   @return [String] target guid
      property :target_guid, :string, xml_name: :post_guid

      # @!attribute [r] target_type
      #   A string describing the type of the target
      #   @return [String] target type
      property :target_type, :string, xml_name: :type

      # @!attribute [r] target
      #   Target entity
      #   @return [RelatedEntity] target entity
      entity :target, Entities::RelatedEntity

      def sender_valid?(sender)
        case target_type
        when "Comment", "Like", "PollParticipation"
          sender == target.author || sender == target.parent.author
        else
          sender == target.author
        end
      end

      # @return [String] string representation of this object
      def to_s
        "Retraction:#{target_type}:#{target_guid}"
      end

      # @return [Retraction] instance
      private_class_method def self.populate_entity(&block)
        entity_data = entity_data(&block)
        entity_data[:target] = fetch_target(entity_data[:target_type], entity_data[:target_guid])
        new(entity_data)
      end

      private_class_method def self.fetch_target(target_type, target_guid)
        DiasporaFederation.callbacks.trigger(:fetch_related_entity, target_type, target_guid).tap do |target|
          raise TargetNotFound, "not found: #{target_type}:#{target_guid}" unless target
        end
      end

      # Raised, if the target of the {Retraction} was not found.
      class TargetNotFound < RuntimeError
      end
    end
  end
end
