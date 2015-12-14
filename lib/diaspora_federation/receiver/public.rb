module DiasporaFederation
  class Receiver
    # Receiver::Public is used to recieve public messages, which are not addressed to a specific user, unencrypted
    # and packed using Salmon::Slap
    class Public < self
      protected

      def slap
        @salmon ||= Salmon::Slap.from_xml(@salmon_xml)
      end
    end
  end
end
