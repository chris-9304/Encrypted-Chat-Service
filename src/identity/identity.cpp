#include "identity.h"

namespace ev::identity {

ev::core::Result<Identity> Identity::generate(const std::string&) {
    return std::unexpected(ev::core::Error{ev::core::ErrorCode::NotImplemented, "M1.1 skeleton", std::nullopt});
}

ev::core::Result<Identity> Identity::load(const ev::core::Path&, const std::string&) {
    return std::unexpected(ev::core::Error{ev::core::ErrorCode::NotImplemented, "M1.1 skeleton", std::nullopt});
}

ev::core::Result<void> Identity::save(const ev::core::Path&) const {
    return std::unexpected(ev::core::Error{ev::core::ErrorCode::NotImplemented, "M1.1 skeleton", std::nullopt});
}

const ev::core::PublicKey& Identity::signing_public_key() const {
    static ev::core::PublicKey dummy;
    return dummy; // M1.1 skeleton
}

const ev::core::PublicKey& Identity::agreement_public_key() const {
    static ev::core::PublicKey dummy;
    return dummy; // M1.1 skeleton
}

ev::core::SafetyNumber Identity::safety_number(const ev::core::PublicKey&) const {
    return ev::core::SafetyNumber{"M1.1 skeleton"}; // M1.1 skeleton
}

} // namespace ev::identity
