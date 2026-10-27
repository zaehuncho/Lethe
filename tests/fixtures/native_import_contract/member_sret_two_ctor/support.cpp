#include "member_abi.h"

StringLike::StringLike(StringLike const& other) noexcept
    : words{other.words[0], other.words[1], other.words[2]} {}
