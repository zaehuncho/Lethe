#include "member_abi.h"

#include <intrin.h>

#pragma intrinsic(_InterlockedIncrement)
#pragma intrinsic(_InterlockedDecrement)

QStrLike::QStrLike(QStrLike const& other) noexcept
    : d(other.d), data(other.data), size(other.size)
{
    if (d != nullptr) {
        _InterlockedIncrement(&d->refs);
    }
}

QStrLike::~QStrLike() noexcept
{
    if (d != nullptr) {
        _InterlockedDecrement(&d->refs);
    }
}