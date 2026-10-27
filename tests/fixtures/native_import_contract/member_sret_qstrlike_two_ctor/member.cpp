#include "member_abi.h"

class DetectorLike {
public:
    DetectorLike(RefData& first, RefData& second) noexcept
    {
        first.refs = 1;
        second.refs = 1;
        first.tag = 0x51465354u;
        second.tag = 0x51465354u;
        value_.first.d = &first;
        value_.first.data = u"first";
        value_.first.size = 5;
        value_.second.d = &second;
        value_.second.data = u"second";
        value_.second.size = 6;
        value_.marker = 0x123456789ABCDEF0ui64;
    }

    ~DetectorLike() noexcept
    {
        // These two source values are borrowed from static ref cells.  The
        // imported destructors still execute, but must not decrement them.
        value_.first.d = nullptr;
        value_.second.d = nullptr;
    }

    __declspec(dllexport) __declspec(noinline)
    ConfigLike config() const noexcept;

private:
    ConfigLike value_;
};

ConfigLike DetectorLike::config() const noexcept
{
    return ConfigLike(value_.first, value_.second, value_.marker);
}

extern "C" __declspec(dllexport) __declspec(noinline)
int __cdecl xfg_qstrlike_two_invoke()
{
    static RefData first_ref{};
    static RefData second_ref{};
    DetectorLike detector(first_ref, second_ref);
    int live_result_ok = 0;
    {
        ConfigLike result = detector.config();
        live_result_ok = result.first.d == &first_ref
            && result.second.d == &second_ref
            && result.first.size == 5
            && result.second.size == 6
            && result.marker == 0x123456789ABCDEF0ui64
            && first_ref.refs == 2
            && second_ref.refs == 2;
    }
    // The returned aggregate's two imported destructors must restore the
    // borrowed source-cell counts before DetectorLike leaves scope.
    return live_result_ok && first_ref.refs == 1 && second_ref.refs == 1;
}