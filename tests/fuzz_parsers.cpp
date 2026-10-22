#include <cstddef>
#include <cstdint>

#include "fixer.hpp"

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    if (!size || size > 65536)
        return 0;
    const auto bytes = std::span<const unsigned char>(data + 1, size - 1);
    const std::string text(reinterpret_cast<const char*>(bytes.data()), bytes.size());
    try {
        switch (data[0] % 6) {
            case 0:
                (void)fixer::validate_entry(text);
                break;
            case 1:
                (void)fixer::version_parts(text);
                break;
            case 2:
                (void)fixer::parse_json(text);
                break;
            case 3:
                (void)fixer::verify_crx(bytes);
                break;
            case 4:
                (void)fixer::extract_zip(bytes);
                break;
            case 5:
                (void)fixer::parse_release(text);
                break;
        }
    } catch (const std::exception&) {
    }
    return 0;
}
