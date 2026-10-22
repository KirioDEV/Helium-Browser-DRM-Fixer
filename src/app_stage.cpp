#include "app_update.hpp"
#include "directory.hpp"

namespace fixer {
fs::path stage_app_package(const AppPackageManifest& manifest, std::span<const unsigned char> package,
                           const fs::path& parent) {
    // No filesystem mutation until every compressed and expanded byte is checked.
    const auto files = unpack_app_package(manifest, package);
    require(parent.is_absolute(), "App staging parent must be absolute");
    const Directory owner(parent);  // The parent must already exist.
    create_private_dir(parent);     // Validate its ownership/private permissions.
    owner.verify_location();
    check_cancelled();
    const auto id = random_id();
    const auto partial = "app-update-" + id + ".partial";
    const auto ready = "app-update-" + id + ".ready";
    owner.create_private(partial, true);
    const auto staging = owner.child(partial);
    Json expected = Json::object();
    for (const auto& file : files) {
        check_cancelled();
        auto directory = staging;
        std::size_t start = 0;
        for (auto slash = file.path.find('/'); slash != std::string::npos; slash = file.path.find('/', start)) {
            const auto component = file.path.substr(start, slash - start);
            directory.create_private(component);
            directory = directory.child(component);
            start = slash + 1;
        }
        directory.write(file.path.substr(start), file.bytes, file.executable);
        directory.sync();
        expected[file.path] = sha256(file.bytes);
    }
    check_cancelled();
    require(directory_inventory(staging) == expected, "Staged app inventory failed read-back verification");
    staging.sync();
    staging.verify_location();
    owner.verify_location();
    check_cancelled();
    // Rename never replaces another entry. Do not report cancellation after this
    // publication point; installation still needs fresh signature/file
    // validation.
    owner.rename(partial, owner, ready);
    return parent / from_utf8(ready);
}
}  // namespace fixer
