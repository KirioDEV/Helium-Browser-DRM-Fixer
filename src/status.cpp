#include "fixer.hpp"

namespace fixer {
LocalStatus inspect_local(const Options &options) {
  check_cancelled();
  LocalStatus status;
  try {
    status.target = resolve_target(options);
    if (has_transaction(status.target)) {
      status.state = LocalState::recovery_required;
      status.exit_code = static_cast<int>(Code::recovery);
      status.detail = "Pending recovery: run --restore before installing";
    } else if (!fs::exists(status.target)) {
      status.state = LocalState::missing;
      status.exit_code = static_cast<int>(Code::missing);
      status.detail = "Widevine is missing";
    } else {
      try {
        const auto cdm = read_cdm(installed_cdm_dir(status.target));
        status.version = cdm.version;
        status.state = LocalState::locally_valid;
        status.exit_code = 0;
        status.detail = "Manifest and x86_64 library are locally valid";
      } catch (const Error &error) {
        if (error.code != Code::security) throw;
        status.state = LocalState::locally_invalid;
        status.exit_code = static_cast<int>(Code::security);
        status.detail = error.what();
      }
    }
  } catch (const Error &error) {
    if (error.code == Code::cancelled) throw;
    status.state = LocalState::unavailable;
    status.exit_code = static_cast<int>(error.code);
    status.detail = error.what();
  } catch (const fs::filesystem_error &error) {
    status.state = LocalState::unavailable;
    status.exit_code = static_cast<int>(Code::failure);
    status.detail = error.what();
  }
  check_cancelled();
  return status;
}

Json local_status_json(const LocalStatus &status) {
  const auto state = [&]() {
    switch (status.state) {
      case LocalState::missing:
        return "missing";
      case LocalState::locally_invalid:
        return "locally_invalid";
      case LocalState::locally_valid:
        return "locally_valid";
      case LocalState::recovery_required:
        return "recovery_required";
      case LocalState::unavailable:
        return "unavailable";
    }
    throw Error("Unknown local status", Code::invalid);
  }();
  return Json{{"schema_version", 1},
              {"state", state},
              {"target", status.target.empty() ? Json(nullptr)
                                               : Json(utf8(status.target))},
              {"version",
               status.version.empty() ? Json(nullptr) : Json(status.version)},
              {"detail", status.detail},
              {"exit_code", status.exit_code},
              {"online_version_checked", false},
              {"publisher_integrity_verified", false},
              {"streaming_compatibility_verified", false}};
}
}  // namespace fixer
