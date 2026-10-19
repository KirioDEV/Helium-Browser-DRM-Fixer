#pragma once

// The GUI updater is compiled separately. Identity is fixed by the application,
// never selected by untrusted release metadata or a command-line switch.
namespace fixer {
#ifdef FIXER_GUI_APP
inline constexpr char app_update_id[] = "helium-drm-fixer-gui";
inline constexpr char app_update_state_name[] = ".helium-gui-app-update";
inline constexpr char app_update_jobs_name[] = ".helium-gui-app-update-jobs";
#ifdef _WIN32
inline constexpr char app_update_binary[] = "helium_drm_fixer_gui.exe";
#else
inline constexpr char app_update_binary[] = "helium_drm_fixer_gui.AppImage";
#endif
#else
inline constexpr char app_update_id[] = "helium-drm-fixer-cpp";
inline constexpr char app_update_state_name[] = ".helium-app-update";
inline constexpr char app_update_jobs_name[] = ".helium-app-update-jobs";
#ifdef _WIN32
inline constexpr char app_update_binary[] = "helium_drm_fixer.exe";
#else
inline constexpr char app_update_binary[] = "helium_drm_fixer";
#endif
#endif
}  // namespace fixer
