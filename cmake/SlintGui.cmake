# Pinned HTTPS archives; override Slint's transitive Git-based declaration.
set(CORROSION_URL "https://codeload.github.com/corrosion-rs/corrosion/tar.gz/refs/tags/v0.6.1")
set(SLINT_URL "https://codeload.github.com/slint-ui/slint/tar.gz/refs/tags/v1.18.1")
if(EXISTS "${CMAKE_SOURCE_DIR}/.deps/corrosion-0.6.1.tar.gz")
    set(CORROSION_URL "${CMAKE_SOURCE_DIR}/.deps/corrosion-0.6.1.tar.gz")
endif()
if(EXISTS "${CMAKE_SOURCE_DIR}/.deps/slint-1.18.1.tar.gz")
    set(SLINT_URL "${CMAKE_SOURCE_DIR}/.deps/slint-1.18.1.tar.gz")
endif()
FetchContent_Declare(Corrosion URL "${CORROSION_URL}"
    URL_HASH SHA256=e9e95b1ee2bad52681f347993fb1a5af5cce458c5ce8a2636c9e476e4babf8e3)

# A small desktop runtime: no Qt, Skia, interpreter, tray or remote tooling.
set(BUILD_SHARED_LIBS OFF)
set(SLINT_FEATURE_INTERPRETER OFF CACHE BOOL "" FORCE)
set(SLINT_FEATURE_BACKEND_QT OFF CACHE BOOL "" FORCE)
set(SLINT_FEATURE_RENDERER_SKIA OFF CACHE BOOL "" FORCE)
set(SLINT_FEATURE_RENDERER_FEMTOVG OFF CACHE BOOL "" FORCE)
set(SLINT_FEATURE_RENDERER_SOFTWARE ON CACHE BOOL "" FORCE)
set(SLINT_FEATURE_SYSTEM_TRAY OFF CACHE BOOL "" FORCE)
set(SLINT_FEATURE_TESTING OFF CACHE BOOL "" FORCE)
set(SLINT_STYLE "fluent" CACHE STRING "Slint widget style")
FetchContent_Declare(Slint URL "${SLINT_URL}"
    URL_HASH SHA256=fe485305ed303215e76c04918ee9aefbffbe229f18f979098ec36c7fa1dab28b
    SOURCE_SUBDIR api/cpp)
FetchContent_MakeAvailable(Slint)
corrosion_set_cargo_flags(slint_cpp --locked)
corrosion_set_cargo_flags(slint-compiler --locked)
if(MSVC)
    corrosion_add_target_rustflags(slint_cpp "-Ctarget-feature=+crt-static")
endif()

add_executable(helium_drm_fixer_gui ui/main.cpp)
target_link_libraries(helium_drm_fixer_gui PRIVATE fixer_core Slint::Slint)
slint_target_sources(helium_drm_fixer_gui ui/app-window.slint)
set_target_properties(helium_drm_fixer_gui PROPERTIES
    WIN32_EXECUTABLE TRUE
    SLINT_EMBED_RESOURCES embed-files)
if(WIN32)
    target_link_libraries(Slint INTERFACE imm32 uxtheme)
endif()
if(MSVC)
    target_compile_options(helium_drm_fixer_gui PRIVATE /W4 /permissive- /utf-8)
    target_compile_options(helium_drm_fixer_gui PRIVATE "$<$<COMPILE_LANGUAGE:CXX>:/FI${CMAKE_SOURCE_DIR}/ui/slint-static.hpp>")
    target_link_options(helium_drm_fixer_gui PRIVATE /ENTRY:mainCRTStartup)
elseif(MINGW)
    target_compile_options(helium_drm_fixer_gui PRIVATE "$<$<COMPILE_LANGUAGE:CXX>:-include${CMAKE_SOURCE_DIR}/ui/slint-static.hpp>")
    target_compile_options(helium_drm_fixer_gui PRIVATE "$<$<COMPILE_LANGUAGE:CXX>:-mcrtdll=ucrt>")
    target_link_options(helium_drm_fixer_gui PRIVATE -mcrtdll=ucrt -static -static-libgcc -static-libstdc++)
    # Use one allocator family throughout the static MinGW runtime. Resolving
    # malloc/free from MSVCRT but realloc from UCRT corrupts pthread's cache.
    # UCRT itself is supplied by Windows 11.
    target_link_libraries(helium_drm_fixer_gui PRIVATE
        "-Wl,--start-group" mingw32 mingwex pthread ucrt "-Wl,--end-group")
endif()
# This prototype is deliberately not installed into signed app-update packages.
