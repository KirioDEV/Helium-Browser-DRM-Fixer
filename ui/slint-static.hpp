#pragma once

#include <private/slint_config.h>

// Slint 1.18.1 marks its Windows vtable accessors as DLL imports even when
// linking the static runtime. Load its config once, then use direct references.
// Force-include this header for both our code and generated UI translation
// units.
#ifdef _WIN32
#undef SLINT_DLL_IMPORT
#define SLINT_DLL_IMPORT
#endif
