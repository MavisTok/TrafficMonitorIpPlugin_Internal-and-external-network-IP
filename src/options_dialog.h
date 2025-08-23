#pragma once

#include <windows.h>
#include "plugin_options.h"

// Shows the options dialog; returns true if options changed
bool ShowIpOptionsDialog(HWND hParent, PluginOptions& options);

