#pragma once

#include "wia_com_worker.h"

#include <memory>

namespace just_scanner {

// Constructs the production WIA 2.0 backend. Merely constructing it performs
// no COM or device work; open/execute/close must run inside WiaComWorker.
std::shared_ptr<IWiaWorkerBackend> make_windows_wia2_backend();

}  // namespace just_scanner
