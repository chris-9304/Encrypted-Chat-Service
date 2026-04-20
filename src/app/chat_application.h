#pragma once

#include <ev/core/error.h>

namespace ev::app {

class ChatApplication {
public:
    ChatApplication();
    ~ChatApplication();

    ev::core::Result<void> initialize();
    ev::core::Result<void> run();
    void shutdown();

private:
    // TODO(M1.x): Subsystem orchestration objects
};

} // namespace ev::app
