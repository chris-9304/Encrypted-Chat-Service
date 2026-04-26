#include <cloak/app/chat_application.h>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <boost/program_options.hpp>
#include <iostream>
#include <memory>
#include <optional>

namespace po = boost::program_options;

static std::unique_ptr<cloak::app::ChatApplication> g_app;

BOOL WINAPI CtrlHandler(DWORD fdwCtrlType) {
    if (fdwCtrlType == CTRL_C_EVENT || fdwCtrlType == CTRL_CLOSE_EVENT) {
        std::cout << "\n[System] Shutting down…\n";
        g_app.reset();
        ExitProcess(0);
    }
    return FALSE;
}

int main(int argc, char** argv) {
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCtrlHandler(CtrlHandler, TRUE);

    po::options_description desc("cloak options");
    desc.add_options()
        ("help",      "show this help")
        ("name",      po::value<std::string>(),
                      "display name (required)")
        ("port",      po::value<uint16_t>()->default_value(0),
                      "listen port (0 = ephemeral)")
        ("connect",   po::value<std::string>()->default_value(""),
                      "host:port to connect to on startup")
        ("discovery", po::value<std::string>()->default_value("loopback"),
                      "discovery mode: loopback (default)")
        ("relay",     po::value<std::string>()->default_value(""),
                      "relay server address (host:port) for /make-invite");

    po::variables_map vm;
    try {
        po::store(po::parse_command_line(argc, argv, desc), vm);
        po::notify(vm);
    } catch (const po::error& e) {
        std::cerr << "Argument error: " << e.what() << "\n";
        return 1;
    }

    if (vm.count("help") || !vm.count("name")) {
        std::cout << "Cloak 0.4.0 — End-to-End Encrypted P2P Messenger\n\n" << desc << "\n";
        return vm.count("help") ? 0 : 1;
    }

    const auto name    = vm["name"].as<std::string>();
    const auto port    = vm["port"].as<uint16_t>();
    const auto connect = vm["connect"].as<std::string>();
    const auto relay   = vm["relay"].as<std::string>();

    // Parse optional relay endpoint.
    std::optional<cloak::core::Endpoint> relay_ep;
    if (!relay.empty()) {
        const auto colon = relay.rfind(':');
        if (colon == std::string::npos) {
            std::cerr << "Argument error: --relay must be host:port\n";
            return 1;
        }
        try {
            cloak::core::Endpoint ep;
            ep.address = relay.substr(0, colon);
            ep.port    = static_cast<uint16_t>(std::stoi(relay.substr(colon + 1)));
            relay_ep   = ep;
        } catch (...) {
            std::cerr << "Argument error: invalid --relay port\n";
            return 1;
        }
    }

    std::cout << "Cloak 0.4.0  |  name=" << name
              << "  port=" << port;
    if (relay_ep)
        std::cout << "  relay=" << relay_ep->address << ":" << relay_ep->port;
    std::cout << "\n\n";

    g_app = std::make_unique<cloak::app::ChatApplication>(
        name, port, connect, relay_ep);

    auto result = g_app->run();
    if (!result) {
        std::cerr << "[Fatal] " << result.error().message << "\n";
        return 2;
    }
    return 0;
}
