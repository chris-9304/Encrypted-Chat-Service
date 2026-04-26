#include <ev/relay/relay_server.h>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <boost/program_options.hpp>
#include <iostream>
#include <memory>

namespace po = boost::program_options;

static std::unique_ptr<ev::relay::RelayServer> g_relay;

BOOL WINAPI CtrlHandler(DWORD fdwCtrlType) {
    if (fdwCtrlType == CTRL_C_EVENT || fdwCtrlType == CTRL_CLOSE_EVENT) {
        std::cout << "\n[ev-relay] Shutting down.\n";
        if (g_relay) g_relay->stop();
        ExitProcess(0);
    }
    return FALSE;
}

int main(int argc, char** argv) {
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCtrlHandler(CtrlHandler, TRUE);

    po::options_description desc("ev-relay options");
    desc.add_options()
        ("help",  "show this help")
        ("port",  po::value<uint16_t>()->default_value(8765),
                  "TCP port to listen on (default: 8765)");

    po::variables_map vm;
    try {
        po::store(po::parse_command_line(argc, argv, desc), vm);
        po::notify(vm);
    } catch (const po::error& e) {
        std::cerr << "Argument error: " << e.what() << "\n";
        return 1;
    }

    if (vm.count("help")) {
        std::cout << "ev-relay 0.4.0 — EncryptiV relay server\n\n" << desc << "\n";
        return 0;
    }

    const uint16_t port = vm["port"].as<uint16_t>();

    g_relay = std::make_unique<ev::relay::RelayServer>(port);
    std::cout << "ev-relay 0.4.0  |  listening on port " << port << "\n"
              << "Press Ctrl+C to stop.\n";

    auto result = g_relay->run();
    if (!result) {
        std::cerr << "[Fatal] " << result.error().message << "\n";
        return 2;
    }
    return 0;
}
