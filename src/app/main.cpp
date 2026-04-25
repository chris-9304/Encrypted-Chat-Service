#include <ev/app/chat_application.h>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <boost/program_options.hpp>
#include <iostream>
#include <memory>

namespace po = boost::program_options;

static std::unique_ptr<ev::app::ChatApplication> g_app;

BOOL WINAPI CtrlHandler(DWORD fdwCtrlType) {
    if (fdwCtrlType == CTRL_C_EVENT || fdwCtrlType == CTRL_CLOSE_EVENT) {
        std::cout << "\n[System] Shutting down…\n";
        g_app.reset();
        ExitProcess(0);
    }
    return FALSE;
}

int main(int argc, char** argv) {
    // UTF-8 console output on Windows.
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCtrlHandler(CtrlHandler, TRUE);

    po::options_description desc("ev-chat options");
    desc.add_options()
        ("help",      "show this help")
        ("name",      po::value<std::string>(),              "display name (required)")
        ("port",      po::value<uint16_t>()->default_value(0), "listen port (0 = ephemeral)")
        ("connect",   po::value<std::string>()->default_value(""),
                      "host:port to connect to on startup")
        ("discovery", po::value<std::string>()->default_value("loopback"),
                      "discovery mode: loopback (default)");

    po::variables_map vm;
    try {
        po::store(po::parse_command_line(argc, argv, desc), vm);
        po::notify(vm);
    } catch (const po::error& e) {
        std::cerr << "Argument error: " << e.what() << "\n";
        return 1;
    }

    if (vm.count("help") || !vm.count("name")) {
        std::cout << "ev-chat 0.2.0 (Phase 2 — Double Ratchet)\n\n" << desc << "\n";
        return vm.count("help") ? 0 : 1;
    }

    const auto name    = vm["name"].as<std::string>();
    const auto port    = vm["port"].as<uint16_t>();
    const auto connect = vm["connect"].as<std::string>();

    std::cout << "ev-chat 0.2.0  |  name=" << name
              << "  port=" << port << "\n\n";

    g_app = std::make_unique<ev::app::ChatApplication>(name, port, connect);

    auto result = g_app->run();
    if (!result) {
        std::cerr << "[Fatal] " << result.error().message << "\n";
        return 2;
    }
    return 0;
}
