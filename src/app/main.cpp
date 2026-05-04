#include <cloak/app/chat_application.h>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <boost/program_options.hpp>
#include <iostream>
#include <memory>
#include <optional>
#include <string>

namespace po = boost::program_options;

static std::unique_ptr<cloak::app::ChatApplication> g_app;

BOOL WINAPI CtrlHandler(DWORD fdwCtrlType) {
    if (fdwCtrlType == CTRL_C_EVENT || fdwCtrlType == CTRL_CLOSE_EVENT) {
        std::cout << "\n[System] Shutting down...\n";
        g_app.reset();
        ExitProcess(0);
    }
    return FALSE;
}

static void print_banner() {
    std::cout <<
        "==========================================================\n"
        "  Cloak 0.4.0  --  End-to-End Encrypted P2P Messenger\n"
        "==========================================================\n\n";
}

static void print_help(const po::options_description& desc) {
    print_banner();
    std::cout << desc << "\n";
    std::cout
        << "Examples:\n"
        << "  cloak.exe --name Alice\n"
        << "  cloak.exe --name Alice --port 5000\n"
        << "  cloak.exe --name Bob --connect 192.168.1.5:5000\n"
        << "  cloak.exe --name Alice --relay relay.example.com:8765\n\n"
        << "Commands (once connected):\n"
        << "  /peers                list connected peers\n"
        << "  /switch <name>        switch active peer\n"
        << "  /send <file>          send a file\n"
        << "  /make-invite          generate an invite code (relay mode)\n"
        << "  /connect-invite <code> connect via invite code\n"
        << "  /help                 show all commands\n\n";
}

int main(int argc, char** argv) {
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCtrlHandler(CtrlHandler, TRUE);

    po::options_description desc("Options");
    desc.add_options()
        ("help",      "show this help message")
        ("name",      po::value<std::string>(),
                      "your display name")
        ("port",      po::value<uint16_t>()->default_value(0),
                      "listen port (0 = auto)")
        ("connect",   po::value<std::string>()->default_value(""),
                      "host:port to connect to on startup")
        ("discovery", po::value<std::string>()->default_value("loopback"),
                      "discovery mode: loopback (default)")
        ("relay",     po::value<std::string>()->default_value(""),
                      "relay server host:port (for /make-invite)");

    po::variables_map vm;
    try {
        po::store(po::parse_command_line(argc, argv, desc), vm);
        po::notify(vm);
    } catch (const po::error& e) {
        std::cerr << "Error: " << e.what() << "\n\n";
        print_help(desc);
        std::cout << "Press Enter to exit...";
        std::cin.get();
        return 1;
    }

    if (vm.count("help")) {
        print_help(desc);
        std::cout << "Press Enter to exit...";
        std::cin.get();
        return 0;
    }

    // ── If no --name was given, prompt interactively ──────────────────────────
    // This allows launching from Start Menu / double-click without arguments.
    std::string name;
    if (vm.count("name")) {
        name = vm["name"].as<std::string>();
    } else {
        print_banner();
        std::cout << "  Your display name will be shown to people you connect with.\n\n";
        std::cout << "  Enter your display name: ";
        std::getline(std::cin, name);
        if (name.empty()) {
            std::cerr << "\nError: display name cannot be empty.\n";
            std::cout << "Press Enter to exit...";
            std::cin.get();
            return 1;
        }
        std::cout << "\n";
    }

    const auto port    = vm["port"].as<uint16_t>();
    const auto connect = vm["connect"].as<std::string>();
    const auto relay   = vm["relay"].as<std::string>();

    // Parse optional relay endpoint.
    std::optional<cloak::core::Endpoint> relay_ep;
    if (!relay.empty()) {
        const auto colon = relay.rfind(':');
        if (colon == std::string::npos) {
            std::cerr << "Error: --relay must be host:port\n";
            return 1;
        }
        try {
            cloak::core::Endpoint ep;
            ep.address = relay.substr(0, colon);
            ep.port    = static_cast<uint16_t>(std::stoi(relay.substr(colon + 1)));
            relay_ep   = ep;
        } catch (...) {
            std::cerr << "Error: invalid --relay port number\n";
            return 1;
        }
    }

    std::cout << "  Starting as \"" << name << "\"";
    if (port)    std::cout << "  |  port " << port;
    if (relay_ep) std::cout << "  |  relay " << relay_ep->address << ":" << relay_ep->port;
    std::cout << "\n\n";

    std::cout << "  Type a message and press Enter to send.\n"
              << "  Type /help to see all commands.\n"
              << "  Press Ctrl+C to quit.\n\n";

    g_app = std::make_unique<cloak::app::ChatApplication>(
        name, port, connect, relay_ep);

    auto result = g_app->run();
    if (!result) {
        std::cerr << "\n[Fatal] " << result.error().message << "\n";
        std::cout << "\nPress Enter to exit...";
        std::cin.get();
        return 2;
    }
    return 0;
}
