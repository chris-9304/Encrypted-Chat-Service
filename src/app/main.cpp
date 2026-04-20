#include <iostream>
#include <boost/program_options.hpp>
#include <ev/app/chat_application.h>
#include <windows.h>

namespace po = boost::program_options;
std::unique_ptr<ev::app::ChatApplication> app;

BOOL WINAPI CtrlHandler(DWORD fdwCtrlType) {
    if (fdwCtrlType == CTRL_C_EVENT) {
        std::cout << "\n[System] Shutting down...\n";
        app.reset();
        exit(0);
    }
    return FALSE;
}

int main(int argc, char** argv) {
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCtrlHandler(CtrlHandler, TRUE);

    po::options_description desc("Allowed options");
    desc.add_options()
        ("help", "produce help message")
        ("name", po::value<std::string>(), "display name")
        ("port", po::value<uint16_t>()->default_value(0), "listening port")
        ("discovery", po::value<std::string>()->default_value("loopback"), "mdns or loopback")
        ("connect", po::value<std::string>()->default_value(""), "host:port to explicitly connect to");

    po::variables_map vm;
    po::store(po::parse_command_line(argc, argv, desc), vm);
    po::notify(vm);

    if (vm.count("help") || !vm.count("name")) {
        std::cout << desc << "\n";
        return 1;
    }

    std::string name = vm["name"].as<std::string>();
    uint16_t port = vm["port"].as<uint16_t>();
    std::string connect = vm["connect"].as<std::string>();

    std::cout << "ev-chat 0.1.0 (Demo Mode)\n";

    app = std::make_unique<ev::app::ChatApplication>(name, port, connect);
    app->run();

    return 0;
}
