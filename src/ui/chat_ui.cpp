// chat_ui.cpp — Full FTXUI button-driven UI for Cloak.
// All slash-command typing is gone; every action is driven by buttons/menus.

#include <cloak/ui/chat_ui.h>
#include <cloak/app/chat_application.h>

#include <ftxui/component/component.hpp>
#include <ftxui/component/component_options.hpp>
#include <ftxui/component/screen_interactive.hpp>
#include <ftxui/dom/elements.hpp>
#include <ftxui/screen/color.hpp>

#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace cloak::ui {

using namespace ftxui;

ChatUi::ChatUi(cloak::app::ChatApplication& app) : app_(app) {}

void ChatUi::request_shutdown() {
    shutdown_ = true;
}

cloak::core::Result<void> ChatUi::run_main_loop() {
    auto screen = ScreenInteractive::Fullscreen();

    // ── Shared UI state ────────────────────────────────────────────────────────
    std::mutex                                          state_mutex;
    std::vector<cloak::app::ChatApplication::MessageEntry> messages;
    std::vector<cloak::app::ChatApplication::PeerInfo>     peers;
    std::string                                            status_line = "Ready";
    std::string                                            invite_code_str;

    // ── UI control variables ───────────────────────────────────────────────────
    std::string  input_text;
    std::string  join_code_input;
    std::string  direct_host_input;
    std::string  direct_port_input;
    bool         show_invite_modal  = false;
    bool         show_join_modal    = false;
    bool         show_direct_modal  = false;
    bool         invite_generating  = false;
    int          peer_selected      = 0;

    // Peer name list for the Menu component.
    std::vector<std::string> peer_entries;

    // ── Register callbacks (called from background threads) ───────────────────
    app_.set_message_callback([&](std::string from, std::string text, bool is_mine) {
        {
            std::lock_guard lock(state_mutex);
            messages.push_back({std::move(from), std::move(text), "", is_mine});
        }
        screen.PostEvent(Event::Custom);
    });

    app_.set_peer_change_callback([&]() {
        {
            std::lock_guard lock(state_mutex);
            peers = app_.get_peers();
            peer_entries.clear();
            for (const auto& p : peers) {
                std::string label = (p.online ? " \u25cf " : " \u25cb ") + p.name;
                if (p.verified)     label += " \u2713";
                if (p.queued_count) label += " [" + std::to_string(p.queued_count) + "]";
                peer_entries.push_back(label);
            }
            // Clamp selection.
            if (!peers.empty() && peer_selected >= static_cast<int>(peers.size()))
                peer_selected = static_cast<int>(peers.size()) - 1;
        }
        screen.PostEvent(Event::Custom);
    });

    app_.set_system_callback([&](std::string msg) {
        {
            std::lock_guard lock(state_mutex);
            status_line = std::move(msg);
        }
        screen.PostEvent(Event::Custom);
    });

    // Initial peer load (may already have connections from --connect).
    {
        peers = app_.get_peers();
        for (const auto& p : peers) {
            std::string label = (p.online ? " \u25cf " : " \u25cb ") + p.name;
            if (p.verified)     label += " \u2713";
            if (p.queued_count) label += " [" + std::to_string(p.queued_count) + "]";
            peer_entries.push_back(label);
        }
    }

    // ── Helper: post and run task on UI thread ─────────────────────────────────
    auto post_refresh = [&] { screen.PostEvent(Event::Custom); };

    // ── Components ────────────────────────────────────────────────────────────

    // Message input (Enter sends).
    InputOption inp_opt;
    inp_opt.on_enter = [&] {
        if (input_text.empty()) return;
        std::string text = input_text;
        input_text.clear();
        std::thread([&, text]() {
            static_cast<void>(app_.send_text_to_current(text));
        }).detach();
    };
    auto msg_input = Input(&input_text, "Message...", inp_opt);

    // Send button.
    auto send_btn = Button("  Send  ", [&] {
        if (input_text.empty()) return;
        std::string text = input_text;
        input_text.clear();
        std::thread([&, text]() {
            static_cast<void>(app_.send_text_to_current(text));
        }).detach();
    }, ButtonOption::Ascii());

    // Search LAN button — discovery already runs; this refreshes the display.
    auto search_btn = Button(" [\u25ce] Search LAN ", [&] {
        std::thread([&]() {
            std::this_thread::sleep_for(std::chrono::milliseconds(300));
            std::lock_guard lock(state_mutex);
            peers = app_.get_peers();
            peer_entries.clear();
            for (const auto& p : peers) {
                std::string label = (p.online ? " \u25cf " : " \u25cb ") + p.name;
                if (p.verified)     label += " \u2713";
                if (p.queued_count) label += " [" + std::to_string(p.queued_count) + "]";
                peer_entries.push_back(label);
            }
            post_refresh();
        }).detach();
        std::lock_guard lock(state_mutex);
        status_line = "Searching LAN...";
        post_refresh();
    }, ButtonOption::Ascii());

    // Invite Code button.
    auto invite_btn = Button(" [\u2709] Invite Code ", [&] {
        show_invite_modal  = true;
        invite_generating  = true;
        invite_code_str    = "Generating...";
        post_refresh();
        std::thread([&]() {
            auto res = app_.make_invite_code();
            {
                std::lock_guard lock(state_mutex);
                invite_generating = false;
                invite_code_str   = res ? *res : "[Error] " + res.error().message;
                status_line       = res ? "Invite code ready \u2014 share it!" : res.error().message;
            }
            post_refresh();
        }).detach();
    }, ButtonOption::Ascii());

    // Join via Invite Code button.
    auto join_btn = Button(" [\u21aa] Join via Code ", [&] {
        join_code_input   = "";
        show_join_modal   = true;
        post_refresh();
    }, ButtonOption::Ascii());

    // Direct Connect button.
    auto direct_btn = Button(" [\u27a1] Direct Connect ", [&] {
        direct_host_input = "";
        direct_port_input = "";
        show_direct_modal = true;
        post_refresh();
    }, ButtonOption::Ascii());

    // Close invite modal.
    auto close_invite_btn = Button("  Close  ", [&] {
        show_invite_modal = false;
    }, ButtonOption::Ascii());

    // Join modal inputs + buttons.
    InputOption join_opt;
    join_opt.on_enter = [&] { /* handled by Connect button */ };
    auto join_input = Input(&join_code_input, "Paste invite code...", join_opt);

    auto connect_join_btn = Button("  Connect  ", [&] {
        if (join_code_input.empty()) return;
        std::string code = join_code_input;
        show_join_modal  = false;
        join_code_input  = "";
        {
            std::lock_guard lock(state_mutex);
            status_line = "Connecting via invite...";
        }
        post_refresh();
        std::thread([&, code]() {
            auto res = app_.connect_invite(code);
            std::lock_guard lock(state_mutex);
            status_line = res ? "Connected!" : "Connect failed: " + res.error().message;
            post_refresh();
        }).detach();
    }, ButtonOption::Ascii());

    auto cancel_join_btn = Button("  Cancel  ", [&] {
        show_join_modal = false;
    }, ButtonOption::Ascii());

    // Direct connect modal inputs + buttons.
    auto host_input = Input(&direct_host_input, "Host (e.g. 192.168.1.5)");
    auto port_input = Input(&direct_port_input, "Port (e.g. 5000)");

    auto do_direct_btn = Button("  Connect  ", [&] {
        if (direct_host_input.empty() || direct_port_input.empty()) return;
        std::string host = direct_host_input;
        uint16_t    port = 0;
        try { port = static_cast<uint16_t>(std::stoi(direct_port_input)); }
        catch (...) { return; }
        show_direct_modal  = false;
        direct_host_input  = "";
        direct_port_input  = "";
        {
            std::lock_guard lock(state_mutex);
            status_line = "Connecting to " + host + ":" + std::to_string(port) + "...";
        }
        post_refresh();
        std::thread([&, host, port]() {
            auto res = app_.connect_to(host, port);
            std::lock_guard lock(state_mutex);
            status_line = res ? "Connected!" : "Failed: " + res.error().message;
            post_refresh();
        }).detach();
    }, ButtonOption::Ascii());

    auto cancel_direct_btn = Button("  Cancel  ", [&] {
        show_direct_modal = false;
    }, ButtonOption::Ascii());

    // Peer list menu.
    MenuOption menu_opt = MenuOption::Vertical();
    menu_opt.on_change = [&] {
        int sel = peer_selected;
        app_.switch_peer(static_cast<size_t>(sel));
        // Clear log when switching peer (new context).
        std::lock_guard lock(state_mutex);
        messages.clear();
        status_line = peers.empty() ? "Ready" :
                      "Chat with " + peers[static_cast<size_t>(sel)].name;
        post_refresh();
    };
    auto peer_menu = Menu(&peer_entries, &peer_selected, menu_opt);

    // ── Container assembly ────────────────────────────────────────────────────
    // Left panel interactive elements.
    auto left_btns = Container::Vertical({
        search_btn, invite_btn, join_btn, direct_btn,
        peer_menu,
    });

    // Right panel interactive elements.
    auto input_row = Container::Horizontal({msg_input, send_btn});

    // Modal interactive elements.
    auto invite_modal_comp  = Container::Vertical({close_invite_btn});
    auto join_modal_comp    = Container::Vertical({
        join_input,
        Container::Horizontal({connect_join_btn, cancel_join_btn}),
    });
    auto direct_modal_comp  = Container::Vertical({
        host_input, port_input,
        Container::Horizontal({do_direct_btn, cancel_direct_btn}),
    });

    // Route focus to whichever modal is open, else the normal UI.
    auto all_comp = Container::Tab(
        {left_btns, input_row,
         invite_modal_comp, join_modal_comp, direct_modal_comp},
        // Tab index is managed by the renderer below via CatchEvent.
        nullptr
    );

    // ── Master renderer ───────────────────────────────────────────────────────
    auto main_renderer = Renderer(all_comp, [&]() -> Element {

        // Snapshot shared state.
        std::vector<cloak::app::ChatApplication::MessageEntry> msgs_snap;
        std::vector<cloak::app::ChatApplication::PeerInfo>     peers_snap;
        std::string sys_snap;
        std::string invite_snap;
        {
            std::lock_guard lock(state_mutex);
            msgs_snap   = messages;
            peers_snap  = peers;
            sys_snap    = status_line;
            invite_snap = invite_code_str;
        }

        // ── Status bar ────────────────────────────────────────────────────────
        const std::string fp_short = app_.my_fingerprint().substr(0, 12) + "...";
        auto status_bar = hbox({
            text(" " + app_.my_name() + " ") | bold
                | color(Color::Black) | bgcolor(Color::Blue),
            text(" FP: " + fp_short + " ") | color(Color::GrayLight),
            separator(),
            text(" " + std::to_string(peers_snap.size()) + " peer(s) ")
                | color(Color::Cyan),
            separator(),
            text(" " + sys_snap + " ") | color(Color::Green) | flex,
            text(" Cloak 0.4 ") | color(Color::GrayDark),
        });

        // ── Peer list (left panel) ─────────────────────────────────────────────
        Element peer_panel;
        {
            Elements peer_section;
            peer_section.push_back(
                text(" Peers ") | bold | color(Color::Yellow));
            peer_section.push_back(separator());
            peer_section.push_back(search_btn->Render());
            peer_section.push_back(invite_btn->Render());
            peer_section.push_back(join_btn->Render());
            peer_section.push_back(direct_btn->Render());
            peer_section.push_back(separator());

            if (peer_entries.empty()) {
                peer_section.push_back(
                    text(" No peers found ") | color(Color::GrayDark) | italic);
                peer_section.push_back(
                    text(" Click Search LAN ") | color(Color::GrayDark));
                peer_section.push_back(
                    text(" or use Invite Code ") | color(Color::GrayDark));
            } else {
                peer_section.push_back(text(" Select peer: ") | color(Color::GrayLight));
                peer_section.push_back(peer_menu->Render() | flex);
            }

            peer_panel = vbox(peer_section)
                | border
                | size(WIDTH, EQUAL, 24);
        }

        // ── Message area (right panel) ─────────────────────────────────────────
        Elements msg_elems;
        if (msgs_snap.empty()) {
            msg_elems.push_back(
                text("  No messages yet.") | color(Color::GrayDark));
            if (peers_snap.empty()) {
                msg_elems.push_back(
                    text("  Use the buttons on the left to find or connect to a peer.")
                    | color(Color::GrayDark));
            } else {
                msg_elems.push_back(
                    text("  Type a message below and press Send.")
                    | color(Color::GrayDark));
            }
        } else {
            std::string current_peer_name =
                (peer_selected >= 0 &&
                 peer_selected < static_cast<int>(peers_snap.size()))
                ? peers_snap[static_cast<size_t>(peer_selected)].name
                : "";

            for (const auto& m : msgs_snap) {
                if (m.is_mine) {
                    msg_elems.push_back(
                        hbox({
                            filler(),
                            text(" " + m.sender + ": " + m.text + " ")
                                | color(Color::Cyan)
                                | bgcolor(Color::NavyBlue),
                        }));
                } else {
                    msg_elems.push_back(
                        hbox({
                            text(" " + m.sender + ": " + m.text + " ")
                                | color(Color::White),
                            filler(),
                        }));
                }
            }
        }

        auto msgs_box  = vbox(msg_elems) | flex | frame;
        auto right_panel = vbox({
            msgs_box | flex,
            separator(),
            hbox({
                msg_input->Render() | flex,
                send_btn->Render(),
            }),
        }) | flex | border;

        // ── Main body ──────────────────────────────────────────────────────────
        auto body     = hbox({peer_panel, right_panel});
        auto main_doc = vbox({status_bar, body | flex});

        // ── Invite code modal ──────────────────────────────────────────────────
        if (show_invite_modal) {
            auto modal_doc = vbox({
                text(" Invite Code ") | bold | center | color(Color::Yellow),
                separator(),
                text("Share this code with the peer you want to connect to:")
                    | color(Color::GrayLight),
                separator(),
                paragraph(invite_snap)
                    | color(Color::Green) | bold | center,
                separator(),
                invite_generating
                    ? (text("  Waiting for peer to connect...") | color(Color::GrayDark))
                    : (text("  Relay host is waiting for the peer.") | color(Color::GrayDark)),
                separator(),
                close_invite_btn->Render() | center,
            }) | border | size(WIDTH, EQUAL, 62) | center | clear_under;

            return dbox({main_doc | dim, modal_doc});
        }

        // ── Join via invite code modal ─────────────────────────────────────────
        if (show_join_modal) {
            auto modal_doc = vbox({
                text(" Join via Invite Code ") | bold | center | color(Color::Yellow),
                separator(),
                text("Paste the code you received from your peer:")
                    | color(Color::GrayLight),
                separator(),
                join_input->Render() | border,
                separator(),
                hbox({
                    connect_join_btn->Render(),
                    text("  "),
                    cancel_join_btn->Render(),
                }) | center,
            }) | border | size(WIDTH, EQUAL, 62) | center | clear_under;

            return dbox({main_doc | dim, modal_doc});
        }

        // ── Direct connect modal ───────────────────────────────────────────────
        if (show_direct_modal) {
            auto modal_doc = vbox({
                text(" Direct Connect ") | bold | center | color(Color::Yellow),
                separator(),
                text("Host / IP:") | color(Color::GrayLight),
                host_input->Render() | border,
                text("Port:") | color(Color::GrayLight),
                port_input->Render() | border,
                separator(),
                hbox({
                    do_direct_btn->Render(),
                    text("  "),
                    cancel_direct_btn->Render(),
                }) | center,
            }) | border | size(WIDTH, EQUAL, 50) | center | clear_under;

            return dbox({main_doc | dim, modal_doc});
        }

        return main_doc;
    });

    // ── Escape closes modals; Ctrl-Q quits ────────────────────────────────────
    auto with_keys = CatchEvent(main_renderer, [&](Event event) -> bool {
        if (event == Event::Escape) {
            if (show_invite_modal) { show_invite_modal = false; return true; }
            if (show_join_modal)   { show_join_modal   = false; return true; }
            if (show_direct_modal) { show_direct_modal = false; return true; }
        }
        // Ctrl-Q to quit.
        if (event == Event::Character('\x11')) {
            screen.ExitLoopClosure()();
            return true;
        }
        return false;
    });

    screen.Loop(with_keys);
    return {};
}

} // namespace cloak::ui
