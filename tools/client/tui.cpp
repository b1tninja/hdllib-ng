#include "tui.hpp"

#include "repl.hpp"
#include "recipes.hpp"
#include "util.hpp"

#include <cstdio>
#include <cstring>
#include <deque>
#include <string>
#include <vector>

#if defined(HDL_HAS_TUI)
#ifdef MOUSE_MOVED
#undef MOUSE_MOVED
#endif
#include <curses.h>
#ifdef MOUSE_MOVED
/* keep PDCurses definition for keypad/mouse; Win32 name unused here */
#endif
#endif

#define WIN32_LEAN_AND_MEAN
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>

namespace hdlcli {
namespace {

#if defined(HDL_HAS_TUI)

void PushLog(std::deque<std::wstring>* log, const std::wstring& w) {
    log->push_back(w);
    while (log->size() > 200) {
        log->pop_front();
    }
}

void MvAddClipped(int y, int x, int max_w, const std::wstring& s) {
    if (max_w <= 0) {
        return;
    }
    if (static_cast<int>(s.size()) <= max_w) {
        mvaddnwstr(y, x, s.c_str(), static_cast<int>(s.size()));
        return;
    }
    mvaddnwstr(y, x, s.c_str(), max_w);
}

void Draw(ControllerState& st, uint32_t pid, const std::deque<std::wstring>& log,
          const std::wstring& input, int focus) {
    erase();
    const int rows = LINES;
    const int cols = COLS;
    wchar_t header[512];
    swprintf_s(header, L"hdlclient TUI  pid=%u  session=%llu  store=%ls", pid,
               static_cast<unsigned long long>(st.discover_session), st.store_path.c_str());
    MvAddClipped(0, 0, cols, header);
    mvhline(1, 0, ACS_HLINE, cols);

    const int right_w = cols / 3;
    const int left_w = cols - right_w - 1;
    const int body_top = 2;
    const int body_bot = rows - 3;
    const int body_h = body_bot - body_top + 1;

    int start = static_cast<int>(log.size()) - body_h;
    if (start < 0) {
        start = 0;
    }
    for (int i = 0; i < body_h && start + i < static_cast<int>(log.size()); ++i) {
        MvAddClipped(body_top + i, 0, left_w - 1, log[static_cast<size_t>(start + i)]);
    }
    mvvline(body_top, left_w, ACS_VLINE, body_h);

    MvAddClipped(body_top, left_w + 1, right_w - 2, L"Interests");
    int yi = body_top + 1;
    for (const auto& in : st.store.interests) {
        if (yi > body_bot) {
            break;
        }
        wchar_t tags[16] = {};
        size_t ti = 0;
        for (const auto& loc : in.locators) {
            if (ti + 1 >= sizeof(tags) / sizeof(tags[0])) {
                break;
            }
            wchar_t t = L'?';
            switch (loc.type) {
            case Locator::Pattern:
                t = L'P';
                break;
            case Locator::Path:
                t = L'A';
                break;
            case Locator::Export:
                t = L'E';
                break;
            case Locator::Import:
                t = L'I';
                break;
            case Locator::Cave:
                t = L'C';
                break;
            case Locator::Stub:
                t = L'S';
                break;
            case Locator::Patch:
                t = L'X';
                break;
            }
            tags[ti++] = t;
        }
        tags[ti] = 0;
        wchar_t line[256];
        swprintf_s(line, L"%ls [%ls]", Utf8ToWide(in.name).c_str(), tags);
        MvAddClipped(yi++, left_w + 1, right_w - 2, line);
    }

    mvhline(rows - 2, 0, ACS_HLINE, cols);
    MvAddClipped(rows - 2, 0, cols,
                 L"q quit  s/L save/load  r reval  a/c/p/t/x recipes  n session  z stabilize  "
                 L"Enter cmd");
    if (focus) {
        std::wstring prompt = L"> ";
        prompt += input;
        MvAddClipped(rows - 1, 0, cols, prompt);
    } else {
        MvAddClipped(rows - 1, 0, cols, L"(keys or Enter for command)");
    }
    refresh();
}

bool IsEnterKey(wint_t wch, int get_rc) {
    if (wch == L'\n' || wch == L'\r') {
        return true;
    }
#ifdef KEY_ENTER
    if (get_rc == KEY_CODE_YES && wch == KEY_ENTER) {
        return true;
    }
#endif
    return false;
}

bool IsBackspaceKey(wint_t wch, int get_rc) {
    if (wch == 127 || wch == 8) {
        return true;
    }
    if (get_rc == KEY_CODE_YES && wch == KEY_BACKSPACE) {
        return true;
    }
    return false;
}

#endif

}  // namespace

int RunTui(uint32_t pid, PipeClient& client, const wchar_t* store_path_or_null) {
#if !defined(HDL_HAS_TUI)
    (void)pid;
    (void)client;
    (void)store_path_or_null;
    wprintf(L"--tui requires HDL_CLIENT_TUI=ON (PDCurses) at build time\n");
    return 1;
#else
    ControllerState st;
    st.client = &client;
    if (store_path_or_null && store_path_or_null[0]) {
        st.store_path = store_path_or_null;
        st.store.Load(store_path_or_null);
    }

    initscr();
    cbreak();
    noecho();
    keypad(stdscr, TRUE);
    curs_set(1);

    std::deque<std::wstring> log;
    PushLog(&log, L"TUI ready — ? for help");
    std::wstring input;
    bool cmd_mode = false;

    auto logfn = [&](const std::wstring& w) { PushLog(&log, w); };

    st.wait_enter = [&]() {
        PushLog(&log, L"Press Enter after triggering the action (Esc cancel)...");
        Draw(st, pid, log, input, cmd_mode ? 1 : 0);
        for (;;) {
            wint_t wch = 0;
            const int rc = get_wch(&wch);
            if (rc == ERR) {
                continue;
            }
            if (IsEnterKey(wch, rc)) {
                return true;
            }
            if (wch == 27) {
                return false;
            }
        }
    };

    for (;;) {
        Draw(st, pid, log, input, cmd_mode ? 1 : 0);
        wint_t wch = 0;
        const int rc = get_wch(&wch);
        if (rc == ERR) {
            continue;
        }

        if (cmd_mode) {
            if (wch == 27) {
                cmd_mode = false;
                input.clear();
            } else if (IsEnterKey(wch, rc)) {
                const int drc = DispatchLine(st, pid, input, logfn);
                input.clear();
                cmd_mode = false;
                if (drc < 0) {
                    break;
                }
            } else if (IsBackspaceKey(wch, rc)) {
                if (!input.empty()) {
                    input.pop_back();
                }
            } else if (rc == OK && wch >= 32) {
                /* Accept any printable Unicode code point (BMP + beyond via wint_t). */
                input.push_back(static_cast<wchar_t>(wch));
            }
            continue;
        }

        if (rc == KEY_CODE_YES) {
            continue;
        }

        if (wch == L'q') {
            break;
        }
        if (wch == L'?' || wch == L'h') {
            PushLog(&log,
                    L"q quit | s save | L load | r revalidate | a action | c constrain | p place | "
                    L"t stitch | x expand | z stabilize | n session | Enter cmd");
            continue;
        }
        if (wch == L's') {
            if (st.store.Save(st.store_path.c_str())) {
                PushLog(&log, L"store saved");
            } else {
                PushLog(&log, L"store save failed");
            }
            continue;
        }
        if (wch == L'L') {
            if (st.store.Load(st.store_path.c_str())) {
                PushLog(&log, L"store loaded");
            } else {
                PushLog(&log, L"store load failed");
            }
            continue;
        }
        if (wch == L'r') {
            RevalidateStore(st, logfn);
            continue;
        }
        if (wch == L'n') {
            if (st.discover_session) {
                DiscoverClose(client, st.discover_session);
                st.discover_session = 0;
            }
            EnsureDiscoverSession(st, logfn);
            continue;
        }
        if (wch == L'a') {
            PushLog(&log, L"Enter: recipe action <name> <watch_hex>");
            cmd_mode = true;
            input = L"recipe action ";
            continue;
        }
        if (wch == L'c') {
            PushLog(&log, L"Enter: recipe constrain <size> <pred>...");
            cmd_mode = true;
            input = L"recipe constrain ";
            continue;
        }
        if (wch == L'p') {
            PushLog(&log, L"Enter: recipe place <interest> <near_hex>");
            cmd_mode = true;
            input = L"recipe place ";
            continue;
        }
        if (wch == L't') {
            PushLog(&log, L"Enter: recipe stitch <interest> --target HEX");
            cmd_mode = true;
            input = L"recipe stitch ";
            continue;
        }
        if (wch == L'x') {
            PushLog(&log, L"Enter: recipe expand <base_hex> <size>");
            cmd_mode = true;
            input = L"recipe expand ";
            continue;
        }
        if (wch == L'z') {
            PushLog(&log, L"Enter: stabilize <cand_id>");
            cmd_mode = true;
            input = L"stabilize ";
            continue;
        }
        if (IsEnterKey(wch, rc)) {
            cmd_mode = true;
            input.clear();
            continue;
        }
    }

    if (st.discover_session) {
        DiscoverClose(client, st.discover_session);
    }
    endwin();
    return 0;
#endif
}

}  // namespace hdlcli
