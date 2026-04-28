

#define NOGDI
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>


#include "net.h"
#include "filetransfer.h"
#include "file_dialog.h"
#include "Auth/Userlogin.h"
#include "Auth/session.h"
#include "introductory_mod.h"
#include "home_screen.h"

#include <iostream>
#include <string>
#include <mutex>
#include <atomic>
#include <cstdio>
#include <cstring>
#include <direct.h>

using namespace std;

// ── Server connection settings 
static const char* SERVER_IP   = "127.0.0.1";
static int         SERVER_PORT = 8080;

// ── Cipher key (derived from authenticated username) 

// Filled in main() after successful auth and used everywhere.
static unsigned char g_key[VaultCipher::KEY_LEN] = {};

// ── File-list cache  

// After decryption the list holds PLAINTEXT names for the user.
// We also keep a parallel array of the HEX (encrypted) names so
// we can send the correct encrypted name back to the server.
static const int MAX_FILES = 1024;
static char      g_fileList[MAX_FILES][300];    // plaintext names (display)
static char      g_hexList [MAX_FILES][600];    // hex-encoded encrypted names
static int       g_fileCount = 0;

// ── Shared async state ────────────────────────────────────────
static mutex          g_mtx;
static string         g_opResult;
static string         g_propsResult;
static atomic<bool>   g_fileListReady { false };
static atomic<bool>   g_opResultReady { false };
static atomic<bool>   g_propsReady    { false };
static atomic<bool>   g_downloadDone  { false };
static string         g_downloadedFile;
static atomic<float>  g_dlProgress    { 0.0f };

// ── Helpers ───────────────────────────────────────────────────
static void printProgress(uint64_t got, uint64_t total, int width = 40) {
    float pct    = total > 0 ? (float)got / (float)total : 0.f;
    int   filled = (int)(pct * width);
    printf("\r  [");
    for (int i = 0; i < width; i++) putchar(i < filled ? '#' : '-');
    printf("] %3d%%  %llu / %llu bytes",
           (int)(pct * 100),
           (unsigned long long)got,
           (unsigned long long)total);
    fflush(stdout);
}

static void waitFor(atomic<bool>& flag) {
    while (!flag) Sleep(30);
    flag = false;
}

// Return the PLAINTEXT display name for a list entry (already decrypted)
static string filenameFromEntry(int idx) {
    return string(g_fileList[idx]);
}

// Return the encrypted HEX name for sending to the server
static string hexnameFromEntry(int idx) {
    return string(g_hexList[idx]);
}

// ── fetchAndShowList ──────────────────────────────────────────
// Requests the list, waits, prints numbered plaintext names.
static int fetchAndShowList() {
    { lock_guard<mutex> lk(g_mtx); g_fileCount = 0; }
    g_fileListReady = false;
    net_send_cmd("LIST_FILES");
    waitFor(g_fileListReady);

    lock_guard<mutex> lk(g_mtx);
    if (g_fileCount == 0) {
        cout << "  (no files on server)\n";
        return 0;
    }
    cout << "\n  Files on server:\n";
    for (int i = 0; i < g_fileCount; i++)
        cout << "  " << (i + 1) << ". " << g_fileList[i] << "\n";
    return g_fileCount;
}

// ── pickFileByIndex ───────────────────────────────────────────
// Returns the index (0-based) of the selected file, or -1.
static int pickFileIndex(const char* prompt = nullptr) {
    int count = fetchAndShowList();
    if (count == 0) return -1;
    if (prompt) cout << "  " << prompt << "\n";
    cout << "  Enter number (0 to cancel): ";
    int idx; cin >> idx; cin.ignore(1000, '\n');
    if (idx < 1 || idx > count) return -1;
    return idx - 1;
}

// ── Auth handshake ────────────────────────────────────────────
static string doAuthHandshake(const LoginSession& sess) {
    string magic  = sess.isRegister ? MAGIC_AUTH_REG : MAGIC_AUTH_LOGIN;
    string packet = magic + sess.username + "|" + sess.passwordHash;
    net_send(packet.c_str(), (int)packet.size());

    char buf[256] = {};
    int  bytes    = net_recv_raw(buf, (int)sizeof(buf) - 1);
    if (bytes <= 0) return "";

    string reply(buf, bytes);
    int okLen   = (int)strlen(MAGIC_AUTH_OK);
    int failLen = (int)strlen(MAGIC_AUTH_FAIL);

    if ((int)reply.size() >= okLen &&
        reply.substr(0, okLen) == MAGIC_AUTH_OK)
        return reply.substr(okLen);

    if ((int)reply.size() >= failLen &&
        reply.substr(0, failLen) == MAGIC_AUTH_FAIL)
        cout << "  [AUTH FAILED] " << reply.substr(failLen) << "\n";

    return "";
}

// ── startRecvLoop ─────────────────────────────────────────────
// The recv loop stores BOTH the plaintext and hex name for each
// list entry so the UI can show plaintext while commands use hex.
static void startRecvLoop() {
    net_start_recv(
        [](const char* d, int n) { cout << string(d, n) << "\n"; },

        // onFileListResponse: clear cache
        []() {
            lock_guard<mutex> lk(g_mtx);
            g_fileCount     = 0;
            g_fileListReady = true;
        },

        // onListEntry: entry arrives ALREADY DECRYPTED (net.cpp does it).
        // We need to re-derive the hex name from the plaintext for later use.
        // Strategy: net.cpp receives the hex from server, decrypts it, then
        // passes (plaintext, idx). We re-encrypt to get hex back.
        // Since encrypt is deterministic this round-trips perfectly.
        [](const string& plainEntry, int idx) {
            lock_guard<mutex> lk(g_mtx);
            if (idx < MAX_FILES) {
                strncpy(g_fileList[idx], plainEntry.c_str(), 299);
                g_fileList[idx][299] = '\0';

                // Re-derive encrypted hex for server commands
                string hexName = VaultCipher::encryptFilename(
                                     plainEntry, g_key);
                strncpy(g_hexList[idx], hexName.c_str(), 599);
                g_hexList[idx][599] = '\0';

                if (idx + 1 > g_fileCount) g_fileCount = idx + 1;
            }
            g_fileListReady = true;
        },

        []() { g_dlProgress = 0.f; },
        [](float pct) { g_dlProgress = pct; },

        [](const string& fn) {
            g_downloadedFile = fn;
            g_downloadDone   = true;
        },

        [](const string& payload) {
            lock_guard<mutex> lk(g_mtx);
            g_opResult      = payload;
            g_opResultReady = true;
        },

        // onPropsResponse: display the props received from server.
        // Prepend the plaintext filename so the user knows what they're
        // looking at (the server only knows the encrypted name).
        [](const string& payload) {
            lock_guard<mutex> lk(g_mtx);
            g_propsResult = payload;
            g_propsReady  = true;
        },

        [](int err) {
            cout << "\n  [Disconnected from server"
                 << (err ? " (error " + to_string(err) + ")" : "")
                 << "]\n";
        },

        g_key   // pass key to recv thread for download decryption
    );
}

// ── File manager operations ───────────────────────────────────

static void fm_viewDownload() {
    int i = pickFileIndex("Select file to download:");
    if (i < 0) return;

    string plainName = filenameFromEntry(i);
    string hexName   = hexnameFromEntry(i);

    g_downloadDone = false;
    g_dlProgress   = 0.f;
    // Send the encrypted hex name so the server can find the file
    net_send_cmd(string(MAGIC_DL_REQ) + hexName);

    cout << "  Downloading '" << plainName << "'...\n";
    // while (!g_downloadDone) {
    //     printProgress((uint64_t)(g_dlProgress * 100), 100);
    //     //Sleep(100);
    // }
    printf("\n  Saved as: %s\n", g_downloadedFile.c_str());
}

static void fm_upload() {
    filedialog_open();
    cout << "  (select a file in the dialog...)\n";
    while (!filedialog_ready()) Sleep(50);
    string path = filedialog_result();
    if (path.empty()) { cout << "  Cancelled.\n"; return; }
    cout << "  Uploading (encrypting): " << path << "\n";
    net_send_file_async(path, g_key,
        [](uint64_t got, uint64_t total) { printProgress(got, total); },
        [](bool ok, const string& fn) {
            printf("\n  Upload %s: %s\n", ok ? "OK" : "FAILED", fn.c_str());
        });
}

static void fm_rename() {
    int i = pickFileIndex("Select file to rename:");
    if (i < 0) return;

    string oldPlain = filenameFromEntry(i);
    string oldHex   = hexnameFromEntry(i);

    cout << "  New name for '" << oldPlain << "': ";
    string newPlain; getline(cin, newPlain);
    if (newPlain.empty()) { cout << "  Cancelled.\n"; return; }

    // Encrypt the new name using the same key
    string newHex = VaultCipher::encryptFilename(newPlain, g_key);

    g_opResultReady = false;
    net_send_rename(oldHex, newHex);
    waitFor(g_opResultReady);
    cout << "  Server: " << g_opResult << "\n";
}

static void fm_delete() {
    int i = pickFileIndex("Select file to delete:");
    if (i < 0) return;

    string plainName = filenameFromEntry(i);
    string hexName   = hexnameFromEntry(i);

    cout << "  Confirm delete '" << plainName << "'? (y/N): ";
    string b; getline(cin, b);
    if (b == "y" || b == "Y") {
        g_opResultReady = false;
        net_send_delete(hexName);
        waitFor(g_opResultReady);
        cout << "  Server: " << g_opResult << "\n";
    } else {
        cout << "  Cancelled.\n";
    }
}



static void fm_viewProperties() {
    int i = pickFileIndex("Select file for properties:");
    if (i < 0) return;

    string plainName = filenameFromEntry(i);
    string hexName   = hexnameFromEntry(i);

    g_propsReady = false;
    net_send_props(hexName);
    waitFor(g_propsReady);

    // Show the original plaintext name first, then server's filesystem info
    cout << "\n  File: " << plainName << "\n"
         << g_propsResult << "\n";
}

// ── runFileManagerMenu  (called by HomeScreen) ────────────────
void runFileManagerMenu(const string& username) {
    cout << "\n  -- File Manager (" << username << ") --------------\n";

    int choice = -1;
    while (choice != 0) {
        cout << "\n"
             << "  .==============================.\n"
             << "  |        FILE MANAGER          |\n"
             << "  |------------------------------|\n"
             << "  |  1. View / Download files    |\n"
             << "  |  2. Upload a file            |\n"
             << "  |  3. Rename a file            |\n"
             << "  |  4. Delete a file            |\n"
             << "  |  5. View file properties     |\n"
             << "  |  0. Back to Home             |\n"
             << "  |______________________________|\n"
             << "  Choice: ";
        cin >> choice; cin.ignore(1000, '\n');

        switch (choice) {
            case 1: fm_viewDownload();   break;
            case 2: fm_upload();         break;
            case 3: fm_rename();         break;
            case 4: fm_delete();         break;
            case 5: fm_viewProperties(); break;
            case 0: break;
            default: cout << "  [!] Invalid option.\n";
        }
    }
}

// ── connectAndAuth ────────────────────────────────────────────
static string connectAndAuth(const LoginSession& sess, int& outUserID) {
    cout << "  Connecting to " << SERVER_IP
         << ":" << SERVER_PORT << " ...\n";
    if (!net_connect_sync(SERVER_IP, SERVER_PORT)) {
        cout << "  [ERR] Could not reach server. Is it running?\n";
        return "";
    }
    cout << "  Connected.\n";
    string reply = doAuthHandshake(sess);
    if (reply.empty()) {
        net_cleanup();
        net_startup();
        return "";
    }
    // Server sends "username|userID" — parse both
    size_t pipe = reply.find('|');
    if (pipe != string::npos) {
        outUserID = atoi(reply.substr(pipe + 1).c_str());
        return reply.substr(0, pipe);
    }
    outUserID = 1;  // fallback for old server builds
    return reply;
}

// ── main ──────────────────────────────────────────────────────
int main(int argc, char** argv) {
    if (argc > 1) SERVER_IP   = argv[1];
    if (argc > 2) SERVER_PORT = atoi(argv[2]);

    if (!net_startup()) { cerr << "WSAStartup failed.\n"; return 1; }

    _mkdir("downloads");
    _mkdir("Data");
    net_setSaveDir("downloads");

    SessionRecord savedSession{};
    bool hasSavedSession = SessionManager::load(savedSession);

    string authedUsername;
    string masterKey;
    int    userID = 0;

    if (hasSavedSession) {
        cout << "\n  Welcome back, " << savedSession.username << "!\n";
        cout << "  Enter your password to continue: ";
        getline(cin, masterKey);

        LoginSession sess {
            string(savedSession.username),
            UserAuth::hashPassword(masterKey),
            false
        };

        authedUsername = connectAndAuth(sess, userID);
        userID         = savedSession.userID;

        if (authedUsername.empty()) {
            cout << "  Session re-auth failed. Please log in again.\n";
            SessionManager::clear();
            hasSavedSession = false;
        }
    }

    if (!hasSavedSession) {
        IntroductoryModule welcome;
        welcome.showBanner();

        bool loggedIn = false;
        while (!loggedIn) {
            bool hasAccount = welcome.haveAnAccount();
            LoginSession sess;

            if (hasAccount) {
                LoginScreen loginScr("Login");
                sess = loginScr.run();
            } else {
                RegisterScreen regScr("Create Account");
                sess = regScr.run();
            }

            masterKey      = sess.passwordHash;
            authedUsername = connectAndAuth(sess, userID);

            if (!authedUsername.empty()) {
                loggedIn = true;
                cout << "  (For vault encryption) Re-enter your password: ";
                getline(cin, masterKey);
                SessionManager::save(userID, authedUsername);
            }
        }
    }

    cout << "  [OK] Authenticated as '" << authedUsername << "'.\n";

    // ── Derive cipher key from the authenticated username ──────
    // This is done ONCE here and stored in g_key for the session.
    VaultCipher::buildKey(authedUsername, g_key);
    cout << "  [OK] Encryption key derived.\n";

    // ── Start background receive loop (key passed in) ──────────
    startRecvLoop();

    // ── Launch HomeScreen ──────────────────────────────────────
    {
        HomeScreen home(userID, authedUsername, masterKey);
        home.run();
    }

    net_send_cmd("QUIT");
    net_stop_recv();
    net_cleanup();
    return 0;
}
