#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <map>
#include <ctime>
#include <cstring>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <signal.h>
#include <pthread.h>
#include <unistd.h>
#include <cstdlib>
#include <sys/socket.h>
#include <netinet/in.h>
#include <algorithm>

using namespace std;

// Global flag for graceful shutdown
volatile sig_atomic_t keep_running = 1;
volatile sig_atomic_t capture_active = 0;
pthread_mutex_t events_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t stats_mutex = PTHREAD_MUTEX_INITIALIZER;

void signal_handler(int signum) {
    keep_running = 0;
    capture_active = 0;
}

// Structure to represent a rule
struct Rule {
    string keyword;
    string severity;
    int port;
    string protocol;
};

// Structure to represent a packet event
struct PacketEvent {
    string timestamp;
    string source_ip;
    string dest_ip;
    int source_port;
    int dest_port;
    string protocol;
    string flags;
    int packet_size;
    string event_description;
    string severity;
};

// Structure to represent a monitored IP
struct MonitoredIP {
    string ip;
    string note;
};

// Structure to track connection attempts
struct ConnectionTracker {
    map<string, int> syn_count;
    map<string, time_t> last_syn_time;
    map<string, vector<int> > scanned_ports;
    map<string, time_t> last_packet_time;
    
    // Intelligence features
    map<string, vector<string> > packet_signatures; // IP -> list of recent packet signatures
    map<string, int> similarity_count;             // IP -> count of highly similar packets
    map<string, double> threat_multiplier;          // IP -> user feedback multiplier (default 1.0)
    map<string, int> feedback_count;               // IP -> number of feedback entries
    
    // Analytics
    map<int, int> port_hits;                       // Port -> Hits
    map<string, int> ip_hits;                      // Source IP -> Hits
};

ConnectionTracker tracker;
vector<PacketEvent> captured_events;
vector<Rule> global_rules;
vector<MonitoredIP> global_monitored_ips;

// Statistics
struct Statistics {
    int critical;
    int high;
    int medium;
    int low;
    int info;
    int total;
    int burst_count;
    int port_scan_count;
    int syn_flood_count;
    int false_alarms;
    time_t start_time;
    string current_interface;
};

Statistics global_stats = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, ""};

// Function declarations
string toLowerCase(const string& str);
string trim(const string& str);
string getCurrentTimestamp();
vector<Rule> readRules(const string& filename);
vector<MonitoredIP> readMonitoredIPs(const string& filename);
void writeMonitoredIPs(const string& filename, const vector<MonitoredIP>& monitoredIPs);
bool isIPMonitored(const string& ip, const vector<MonitoredIP>& monitoredIPs);
string analyzePacket(const PacketEvent& event);
void packet_handler(u_char* user_data, const struct pcap_pkthdr* pkthdr, const u_char* packet);
string escapeJSON(const string& str);
string eventsToJSON();
void saveIntelligence();
void loadIntelligence();
string analyticsToJSON();
string rulesToJSON();
string urlDecode(const string& str);
void writeRules(const string& filename, const vector<Rule>& rules);
void processPCAPFile(const string& filename);

// Utility functions
string toLowerCase(const string& str) {
    string result = str;
    for (size_t i = 0; i < result.length(); i++) {
        if (result[i] >= 'A' && result[i] <= 'Z') {
            result[i] = result[i] + 32;
        }
    }
    return result;
}

string trim(const string& str) {
    size_t start = 0;
    size_t end = str.length();
    
    while (start < end && (str[start] == ' ' || str[start] == '\t' || 
           str[start] == '\n' || str[start] == '\r')) {
        start++;
    }
    
    while (end > start && (str[end-1] == ' ' || str[end-1] == '\t' || 
           str[end-1] == '\n' || str[end-1] == '\r')) {
        end--;
    }
    
    return str.substr(start, end - start);
}

string getCurrentTimestamp() {
    time_t now = time(0);
    char buffer[80];
    strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", localtime(&now));
    return string(buffer);
}

void saveIntelligence() {
    ofstream file("intelligence.dat");
    if (!file.is_open()) return;
    
    pthread_mutex_lock(&stats_mutex);
    for (map<string, double>::iterator it = tracker.threat_multiplier.begin(); it != tracker.threat_multiplier.end(); ++it) {
        file << it->first << "," << it->second << "\n";
    }
    pthread_mutex_unlock(&stats_mutex);
    file.close();
}

void loadIntelligence() {
    ifstream file("intelligence.dat");
    if (!file.is_open()) return;
    
    string line;
    pthread_mutex_lock(&stats_mutex);
    while (getline(file, line)) {
        size_t comma = line.find(',');
        if (comma != string::npos) {
            string ip = line.substr(0, comma);
            double mult = atof(line.substr(comma + 1).c_str());
            tracker.threat_multiplier[ip] = mult;
        }
    }
    pthread_mutex_unlock(&stats_mutex);
    file.close();
}

string escapeJSON(const string& str) {
    string escaped;
    for (size_t i = 0; i < str.length(); i++) {
        if (str[i] == '"') escaped += "\\\"";
        else if (str[i] == '\\') escaped += "\\\\";
        else if (str[i] == '\n') escaped += "\\n";
        else if (str[i] == '\r') escaped += "\\r";
        else if (str[i] == '\t') escaped += "\\t";
        else escaped += str[i];
    }
    return escaped;
}

string urlDecode(const string& str) {
    string result;
    result.reserve(str.length());
    for (size_t i = 0; i < str.length(); ++i) {
        if (str[i] == '%') {
            if (i + 2 < str.length()) {
                int value;
                istringstream is(str.substr(i + 1, 2));
                if (is >> hex >> value) {
                    result += static_cast<char>(value);
                    i += 2;
                } else {
                    result += str[i];
                }
            } else {
                result += str[i];
            }
        } else if (str[i] == '+') {
            result += ' ';
        } else {
            result += str[i];
        }
    }
    return result;
}

// File operations
vector<Rule> readRules(const string& filename) {
    vector<Rule> rules;
    ifstream file(filename.c_str());
    
    if (!file.is_open()) {
        cerr << "Warning: Could not open " << filename << ", using default rules." << endl;
        Rule r1; r1.keyword = "syn_flood"; r1.severity = "CRITICAL"; r1.port = -1; r1.protocol = "TCP";
        Rule r2; r2.keyword = "port_scan"; r2.severity = "HIGH"; r2.port = -1; r2.protocol = "ANY";
        rules.push_back(r1);
        rules.push_back(r2);
        return rules;
    }
    
    string line;
    while (getline(file, line)) {
        line = trim(line);
        if (line.empty() || line[0] == '#') continue;
        
        size_t equalPos = line.find('=');
        if (equalPos != string::npos) {
            Rule rule;
            rule.keyword = trim(line.substr(0, equalPos));
            rule.severity = trim(line.substr(equalPos + 1));
            rule.port = -1;
            rule.protocol = "ANY";
            rules.push_back(rule);
        }
    }
    
    file.close();
    return rules;
}

void writeRules(const string& filename, const vector<Rule>& rules) {
    ofstream file(filename.c_str());
    if (!file.is_open()) return;
    
    file << "# IDS Rules - Format: Keyword = Severity\n";
    for (size_t i = 0; i < rules.size(); i++) {
        file << rules[i].keyword << " = " << rules[i].severity << "\n";
    }
    file.close();
}

vector<MonitoredIP> readMonitoredIPs(const string& filename) {
    vector<MonitoredIP> monitoredIPs;
    ifstream file(filename.c_str());
    
    if (!file.is_open()) {
        return monitoredIPs;
    }
    
    string line;
    while (getline(file, line)) {
        line = trim(line);
        if (line.empty() || line[0] == '#') continue;
        
        MonitoredIP mip;
        size_t pipePos = line.find('|');
        if (pipePos != string::npos) {
            mip.ip = trim(line.substr(0, pipePos));
            mip.note = trim(line.substr(pipePos + 1));
        } else {
            mip.ip = line;
            mip.note = "No note";
        }
        monitoredIPs.push_back(mip);
    }
    
    file.close();
    return monitoredIPs;
}

void writeMonitoredIPs(const string& filename, const vector<MonitoredIP>& monitoredIPs) {
    ofstream file(filename.c_str());
    if (!file.is_open()) {
        cerr << "Error: Could not write to " << filename << endl;
        return;
    }
    
    file << "# Monitored IP addresses - Format: IP|Note" << endl;
    for (size_t i = 0; i < monitoredIPs.size(); i++) {
        file << monitoredIPs[i].ip << "|" << monitoredIPs[i].note << endl;
    }
    
    file.close();
}

bool isIPMonitored(const string& ip, const vector<MonitoredIP>& monitoredIPs) {
    for (size_t i = 0; i < monitoredIPs.size(); i++) {
        if (monitoredIPs[i].ip == ip) {
            return true;
        }
    }
    return false;
}

int getSeverityPriority(const string& severity) {
    string lower = toLowerCase(severity);
    if (lower == "critical") return 4;
    if (lower == "high") return 3;
    if (lower == "medium") return 2;
    if (lower == "low") return 1;
    return 0;
}

string analyzePacket(const PacketEvent& event) {
    string severity = "INFO";
    int highestPriority = 0;
    
    // Check for behavioral matches
    bool isSimilar = (event.event_description.find("SIMILAR_PACKET_BURST") != string::npos);
    bool isScan = (event.event_description.find("POSSIBLE_PORT_SCAN") != string::npos);
    bool isFlood = (event.event_description.find("POSSIBLE_SYN_FLOOD") != string::npos);

    if (isFlood) {
        severity = "CRITICAL";
        highestPriority = 4;
    } else if (isSimilar) {
        severity = "HIGH";
        highestPriority = 3;
    } else if (isScan) {
        severity = "MEDIUM";
        highestPriority = 2;
    }

    // Traditional Rule Matching
    for (size_t i = 0; i < global_rules.size(); i++) {
        string lowerDesc = toLowerCase(event.event_description);
        string lowerKeyword = toLowerCase(global_rules[i].keyword);
        
        if (lowerDesc.find(lowerKeyword) != string::npos) {
            int priority = getSeverityPriority(global_rules[i].severity);
            if (priority > highestPriority) {
                highestPriority = priority;
                severity = global_rules[i].severity;
            }
        }
    }
    
    if (isIPMonitored(event.source_ip, global_monitored_ips)) {
        if (highestPriority < 2) {
            severity = "MEDIUM";
            highestPriority = 2;
        }
    }

    // Apply Intelligent Feedback Multiplier
    double multiplier = 1.0;
    if (tracker.threat_multiplier.count(event.source_ip)) {
        multiplier = tracker.threat_multiplier[event.source_ip];
    }

    // Adjust severity based on multiplier (Intelligence Learner)
    if (multiplier < 0.5 && highestPriority > 0) {
        // Highly suppressed due to false positive feedback
        highestPriority = max(1, highestPriority - 1);
    } else if (multiplier > 1.5) {
        // Escalated due to confirmed true positive feedback
        highestPriority = min(4, highestPriority + 1);
    }

    // Map priority back to severity string
    if (highestPriority == 4) severity = "CRITICAL";
    else if (highestPriority == 3) severity = "HIGH";
    else if (highestPriority == 2) severity = "MEDIUM";
    else if (highestPriority == 1) severity = "LOW";
    else severity = "INFO";

    return severity;
}

string getTCPFlags(const struct tcphdr* tcp_header) {
    string flags = "";
    if (tcp_header->fin) flags += "F";
    if (tcp_header->syn) flags += "S";
    if (tcp_header->rst) flags += "R";
    if (tcp_header->psh) flags += "P";
    if (tcp_header->ack) flags += "A";
    if (tcp_header->urg) flags += "U";
    return flags.empty() ? "NONE" : flags;
}

void processPCAPFile(const string& filename) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_offline(filename.c_str(), errbuf);
    if (!handle) {
        cerr << "Error opening PCAP file: " << errbuf << endl;
        return;
    }
    
    cout << "Processing offline PCAP: " << filename << endl;
    pcap_loop(handle, 0, packet_handler, NULL);
    pcap_close(handle);
}

void packet_handler(u_char* user_data, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    struct ether_header* eth_header = (struct ether_header*)packet;
    
    if (ntohs(eth_header->ether_type) != ETHERTYPE_IP) {
        return;
    }
    
    struct ip* ip_header = (struct ip*)(packet + sizeof(struct ether_header));
    
    PacketEvent event;
    event.timestamp = getCurrentTimestamp();
    event.source_ip = inet_ntoa(ip_header->ip_src);
    event.dest_ip = inet_ntoa(ip_header->ip_dst);
    event.packet_size = ntohs(ip_header->ip_len);
    event.source_port = 0;
    event.dest_port = 0;
    event.flags = "NONE";
    
    time_t now = time(0);
    tracker.last_packet_time[event.source_ip] = now;

    // Intelligence: Pattern Signature Generation
    ostringstream sig;
    sig << event.dest_ip << "|" << (int)ip_header->ip_p << "|" << event.packet_size;
    string signature = sig.str();
    
    // Similarity Tracking
    tracker.packet_signatures[event.source_ip].push_back(signature);
    if (tracker.packet_signatures[event.source_ip].size() > 10) {
        tracker.packet_signatures[event.source_ip].erase(tracker.packet_signatures[event.source_ip].begin());
    }

    int similar_count = 0;
    for (size_t i = 0; i < tracker.packet_signatures[event.source_ip].size(); i++) {
        if (tracker.packet_signatures[event.source_ip][i] == signature) similar_count++;
    }
    
    if (ip_header->ip_p == IPPROTO_TCP) {
        event.protocol = "TCP";
        struct tcphdr* tcp_header = (struct tcphdr*)(packet + sizeof(struct ether_header) + sizeof(struct ip));
        event.source_port = ntohs(tcp_header->source);
        event.dest_port = ntohs(tcp_header->dest);
        event.flags = getTCPFlags(tcp_header);
        
        bool port_exists = false;
        for (size_t i = 0; i < tracker.scanned_ports[event.source_ip].size(); i++) {
            if (tracker.scanned_ports[event.source_ip][i] == event.dest_port) {
                port_exists = true;
                break;
            }
        }
        if (!port_exists) {
            tracker.scanned_ports[event.source_ip].push_back(event.dest_port);
        }
        
        ostringstream desc;
        desc << "TCP from " << event.source_ip << ":" << event.source_port 
             << " to " << event.dest_ip << ":" << event.dest_port 
             << " [" << event.flags << "]";
        
        if (event.dest_port == 22) desc << " SSH";
        else if (event.dest_port == 80) desc << " HTTP";
        else if (event.dest_port == 443) desc << " HTTPS";
        
        if (event.flags.find('S') != string::npos) {
            tracker.syn_count[event.source_ip]++;
            tracker.last_syn_time[event.source_ip] = now;
            if (tracker.syn_count[event.source_ip] > 50) desc << " POSSIBLE_SYN_FLOOD";
        }
        
        event.event_description = desc.str();
        
    } else if (ip_header->ip_p == IPPROTO_UDP) {
        event.protocol = "UDP";
        struct udphdr* udp_header = (struct udphdr*)(packet + sizeof(struct ether_header) + sizeof(struct ip));
        event.source_port = ntohs(udp_header->source);
        event.dest_port = ntohs(udp_header->dest);
        
        ostringstream desc;
        desc << "UDP from " << event.source_ip << ":" << event.source_port 
             << " to " << event.dest_ip << ":" << event.dest_port;
        event.event_description = desc.str();
        
    } else if (ip_header->ip_p == IPPROTO_ICMP) {
        event.protocol = "ICMP";
        event.event_description = "ICMP message from " + event.source_ip;
    } else {
        event.protocol = "OTHER";
        event.event_description = "Other protocol from " + event.source_ip;
    }
    
    // Attach intelligence flags
    if (similar_count >= 8) {
        event.event_description += " [SIMILAR_PACKET_BURST]";
    }
    if (tracker.scanned_ports[event.source_ip].size() > 15) {
        event.event_description += " [POSSIBLE_PORT_SCAN]";
    }
    
    event.severity = analyzePacket(event);
    
    pthread_mutex_lock(&stats_mutex);
    tracker.ip_hits[event.source_ip]++;
    if (event.dest_port > 0) tracker.port_hits[event.dest_port]++;
    
    // Increment specific threat counters
    if (event.event_description.find("POSSIBLE_SYN_FLOOD") != string::npos) global_stats.syn_flood_count++;
    if (event.event_description.find("SIMILAR_PACKET_BURST") != string::npos) global_stats.burst_count++;
    if (event.event_description.find("POSSIBLE_PORT_SCAN") != string::npos) global_stats.port_scan_count++;
    pthread_mutex_unlock(&stats_mutex);
    
    pthread_mutex_lock(&events_mutex);
    captured_events.push_back(event);
    
    pthread_mutex_lock(&stats_mutex);
    global_stats.total++;
    string sev = toLowerCase(event.severity);
    if (sev == "critical") global_stats.critical++;
    else if (sev == "high") global_stats.high++;
    else if (sev == "medium") global_stats.medium++;
    else if (sev == "low") global_stats.low++;
    else global_stats.info++;
    pthread_mutex_unlock(&stats_mutex);
    
    pthread_mutex_unlock(&events_mutex);
}

// JSON conversion functions
string eventsToJSON() {
    pthread_mutex_lock(&events_mutex);
    
    ostringstream json;
    json << "[";
    
    size_t start = captured_events.size() > 100 ? captured_events.size() - 100 : 0;
    
    for (size_t i = start; i < captured_events.size(); i++) {
        if (i > start) json << ",";
        json << "{";
        json << "\"timestamp\":\"" << escapeJSON(captured_events[i].timestamp) << "\",";
        json << "\"sourceIP\":\"" << escapeJSON(captured_events[i].source_ip) << "\",";
        json << "\"destIP\":\"" << escapeJSON(captured_events[i].dest_ip) << "\",";
        json << "\"sourcePort\":" << captured_events[i].source_port << ",";
        json << "\"destPort\":" << captured_events[i].dest_port << ",";
        json << "\"protocol\":\"" << escapeJSON(captured_events[i].protocol) << "\",";
        json << "\"flags\":\"" << escapeJSON(captured_events[i].flags) << "\",";
        json << "\"size\":" << captured_events[i].packet_size << ",";
        json << "\"description\":\"" << escapeJSON(captured_events[i].event_description) << "\",";
        json << "\"severity\":\"" << escapeJSON(captured_events[i].severity) << "\"";
        json << "}";
    }
    
    json << "]";
    
    pthread_mutex_unlock(&events_mutex);
    return json.str();
}

string statsToJSON() {
    pthread_mutex_lock(&stats_mutex);
    
    ostringstream json;
    json << "{";
    json << "\"critical\":" << global_stats.critical << ",";
    json << "\"high\":" << global_stats.high << ",";
    json << "\"medium\":" << global_stats.medium << ",";
    json << "\"low\":" << global_stats.low << ",";
    json << "\"info\":" << global_stats.info << ",";
    json << "\"total\":" << global_stats.total << ",";
    json << "\"bursts\":" << global_stats.burst_count << ",";
    json << "\"portScans\":" << global_stats.port_scan_count << ",";
    json << "\"synFloods\":" << global_stats.syn_flood_count << ",";
    json << "\"falseAlarms\":" << global_stats.false_alarms << ",";
    json << "\"captureTime\":" << (capture_active ? (time(0) - global_stats.start_time) : 0) << ",";
    json << "\"interface\":\"" << escapeJSON(global_stats.current_interface) << "\",";
    json << "\"capturing\":" << (capture_active ? "true" : "false");
    json << "}";
    
    pthread_mutex_unlock(&stats_mutex);
    return json.str();
}

string analyticsToJSON() {
    pthread_mutex_lock(&stats_mutex);
    ostringstream json;
    json << "{";
    
    // Top Ports
    json << "\"topPorts\":[";
    vector<pair<int, int> > ports;
    for (map<int, int>::iterator it = tracker.port_hits.begin(); it != tracker.port_hits.end(); ++it)
        ports.push_back(make_pair(it->second, it->first));
    sort(ports.rbegin(), ports.rend());
    for (size_t i = 0; i < ports.size() && i < 5; i++) {
        if (i > 0) json << ",";
        json << "{\"port\":" << ports[i].second << ",\"count\":" << ports[i].first << "}";
    }
    json << "],";
    
    // Top Talkers
    json << "\"topTalkers\":[";
    vector<pair<int, string> > ips;
    for (map<string, int>::iterator it = tracker.ip_hits.begin(); it != tracker.ip_hits.end(); ++it)
        ips.push_back(make_pair(it->second, it->first));
    sort(ips.rbegin(), ips.rend());
    for (size_t i = 0; i < ips.size() && i < 5; i++) {
        if (i > 0) json << ",";
        json << "{\"ip\":\"" << ips[i].second << "\",\"count\":" << ips[i].first << "}";
    }
    json << "]";
    
    json << "}";
    pthread_mutex_unlock(&stats_mutex);
    return json.str();
}

string rulesToJSON() {
    pthread_mutex_lock(&stats_mutex);
    ostringstream json;
    json << "[";
    for (size_t i = 0; i < global_rules.size(); i++) {
        if (i > 0) json << ",";
        json << "{";
        json << "\"keyword\":\"" << escapeJSON(global_rules[i].keyword) << "\",";
        json << "\"severity\":\"" << escapeJSON(global_rules[i].severity) << "\",";
        json << "\"port\":" << global_rules[i].port << ",";
        json << "\"protocol\":\"" << escapeJSON(global_rules[i].protocol) << "\"";
        json << "}";
    }
    json << "]";
    pthread_mutex_unlock(&stats_mutex);
    return json.str();
}

string monitoredIPsToJSON() {
    ostringstream json;
    json << "[";
    
    for (size_t i = 0; i < global_monitored_ips.size(); i++) {
        if (i > 0) json << ",";
        json << "{";
        json << "\"ip\":\"" << escapeJSON(global_monitored_ips[i].ip) << "\",";
        json << "\"note\":\"" << escapeJSON(global_monitored_ips[i].note) << "\"";
        json << "}";
    }
    
    json << "]";
    return json.str();
}

string interfacesToJSON() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t* alldevs;
    
    ostringstream json;
    json << "[";
    
    if (pcap_findalldevs(&alldevs, errbuf) != -1) {
        pcap_if_t* device;
        bool first = true;
        
        for (device = alldevs; device != NULL; device = device->next) {
            if (!first) json << ",";
            first = false;
            
            string ip = "No IPv4";
            for (pcap_addr_t* a = device->addresses; a != NULL; a = a->next) {
                if (a->addr && a->addr->sa_family == AF_INET) {
                    ip = inet_ntoa(((struct sockaddr_in*)a->addr)->sin_addr);
                    break;
                }
            }

            json << "{";
            json << "\"name\":\"" << escapeJSON(device->name) << "\",";
            json << "\"ip\":\"" << escapeJSON(ip) << "\",";
            json << "\"description\":\"" << escapeJSON(device->description ? device->description : "No description") << "\"";
            json << "}";
        }
        
        pcap_freealldevs(alldevs);
    }
    
    json << "]";
    return json.str();
}

// Capture thread function
void* capture_thread_func(void* arg) {
    string interface = *((string*)arg);
    delete (string*)arg;
    
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(interface.c_str(), BUFSIZ, 1, 1000, errbuf);
    
    if (handle == NULL) {
        cerr << "Error opening device: " << errbuf << endl;
        capture_active = 0;
        return NULL;
    }
    
    cout << "Capture started on " << interface << endl;
    
    while (capture_active && keep_running) {
        pcap_dispatch(handle, 10, packet_handler, NULL);
    }
    
    pcap_close(handle);
    cout << "Capture stopped." << endl;
    
    return NULL;
}

// HTTP Server functions
void sendHTTPResponse(int client_sock, int status_code, const string& content_type, const string& body) {
    ostringstream response;
    
    string status_text = (status_code == 200) ? "OK" : "Error";
    
    response << "HTTP/1.1 " << status_code << " " << status_text << "\r\n";
    response << "Content-Type: " << content_type << "\r\n";
    response << "Content-Length: " << body.length() << "\r\n";
    response << "Access-Control-Allow-Origin: *\r\n";
    response << "Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n";
    response << "Access-Control-Allow-Headers: Content-Type\r\n";
    response << "Connection: close\r\n";
    response << "\r\n";
    response << body;
    
    string resp_str = response.str();
    send(client_sock, resp_str.c_str(), resp_str.length(), 0);
}

void handleRequest(int client_sock, const string& request) {
    istringstream request_stream(request);
    string method, path, version;
    request_stream >> method >> path >> version;
    
    if (method == "OPTIONS") {
        sendHTTPResponse(client_sock, 200, "text/plain", "");
        return;
    }
    
    if (path == "/" || path == "/index.html") {
        ifstream file("dashboard.html");
        if (file.is_open()) {
            string content((istreambuf_iterator<char>(file)), istreambuf_iterator<char>());
            sendHTTPResponse(client_sock, 200, "text/html", content);
        } else {
            sendHTTPResponse(client_sock, 404, "text/plain", "Dashboard not found");
        }
    }
    else if (path == "/api/interfaces") {
        string json = interfacesToJSON();
        sendHTTPResponse(client_sock, 200, "application/json", json);
    }
    else if (path == "/api/events") {
        string json = eventsToJSON();
        sendHTTPResponse(client_sock, 200, "application/json", json);
    }
    else if (path == "/api/stats") {
        string json = statsToJSON();
        sendHTTPResponse(client_sock, 200, "application/json", json);
    }
    else if (path == "/api/monitored-ips") {
        string json = monitoredIPsToJSON();
        sendHTTPResponse(client_sock, 200, "application/json", json);
    }
    else if (path == "/api/start-capture" && method == "POST") {
        size_t body_pos = request.find("\r\n\r\n");
        if (body_pos != string::npos) {
            string body = request.substr(body_pos + 4);
            
            size_t iface_pos = body.find("\"interface\":\"");
            if (iface_pos != string::npos) {
                size_t start = iface_pos + 13;
                size_t end = body.find("\"", start);
                string interface = body.substr(start, end - start);
                
                if (!capture_active) {
                    capture_active = 1;
                    global_stats.start_time = time(0);
                    global_stats.current_interface = interface;
                    
                    pthread_t thread;
                    string* iface_ptr = new string(interface);
                    pthread_create(&thread, NULL, capture_thread_func, iface_ptr);
                    pthread_detach(thread);
                    
                    sendHTTPResponse(client_sock, 200, "application/json", "{\"status\":\"started\"}");
                } else {
                    sendHTTPResponse(client_sock, 200, "application/json", "{\"status\":\"already_running\"}");
                }
            }
        }
    }
    else if (path == "/api/stop-capture" && method == "POST") {
        capture_active = 0;
        sendHTTPResponse(client_sock, 200, "application/json", "{\"status\":\"stopped\"}");
    }
    else if (path == "/api/add-monitored-ip" && method == "POST") {
        size_t body_pos = request.find("\r\n\r\n");
        if (body_pos != string::npos) {
            string body = request.substr(body_pos + 4);
            
            size_t ip_pos = body.find("\"ip\":\"");
            size_t note_pos = body.find("\"note\":\"");
            
            if (ip_pos != string::npos && note_pos != string::npos) {
                size_t ip_start = ip_pos + 6;
                size_t ip_end = body.find("\"", ip_start);
                string ip = body.substr(ip_start, ip_end - ip_start);
                
                size_t note_start = note_pos + 8;
                size_t note_end = body.find("\"", note_start);
                string note = body.substr(note_start, note_end - note_start);
                
                MonitoredIP mip;
                mip.ip = ip;
                mip.note = note;
                global_monitored_ips.push_back(mip);
                
                writeMonitoredIPs("monitored_ips.txt", global_monitored_ips);
                
                sendHTTPResponse(client_sock, 200, "application/json", "{\"status\":\"added\"}");
            }
        }
    }
    else if (path.find("/api/remove-monitored-ip/") == 0) {
        string ip = path.substr(25);
        
        for (size_t i = 0; i < global_monitored_ips.size(); i++) {
            if (global_monitored_ips[i].ip == ip) {
                global_monitored_ips.erase(global_monitored_ips.begin() + i);
                writeMonitoredIPs("monitored_ips.txt", global_monitored_ips);
                sendHTTPResponse(client_sock, 200, "application/json", "{\"status\":\"removed\"}");
                return;
            }
        }
        sendHTTPResponse(client_sock, 404, "application/json", "{\"status\":\"not_found\"}");
    }
    else if (path == "/api/feedback" && method == "POST") {
        size_t body_pos = request.find("\r\n\r\n");
        if (body_pos != string::npos) {
            string body = request.substr(body_pos + 4);
            
            size_t ip_pos = body.find("\"ip\":\"");
            size_t true_pos = body.find("\"isTruePositive\":");
            
            if (ip_pos != string::npos && true_pos != string::npos) {
                size_t ip_start = ip_pos + 6;
                size_t ip_end = body.find("\"", ip_start);
                string ip = body.substr(ip_start, ip_end - ip_start);
                
                size_t val_start = true_pos + 17;
                bool isTrue = (body.substr(val_start, 4) == "true");
                
                pthread_mutex_lock(&stats_mutex);
                if (tracker.threat_multiplier.find(ip) == tracker.threat_multiplier.end()) {
                    tracker.threat_multiplier[ip] = 1.0;
                }
                
                if (isTrue) {
                    tracker.threat_multiplier[ip] *= 1.4; // Reinforce
                } else {
                    tracker.threat_multiplier[ip] *= 0.6; // Suppress
                    global_stats.false_alarms++;
                }
                
                if (tracker.threat_multiplier[ip] > 3.0) tracker.threat_multiplier[ip] = 3.0;
                if (tracker.threat_multiplier[ip] < 0.2) tracker.threat_multiplier[ip] = 0.2;
                pthread_mutex_unlock(&stats_mutex);
                
                saveIntelligence();

                sendHTTPResponse(client_sock, 200, "application/json", "{\"status\":\"feedback_updated\"}");
                return;
            }
        }
        sendHTTPResponse(client_sock, 400, "application/json", "{\"status\":\"invalid_request\"}");
    }
    else if (path == "/api/rules") {
        sendHTTPResponse(client_sock, 200, "application/json", rulesToJSON());
    }
    else if (path == "/api/add-rule" && method == "POST") {
        size_t body_pos = request.find("\r\n\r\n");
        if (body_pos != string::npos) {
            string body = request.substr(body_pos + 4);
            size_t k_pos = body.find("\"keyword\":\"");
            size_t s_pos = body.find("\"severity\":\"");
            
            if (k_pos != string::npos && s_pos != string::npos) {
                Rule r;
                size_t k_start = k_pos + 11;
                size_t k_end = body.find("\"", k_start);
                r.keyword = body.substr(k_start, k_end - k_start);
                
                size_t s_start = s_pos + 12;
                size_t s_end = body.find("\"", s_start);
                r.severity = body.substr(s_start, s_end - s_start);
                r.port = -1;
                r.protocol = "ANY";
                
                global_rules.push_back(r);
                writeRules("rules.txt", global_rules);
                sendHTTPResponse(client_sock, 200, "application/json", "{\"status\":\"rule_added\"}");
                return;
            }
        }
        sendHTTPResponse(client_sock, 400, "application/json", "{\"status\":\"add_failed\"}");
    }
    else if (path.find("/api/remove-rule/") == 0) {
        string keyword = urlDecode(path.substr(17));
        for (size_t i = 0; i < global_rules.size(); i++) {
            if (global_rules[i].keyword == keyword) {
                global_rules.erase(global_rules.begin() + i);
                writeRules("rules.txt", global_rules);
                sendHTTPResponse(client_sock, 200, "application/json", "{\"status\":\"rule_removed\"}");
                return;
            }
        }
        sendHTTPResponse(client_sock, 404, "application/json", "{\"status\":\"not_found\"}");
    }
    else if (path == "/api/analytics") {
        sendHTTPResponse(client_sock, 200, "application/json", analyticsToJSON());
    }
    else if (path == "/api/upload-pcap" && method == "POST") {
        // Precise Multipart Parsing
        // 1. Find boundary parameter in headers
        size_t b_pos = request.find("boundary=");
        if (b_pos != string::npos) {
            size_t b_start = b_pos + 9;
            size_t b_end = request.find("\r\n", b_start);
            // Limit boundary search to headers just in case
            if (b_end == string::npos || b_end > request.find("\r\n\r\n")) {
                 // Fallback if formatting is weird
                 b_end = request.find("\r", b_start);
            }
            
            // The separator is "--" + boundary_value
            string boundary = "--" + request.substr(b_start, b_end - b_start);
            
            // 2. Find start of Body (after main headers)
            size_t body_start = request.find("\r\n\r\n");
            if (body_start != string::npos) {
                body_start += 4; 
                
                // 3. Find the first boundary within the body
                size_t first_boundary_pos = request.find(boundary, body_start);
                if (first_boundary_pos != string::npos) {
                    // 4. Find the end of Part Headers (Content-Position, etc.)
                    // These headers follow the boundary line
                    size_t part_headers_end = request.find("\r\n\r\n", first_boundary_pos);
                    
                    if (part_headers_end != string::npos) {
                        size_t file_data_start = part_headers_end + 4;
                        
                        // 5. Find the next boundary (end of data)
                        size_t next_boundary_pos = request.find(boundary, file_data_start);
                        
                        if (next_boundary_pos != string::npos) {
                            // The data ends 2 bytes (__CRLF__) before the next boundary
                            size_t file_data_end = next_boundary_pos - 2;
                            
                            string content = request.substr(file_data_start, file_data_end - file_data_start);
                            
                            cout << "PCAP Upload Debug: Magic Bytes: " 
                                 << hex << (int)(unsigned char)content[0] << " " 
                                 << (int)(unsigned char)content[1] << " " 
                                 << (int)(unsigned char)content[2] << " " 
                                 << (int)(unsigned char)content[3] << dec << endl;

                            ofstream pcap_file("temp_upload.pcap", ios::binary);
                            pcap_file.write(content.c_str(), content.length());
                            pcap_file.close();
                            
                            processPCAPFile("temp_upload.pcap");
                            sendHTTPResponse(client_sock, 200, "application/json", "{\"status\":\"pcap_processed\"}");
                            return;
                        }
                    }
                }
            }
        }
        sendHTTPResponse(client_sock, 400, "application/json", "{\"status\":\"upload_failed\"}");
    }
    else {
        sendHTTPResponse(client_sock, 404, "text/plain", "Not Found");
    }
}

void startWebServer(int port) {
    int server_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (server_sock < 0) {
        cerr << "Failed to create socket" << endl;
        return;
    }
    
    int opt = 1;
    setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    
    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(port);
    
    if (bind(server_sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        cerr << "Failed to bind to port " << port << endl;
        close(server_sock);
        return;
    }
    
    if (listen(server_sock, 10) < 0) {
        cerr << "Failed to listen" << endl;
        close(server_sock);
        return;
    }
    
    cout << "Web server started on http://localhost:" << port << endl;
    cout << "Open your browser and navigate to http://localhost:" << port << endl;
    
    while (keep_running) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        
        int client_sock = accept(server_sock, (struct sockaddr*)&client_addr, &client_len);
        if (client_sock < 0) continue;
        
        // Robust HTTP Request Reading
        vector<char> buffer(1024 * 1024 * 6); // 6MB buffer
        int total_bytes = 0;
        int header_end = -1;
        int content_length = 0;
        
        // Read loop
        while (total_bytes < buffer.size()) {
            int bytes_read = recv(client_sock, buffer.data() + total_bytes, buffer.size() - total_bytes, 0);
            if (bytes_read <= 0) break;
            
            total_bytes += bytes_read;
            
            // Check if we have headers
            if (header_end == -1) {
                string current_data(buffer.data(), total_bytes);
                size_t pos = current_data.find("\r\n\r\n");
                if (pos != string::npos) {
                    header_end = pos + 4;
                    
                    // Parse Content-Length
                    size_t cl_pos = current_data.find("Content-Length: ");
                    if (cl_pos != string::npos) {
                        size_t end = current_data.find("\r\n", cl_pos);
                        content_length = atoi(current_data.substr(cl_pos + 16, end - (cl_pos + 16)).c_str());
                    }
                }
            }
            
            // Check if we have the full request
            if (header_end != -1) {
                if (total_bytes >= header_end + content_length) {
                    break;
                }
            } else if (total_bytes > 8192 && content_length == 0) {
                 // Safety break if headers are too large or malformed
                 break; 
            }
        }
        
        if (total_bytes > 0) {
            string request(buffer.data(), total_bytes);
            handleRequest(client_sock, request);
        }
        
        close(client_sock);
    }
    
    close(server_sock);
}

int main() {
    signal(SIGINT, signal_handler);
    
    cout << "==================================================" << endl;
    cout << "   Real-Time Network IDS with Web Dashboard      " << endl;
    cout << "==================================================" << endl;
    
    global_rules = readRules("rules.txt");
    global_monitored_ips = readMonitoredIPs("monitored_ips.txt");
    loadIntelligence();
    
    pthread_t web_thread;
    cout << "Loaded " << global_rules.size() << " detection rules." << endl;
    cout << "Monitoring " << global_monitored_ips.size() << " IP addresses." << endl;
    cout << "\nStarting web server..." << endl;
    
    startWebServer(8080);
    
    return 0;
}
