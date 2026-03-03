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

using namespace std;

// Global flag for graceful shutdown
volatile sig_atomic_t keep_running = 1;

void signal_handler(int signum) {
    keep_running = 0;
}

// Structure to represent a rule
struct Rule {
    string keyword;
    string severity;
    int port;           // -1 means any port
    string protocol;    // "TCP", "UDP", or "ANY"
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

// Structure to track connection attempts for attack detection
struct ConnectionTracker {
    map<string, int> syn_count;              // IP -> SYN count
    map<string, time_t> last_syn_time;       // IP -> last SYN time
    map<string, vector<int> > scanned_ports; // IP -> ports accessed
    map<string, time_t> last_packet_time;    // IP -> last packet time
};

ConnectionTracker tracker;
vector<PacketEvent> captured_events;
vector<Rule> global_rules;
vector<MonitoredIP> global_monitored_ips;

// Function to convert string to lowercase
string toLowerCase(const string& str) {
    string result = str;
    for (size_t i = 0; i < result.length(); i++) {
        if (result[i] >= 'A' && result[i] <= 'Z') {
            result[i] = result[i] + 32;
        }
    }
    return result;
}

// Function to trim whitespace
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

// Function to get current timestamp
string getCurrentTimestamp() {
    time_t now = time(0);
    char buffer[80];
    strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", localtime(&now));
    return string(buffer);
}

// Function to read rules from rules.txt
vector<Rule> readRules(const string& filename) {
    vector<Rule> rules;
    ifstream file(filename.c_str());
    
    if (!file.is_open()) {
        cerr << "Warning: Could not open " << filename << ", using default rules." << endl;
        // Add some default rules
        Rule r1; r1.keyword = "syn_flood"; r1.severity = "CRITICAL"; r1.port = -1; r1.protocol = "TCP";
        Rule r2; r2.keyword = "port_scan"; r2.severity = "HIGH"; r2.port = -1; r2.protocol = "ANY";
        Rule r3; r3.keyword = "ssh"; r3.severity = "MEDIUM"; r3.port = 22; r3.protocol = "TCP";
        Rule r4; r4.keyword = "http"; r4.severity = "LOW"; r4.port = 80; r4.protocol = "TCP";
        rules.push_back(r1);
        rules.push_back(r2);
        rules.push_back(r3);
        rules.push_back(r4);
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

// Function to read monitored IPs
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

// Function to write monitored IPs
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

// Function to check if IP is monitored
bool isIPMonitored(const string& ip, const vector<MonitoredIP>& monitoredIPs) {
    for (size_t i = 0; i < monitoredIPs.size(); i++) {
        if (monitoredIPs[i].ip == ip) {
            return true;
        }
    }
    return false;
}

// Function to add monitored IP
void addMonitoredIP(vector<MonitoredIP>& monitoredIPs, const string& ip, const string& note) {
    if (isIPMonitored(ip, monitoredIPs)) {
        cout << "IP " << ip << " is already being monitored." << endl;
        return;
    }
    
    MonitoredIP mip;
    mip.ip = ip;
    mip.note = note;
    monitoredIPs.push_back(mip);
    cout << "Added IP " << ip << " to monitored list." << endl;
}

// Function to remove monitored IP
void removeMonitoredIP(vector<MonitoredIP>& monitoredIPs, const string& ip) {
    for (size_t i = 0; i < monitoredIPs.size(); i++) {
        if (monitoredIPs[i].ip == ip) {
            for (size_t j = i; j < monitoredIPs.size() - 1; j++) {
                monitoredIPs[j] = monitoredIPs[j + 1];
            }
            monitoredIPs.pop_back();
            cout << "Removed IP " << ip << " from monitored list." << endl;
            return;
        }
    }
    cout << "IP " << ip << " not found in monitored list." << endl;
}

// Function to display monitored IPs
void displayMonitoredIPs(const vector<MonitoredIP>& monitoredIPs) {
    if (monitoredIPs.empty()) {
        cout << "No IPs are currently being monitored." << endl;
        return;
    }
    
    cout << "\n=== Monitored IP Addresses ===" << endl;
    for (size_t i = 0; i < monitoredIPs.size(); i++) {
        cout << (i + 1) << ". " << monitoredIPs[i].ip 
             << " - " << monitoredIPs[i].note << endl;
    }
    cout << endl;
}

// Function to get severity priority
int getSeverityPriority(const string& severity) {
    string lower = toLowerCase(severity);
    if (lower == "critical") return 4;
    if (lower == "high") return 3;
    if (lower == "medium") return 2;
    if (lower == "low") return 1;
    return 0;
}

// Function to detect attacks and determine severity
string analyzePacket(const PacketEvent& event) {
    string severity = "INFO";
    int highestPriority = 0;
    
    // Check for SYN flood
    if (event.protocol == "TCP" && event.flags.find('S') != string::npos) {
        time_t now = time(0);
        tracker.syn_count[event.source_ip]++;
        tracker.last_syn_time[event.source_ip] = now;
        
        if (tracker.syn_count[event.source_ip] > 50) {
            severity = "CRITICAL";
            highestPriority = 4;
        }
    }
    
    // Check for port scanning
    if (tracker.scanned_ports[event.source_ip].size() > 20) {
        if (getSeverityPriority("HIGH") > highestPriority) {
            severity = "HIGH";
            highestPriority = 3;
        }
    }
    
    // Check rules based on keywords in description
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
        
        // Check port-specific rules
        if (global_rules[i].port != -1 && event.dest_port == global_rules[i].port) {
            int priority = getSeverityPriority(global_rules[i].severity);
            if (priority > highestPriority) {
                highestPriority = priority;
                severity = global_rules[i].severity;
            }
        }
    }
    
    // Elevated severity for monitored IPs
    if (isIPMonitored(event.source_ip, global_monitored_ips)) {
        if (highestPriority < 2) {
            severity = "MEDIUM";
        }
    }
    
    return severity;
}

// Function to parse TCP flags
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

// Packet handler callback
void packet_handler(u_char* user_data, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    struct ether_header* eth_header = (struct ether_header*)packet;
    
    // Check if it's an IP packet
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
    
    // Track packets per IP
    tracker.last_packet_time[event.source_ip] = time(0);
    
    // Determine protocol
    if (ip_header->ip_p == IPPROTO_TCP) {
        event.protocol = "TCP";
        struct tcphdr* tcp_header = (struct tcphdr*)(packet + sizeof(struct ether_header) + sizeof(struct ip));
        event.source_port = ntohs(tcp_header->source);
        event.dest_port = ntohs(tcp_header->dest);
        event.flags = getTCPFlags(tcp_header);
        
        // Track ports for scan detection
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
        
        // Generate event description
        ostringstream desc;
        desc << "TCP connection from " << event.source_ip << ":" << event.source_port 
             << " to " << event.dest_ip << ":" << event.dest_port 
             << " [" << event.flags << "]";
        
        // Check for specific services
        if (event.dest_port == 22) desc << " SSH";
        else if (event.dest_port == 80) desc << " HTTP";
        else if (event.dest_port == 443) desc << " HTTPS";
        else if (event.dest_port == 21) desc << " FTP";
        else if (event.dest_port == 23) desc << " TELNET";
        else if (event.dest_port == 3389) desc << " RDP";
        
        // Check for SYN flood
        if (event.flags.find('S') != string::npos && tracker.syn_count[event.source_ip] > 50) {
            desc << " POSSIBLE_SYN_FLOOD";
        }
        
        event.event_description = desc.str();
        
    } else if (ip_header->ip_p == IPPROTO_UDP) {
        event.protocol = "UDP";
        struct udphdr* udp_header = (struct udphdr*)(packet + sizeof(struct ether_header) + sizeof(struct ip));
        event.source_port = ntohs(udp_header->source);
        event.dest_port = ntohs(udp_header->dest);
        
        ostringstream desc;
        desc << "UDP packet from " << event.source_ip << ":" << event.source_port 
             << " to " << event.dest_ip << ":" << event.dest_port;
        
        if (event.dest_port == 53) desc << " DNS";
        else if (event.dest_port == 67 || event.dest_port == 68) desc << " DHCP";
        else if (event.dest_port == 123) desc << " NTP";
        
        event.event_description = desc.str();
        
    } else if (ip_header->ip_p == IPPROTO_ICMP) {
        event.protocol = "ICMP";
        event.event_description = "ICMP packet from " + event.source_ip + " to " + event.dest_ip;
    } else {
        event.protocol = "OTHER";
        ostringstream desc;
        desc << "Protocol " << (int)ip_header->ip_p << " from " << event.source_ip 
             << " to " << event.dest_ip;
        event.event_description = desc.str();
    }
    
    // Check for port scanning
    if (tracker.scanned_ports[event.source_ip].size() > 20) {
        event.event_description += " POSSIBLE_PORT_SCAN";
    }
    
    // Analyze and determine severity
    event.severity = analyzePacket(event);
    
    // Store the event
    captured_events.push_back(event);
    
    // Print high severity events to console
    if (getSeverityPriority(event.severity) >= 2) {
        cout << "[" << event.severity << "] " << event.timestamp << " - " 
             << event.event_description << endl;
    }
}

// Function to list available network interfaces
void listInterfaces() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t* alldevs;
    pcap_if_t* device;
    
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        cerr << "Error finding devices: " << errbuf << endl;
        return;
    }
    
    cout << "\n=== Available Network Interfaces ===" << endl;
    int i = 1;
    for (device = alldevs; device != NULL; device = device->next) {
        cout << i++ << ". " << device->name;
        if (device->description) {
            cout << " (" << device->description << ")";
        }
        cout << endl;
    }
    
    pcap_freealldevs(alldevs);
}

// Function to escape CSV fields
string escapeCSV(const string& field) {
    if (field.find(',') != string::npos || field.find('"') != string::npos) {
        string escaped = "\"";
        for (size_t i = 0; i < field.length(); i++) {
            if (field[i] == '"') {
                escaped += "\"\"";
            } else {
                escaped += field[i];
            }
        }
        escaped += "\"";
        return escaped;
    }
    return field;
}

// Function to write results to CSV
void writeResultsToCSV(const string& filename, bool filterMonitored) {
    ofstream output(filename.c_str());
    if (!output.is_open()) {
        cerr << "Error: Could not create " << filename << endl;
        return;
    }
    
    output << "Timestamp,Source IP,Source Port,Dest IP,Dest Port,Protocol,Flags,Size,Event,Severity" << endl;
    
    int infoCount = 0, lowCount = 0, mediumCount = 0, highCount = 0, criticalCount = 0;
    
    for (size_t i = 0; i < captured_events.size(); i++) {
        const PacketEvent& event = captured_events[i];
        
        // Filter for monitored IPs if requested
        if (filterMonitored && !isIPMonitored(event.source_ip, global_monitored_ips)) {
            continue;
        }
        
        output << escapeCSV(event.timestamp) << ","
               << escapeCSV(event.source_ip) << ","
               << event.source_port << ","
               << escapeCSV(event.dest_ip) << ","
               << event.dest_port << ","
               << escapeCSV(event.protocol) << ","
               << escapeCSV(event.flags) << ","
               << event.packet_size << ","
               << escapeCSV(event.event_description) << ","
               << escapeCSV(event.severity) << endl;
        
        string sev = toLowerCase(event.severity);
        if (sev == "critical") criticalCount++;
        else if (sev == "high") highCount++;
        else if (sev == "medium") mediumCount++;
        else if (sev == "low") lowCount++;
        else infoCount++;
    }
    
    output << "---SUMMARY---" << endl;
    output << "INFO: " << infoCount << endl;
    output << "LOW: " << lowCount << endl;
    output << "MEDIUM: " << mediumCount << endl;
    output << "HIGH: " << highCount << endl;
    output << "CRITICAL: " << criticalCount << endl;
    
    output.close();
    
    cout << "\nResults written to " << filename << endl;
    cout << "Total events captured: " << captured_events.size() << endl;
    cout << "\nSeverity Summary:" << endl;
    cout << "INFO: " << infoCount << endl;
    cout << "LOW: " << lowCount << endl;
    cout << "MEDIUM: " << mediumCount << endl;
    cout << "HIGH: " << highCount << endl;
    cout << "CRITICAL: " << criticalCount << endl;
}

// Function to start packet capture
void startCapture(const string& interface, int duration) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle;
    
    cout << "\nOpening interface: " << interface << endl;
    
    // Open the device for capturing
    handle = pcap_open_live(interface.c_str(), BUFSIZ, 1, 1000, errbuf);
    
    if (handle == NULL) {
        cerr << "Error opening device: " << errbuf << endl;
        cerr << "\nNote: You may need to run this program with root/administrator privileges." << endl;
        cerr << "Try: sudo ./ids" << endl;
        return;
    }
    
    cout << "Capturing packets for " << duration << " seconds..." << endl;
    cout << "Press Ctrl+C to stop early." << endl;
    cout << "High severity events will be displayed below:\n" << endl;
    
    // Clear previous capture data
    captured_events.clear();
    tracker.syn_count.clear();
    tracker.last_syn_time.clear();
    tracker.scanned_ports.clear();
    tracker.last_packet_time.clear();
    
    // Set up signal handler
    signal(SIGINT, signal_handler);
    
    time_t start_time = time(0);
    keep_running = 1;
    
    // Capture packets
    while (keep_running && (time(0) - start_time) < duration) {
        pcap_dispatch(handle, 10, packet_handler, NULL);
    }
    
    cout << "\n\nCapture complete!" << endl;
    cout << "Total packets captured: " << captured_events.size() << endl;
    
    // Close the handle
    pcap_close(handle);
    
    // Write results
    writeResultsToCSV("result.csv", false);
}

// Function to display statistics for specific IP
void displayIPStats(const string& ip) {
    int infoCount = 0, lowCount = 0, mediumCount = 0, highCount = 0, criticalCount = 0;
    int totalEvents = 0;
    
    cout << "\n=== Statistics for IP: " << ip << " ===" << endl;
    
    for (size_t i = 0; i < captured_events.size(); i++) {
        if (captured_events[i].source_ip == ip) {
            totalEvents++;
            string sev = toLowerCase(captured_events[i].severity);
            if (sev == "critical") criticalCount++;
            else if (sev == "high") highCount++;
            else if (sev == "medium") mediumCount++;
            else if (sev == "low") lowCount++;
            else infoCount++;
        }
    }
    
    if (totalEvents == 0) {
        cout << "No events found for this IP in current capture." << endl;
        return;
    }
    
    cout << "Total Events: " << totalEvents << endl;
    cout << "INFO: " << infoCount << endl;
    cout << "LOW: " << lowCount << endl;
    cout << "MEDIUM: " << mediumCount << endl;
    cout << "HIGH: " << highCount << endl;
    cout << "CRITICAL: " << criticalCount << endl;
    
    cout << "\nRecent events from this IP:" << endl;
    int count = 0;
    for (size_t i = 0; i < captured_events.size() && count < 10; i++) {
        if (captured_events[i].source_ip == ip) {
            cout << captured_events[i].timestamp << " - " 
                 << captured_events[i].event_description << " [" 
                 << captured_events[i].severity << "]" << endl;
            count++;
        }
    }
}

// Function to manage monitored IPs
void manageMonitoredIPs(const string& monitorFile) {
    while (true) {
        cout << "\n=== Monitored IP Management ===" << endl;
        cout << "1. View monitored IPs" << endl;
        cout << "2. Add IP to monitor" << endl;
        cout << "3. Remove IP from monitoring" << endl;
        cout << "4. Save and return to main menu" << endl;
        cout << "Enter choice: ";
        
        int choice;
        cin >> choice;
        cin.ignore();
        
        if (choice == 1) {
            displayMonitoredIPs(global_monitored_ips);
        } else if (choice == 2) {
            cout << "Enter IP address: ";
            string ip;
            getline(cin, ip);
            ip = trim(ip);
            
            cout << "Enter note/description: ";
            string note;
            getline(cin, note);
            note = trim(note);
            
            addMonitoredIP(global_monitored_ips, ip, note);
        } else if (choice == 3) {
            cout << "Enter IP address to remove: ";
            string ip;
            getline(cin, ip);
            ip = trim(ip);
            
            removeMonitoredIP(global_monitored_ips, ip);
        } else if (choice == 4) {
            writeMonitoredIPs(monitorFile, global_monitored_ips);
            cout << "Monitored IPs saved." << endl;
            break;
        } else {
            cout << "Invalid choice. Try again." << endl;
        }
    }
}

int main() {
    cout << "==================================================" << endl;
    cout << "       Real-Time Network Intrusion Detection     " << endl;
    cout << "==================================================" << endl;
    
    string ruleFile = "rules.txt";
    string monitorFile = "monitored_ips.txt";
    
    // Load rules and monitored IPs
    global_rules = readRules(ruleFile);
    global_monitored_ips = readMonitoredIPs(monitorFile);
    
    cout << "\nLoaded " << global_rules.size() << " detection rules." << endl;
    cout << "Monitoring " << global_monitored_ips.size() << " IP addresses." << endl;
    
    while (true) {
        cout << "\n=== Main Menu ===" << endl;
        cout << "1. List network interfaces" << endl;
        cout << "2. Start packet capture" << endl;
        cout << "3. View current capture statistics" << endl;
        cout << "4. Analyze specific IP from capture" << endl;
        cout << "5. Generate filtered report (monitored IPs only)" << endl;
        cout << "6. Manage monitored IPs" << endl;
        cout << "7. Exit" << endl;
        cout << "Enter choice: ";
        
        int choice;
        cin >> choice;
        cin.ignore();
        
        if (choice == 1) {
            listInterfaces();
        } else if (choice == 2) {
            cout << "\nEnter interface name (e.g., eth0, wlan0, en0): ";
            string interface;
            getline(cin, interface);
            interface = trim(interface);
            
            cout << "Enter capture duration in seconds (e.g., 60): ";
            int duration;
            cin >> duration;
            cin.ignore();
            
            if (duration <= 0 || duration > 3600) {
                cout << "Invalid duration. Using 60 seconds." << endl;
                duration = 60;
            }
            
            startCapture(interface, duration);
            
        } else if (choice == 3) {
            if (captured_events.empty()) {
                cout << "No packets captured yet. Start a capture first." << endl;
            } else {
                writeResultsToCSV("result.csv", false);
            }
        } else if (choice == 4) {
            if (captured_events.empty()) {
                cout << "No packets captured yet. Start a capture first." << endl;
            } else {
                cout << "Enter IP address to analyze: ";
                string ip;
                getline(cin, ip);
                ip = trim(ip);
                displayIPStats(ip);
            }
        } else if (choice == 5) {
            if (captured_events.empty()) {
                cout << "No packets captured yet. Start a capture first." << endl;
            } else if (global_monitored_ips.empty()) {
                cout << "No IPs are being monitored. Add IPs first." << endl;
            } else {
                writeResultsToCSV("monitored_report.csv", true);
            }
        } else if (choice == 6) {
            manageMonitoredIPs(monitorFile);
        } else if (choice == 7) {
            cout << "\nExiting IDS. Goodbye!" << endl;
            break;
        } else {
            cout << "Invalid choice. Try again." << endl;
        }
    }
    
    return 0;
}
