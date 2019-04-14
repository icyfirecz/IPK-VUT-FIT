#include "ipk-scan.hpp"

// Method for error handling.
// errorMessage - Message error, which is going to get printed.
// errCode - Number of code that is going to be returned.
void Scanner::print_error_exit(string errorMessage, int errCode)
{
    cerr << errorMessage;
    exit(errCode);
}

// Method is implementation explode from PHP.
// String is splitted into vector by delimeter.
// content - string that will be splitted
// delimeter - delimeter
vector<string> Scanner::explode(string content, char delimeter)
{
    vector<string> tokens;
    stringstream data(content);

    string line;

    while (getline(data, line, delimeter))
    {
        tokens.push_back(line);
    }

    return tokens;
}

// Method parses the ports from unformated string from command
// line, to the vector of number of ports.
// unformatedPorts - unformated string of ports
vector<int> Scanner::parse_ports_range(string unformatedPorts)
{
    // Regex for ports: 1-65535
    regex_t regex;

    if (regcomp(&regex, "^[0-9]{1,5}+-[0-9]{1,5}+$", REG_EXTENDED) != 0)
    {
        cout << "rip regex\n";
        exit(1);
    }

    if (regexec(&regex, unformatedPorts.c_str(), 0, NULL, 0) == 0)
    {
        vector<string> portsString = this->explode(unformatedPorts, '-');

        int startingPort = atoi(portsString[0].c_str());
        int endingPort = atoi(portsString[1].c_str());

        if (startingPort > endingPort || startingPort > MAX_PORT_NUMBER || endingPort > MAX_PORT_NUMBER)
        {
            this->print_error_exit("Error, wrong order/number of requested ports!\n", 1);
        }

        vector<int> ports;
        for (; startingPort <= endingPort; startingPort++)
        {
            ports.push_back(startingPort);
        }

        regfree(&regex);
        return ports;
    }

    regfree(&regex);

    regex_t regex2;
    if (regcomp(&regex2, "^[0-9]{1,5}(,[0-9]{1,5})*$", REG_EXTENDED) != 0)
    {
        cout << "rip regex\n";
        exit(1);
    }
    // Regex for ports: 1,2,420,1337,65535
    if (regexec(&regex2, unformatedPorts.c_str(), 0, NULL, 0) == 0)
    {
        vector<string> portsString = this->explode(unformatedPorts, ',');

        vector<int> ports;
        for (unsigned index = 0; index < portsString.size(); index++)
        {
            ports.push_back(atoi(portsString[index].c_str()));
        }

        return ports;
        regfree(&regex2);
    }
    else
    {
        regfree(&regex2);
        this->print_error_exit("Error, wrong UDP/TCP ports format!\n", 1);

        vector<int> ThisIsDeadCode;
        return ThisIsDeadCode;
    }

    // pedantic is fun :)
    vector<int> ThisIsDeadCode;
    return ThisIsDeadCode;
}

// Method parses given interface from command line.
void Scanner::parse_interface(string interface)
{
    struct ifaddrs *interfaces;
    struct ifaddrs *backup;

    getifaddrs(&interfaces);

    backup = interfaces;

    while (interfaces != NULL)
    {
        if (strcasecmp(interfaces->ifa_name, interface.c_str()) == 0 && interfaces->ifa_addr->sa_family != AF_PACKET)
            break;

        interfaces = interfaces->ifa_next;
    }

    if (interfaces == NULL)
    {
        this->print_error_exit("Error, given interface was not found!\n", 1);
    }

    this->localIpFamily = interfaces->ifa_addr->sa_family;
    this->wasInterface = true;
    this->interfaceName = interface;

    if (this->localIpFamily == AF_INET || this->localIpFamily == AF_INET6)
    {
        this->localIpFamily = interfaces->ifa_addr->sa_family;
        struct sockaddr *tmpAddress = interfaces->ifa_addr;
        int error = getnameinfo(tmpAddress,
                                (this->localIpFamily == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6),
                                this->localIp, NI_MAXHOST,
                                NULL, 0, NI_NUMERICHOST);

        if (error < 0)
        {
            this->print_error_exit("Error, cannot fetch local ip!\n", 1);
        }
    }
    else
    {
        this->print_error_exit("Error, given interface is not ipv4 or ipv6.\n", 1);
    }

    freeifaddrs(backup);
}

// Method parses arguments from command line and sets up
// Scanner attributes.
void Scanner::parse_arguments(int argc, char *argv[])
{
    int option;

    static struct option long_options[] =
        {
            {"pt", required_argument, &option, PT_ARGUMENT},
            {"pu", required_argument, &option, PU_ARGUMENT},
            {"i", required_argument, &option, I_ARGUMENT},
            {"wu", required_argument, &option, WU_ARGUMENT},
            {"wt", required_argument, &option, WT_ARGUMENT}};

    while ((getopt_long_only(argc, argv, "", long_options, &option) != -1))
    {
        switch (option)
        {
        case PT_ARGUMENT:
            this->tcpTargetPorts = this->parse_ports_range(optarg);
            break;
        case PU_ARGUMENT:
            this->udpTargetPorts = this->parse_ports_range(optarg);
            break;
        case I_ARGUMENT:
            this->parse_interface(optarg);
            break;
        case WU_ARGUMENT:
            this->icmpWaitTime = stof(optarg);
            break;
        case WT_ARGUMENT:
            this->tcpWaitTime = stof(optarg);
            break;
        default:
            this->print_error_exit("Error, wrong argument switch!\n", 1);
        }
    }

    if ((optind + 1) != argc)
    {
        this->print_error_exit("Error, wrong number of arguments!\n", 1);
    }

    this->targetByInput = argv[optind];
}

void Scanner::fetch_local_ip()
{
    if (wasInterface)
        return;

    ifaddrs *devices, *device;
    getifaddrs(&devices);

    device = devices;

    while (device != NULL)
    {
        if ((device->ifa_flags & IFF_UP) != 0 and strcasecmp(device->ifa_name, "lo") != 0 and device->ifa_addr->sa_family == this->targetIpFamily)
        {
            this->localIpFamily = this->targetIpFamily;
            if (this->localIpFamily == AF_INET || this->localIpFamily == AF_INET6)
            {
                int error = getnameinfo(device->ifa_addr,
                                        (this->localIpFamily == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6),
                                        this->localIp, NI_MAXHOST,
                                        NULL, 0, NI_NUMERICHOST);
                if (error != 0)
                {
                    this->print_error_exit("Error, cannot fetch local IP!\n", 1);
                }
                break;
            }
        }
        device = device->ifa_next;
    }

    if (device == NULL)
    {
        this->print_error_exit("Error, no interface found!\n", 1);
    }
}
// Method fetches the IP address of the user's target.
void Scanner::fetch_target_IP()
{
    struct addrinfo *result = NULL;

    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));

    if(this->wasInterface)
    {
        hints.ai_family = this->localIpFamily;
    }
    else
    {
        hints.ai_family = AF_UNSPEC;
    }
    
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = 0;

    if (getaddrinfo(this->targetByInput.c_str(), NULL, &hints, &result) != 0)
    {
        this->print_error_exit("Error, cannot fetch target service!\n Check if your interface IP family corresponds with target ip family!\n", 1);
    }

    void *addressPointer;
    char IPaddress[100];

    switch (result->ai_family)
    {
    case AF_INET:
        addressPointer = &((struct sockaddr_in *)result->ai_addr)->sin_addr;
        this->targetIpFamily = AF_INET;
        break;
    case AF_INET6:
        addressPointer = &((struct sockaddr_in6 *)result->ai_addr)->sin6_addr;
        this->targetIpFamily = AF_INET6;
        break;
    default:
        this->print_error_exit("Unknown error in getting IP.\n", 1);
    }

    inet_ntop(result->ai_family, addressPointer, IPaddress, 100);
    this->targetIp = IPaddress;

    cout << "Interesting ports on " << this->targetByInput << " (" << this->targetIp << "): \n";

    freeaddrinfo(result);
}

// Scanner contructor
Scanner::Scanner()
{
    this->wasInterface = false;
    memset(&this->localIp, 0, sizeof(this->localIp));
    this->icmpWaitTime = 1;
    this->tcpWaitTime = 1;
}

int main(int argc, char *argv[])
{
    Scanner *scanner = new Scanner;
    scanner->parse_arguments(argc, argv);
    scanner->fetch_target_IP();
    scanner->fetch_local_ip();
    cout << "PORT         STATE\n";

    scanner->prepare_and_start_udp_scan();
    scanner->prepare_and_start_tcp_scan();
    return 0;
}