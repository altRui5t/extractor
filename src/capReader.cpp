#include <string>
#include <memory>
#include <vector>
#include <cstdint>
#include <stdexcept>
#include <iostream>
#include <algorithm>
#include <iterator> 
#include <fstream>

#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <pcap.h>

#include "capReader.h"


CapReader::CapReader(const std::string& pathToFile)
{
//check file exists
//open file 
    char error_buffer[PCAP_ERRBUF_SIZE];
    fileHandler = pcap_open_offline(pathToFile.c_str(), error_buffer);
    if (fileHandler == nullptr)
        throw std::runtime_error("Couldnt open file: " + pathToFile + " error: " + error_buffer);

}

CapReader::~CapReader()
{
    if (fileHandler != nullptr)
        pcap_close(fileHandler);
}

std::string GetValueFromHttpString(const std::string& stringName, std::vector<std::uint8_t>& data){

    std::vector<std::uint8_t> sn;
    sn.assign(reinterpret_cast<const std::uint8_t*>(stringName.data()), reinterpret_cast<const std::uint8_t*>(stringName.data()) + stringName.length());
    auto snItr = std::search(data.begin(),data.end(),sn.begin(), sn.end());
    if (snItr != data.end()){
        auto stringEnd = std::find(snItr, data.end(), '\r');
        return std::string(snItr+sn.size(), stringEnd);
    }
    return {};
}


bool CapReader::SaveImage(const std::string& srca, const std::string& srcp, const std::string& dsta, const std::string& dstp )
{

    pcap_pkthdr tmp;
    //включаем фильтрацию по адресам и портам
    //src srcaddr && src port Port && dst dstaddr && dst port Port 
    struct bpf_program filter;
    bpf_u_int32 ip;
    
    std::string filterString {"src " + srca + " && src port " + srcp + " && dst " + dsta + " && dst port " + dstp};
    std::cout << "[DBG]" << "filter string: " << filterString <<  std::endl;

    if (pcap_compile(fileHandler, &filter, filterString.c_str(), 0, PCAP_NETMASK_UNKNOWN ) == -1) {
        printf("Bad filter - %s\n", pcap_geterr(fileHandler));
        return false;
    }

    std::cout << "[DBG]" << "Compiled filter." << std::endl;

    if (pcap_setfilter(fileHandler, &filter) == -1) {
        printf("Error setting filter - %s\n", pcap_geterr(fileHandler));
        return false;
    }

    std::cout << "[DBG]" << "Setuped filter." << std::endl;

    auto result = std::make_shared<std::vector<std::uint8_t>>(); 
    int seq, ack, prevSeq, prevAck , counter {0}, reassembledParts{0};
    
    while (true){
        auto packetPointer = pcap_next(fileHandler, &tmp);
        if (packetPointer == nullptr)
            break;
        std::cout << "[DBG]" << "Have next packet " << ++counter << std::endl;
        auto packet = ExtractData(&tmp, packetPointer, seq, ack);    
        if (packet.get())
        {
            int payloadLength = packet->size();
            if (ack == prevAck && payloadLength > 6 ){
                    result->insert(result->end(), packet->begin(), packet->end());
                    reassembledParts++;
            }

        }
        prevSeq = seq;
        prevAck = ack;
    }
    // из полученного массива получаем content-length и content-type.
    // определяем конец http \r\n\r\n всё дальнейшее сохраняем, как картинку.
   
    
    auto contentLength = GetValueFromHttpString("Content-Length:",  *(result.get()) );
    if (contentLength.empty()){
        std::cout << "[DBG] couldnt find Content-Length in http." << std::endl;    
        return false;
    }

    int imageLength = std::stoi( contentLength );
    
    std::cout << "[DBG] content size " << imageLength << std::endl;    
    if (imageLength > result->size()){
        std::cout << "[DBG] reassembled size is lower than content size" << std::endl;    
        return false;
    }

    auto contentType = GetValueFromHttpString("Content-Type:",  *(result.get()) );
    if (contentType.empty()){
        std::cout << "[DBG] couldnt find Content-Type in http." << std::endl;    
        return false;
    }
    auto extensionStart = contentType.find("/") + 1 ;
    auto extension = contentType.substr(extensionStart , contentType.length() - extensionStart);

    std::cout << "[DBG] extension:" << extension <<  std::endl;    

    std::string httpEnd {"\r\n\r\n"};
    auto httpEndItr = std::search(result->begin(),result->end(),httpEnd.begin(), httpEnd.end());

    httpEndItr +=  httpEnd.size();


    std::ofstream fout("image." + extension, std::ios::out | std::ios::binary);
    fout.write((char*)(&(*httpEndItr)), imageLength);
    fout.close();
    std::cout << "Image saved to file: " <<  "image." + extension << std::endl;
    return true;

    /*
    std::cout << "[DBG] total reassembled size " << result->size() << " parts: " << reassembledParts << std::endl;
    std::copy(result->begin(), result->end(), std::ostream_iterator<char>(std::cout, ""));
    return false;
    */
}

std::shared_ptr<std::vector<std::uint8_t>> CapReader::ExtractData(const struct pcap_pkthdr *header,const u_char *packet, int& seq, int& ack)
{
    return ExtractTcpPayload(header, packet,seq,ack);
}

std::shared_ptr<std::vector<std::uint8_t>> CapReader::ExtractTcpPayload(const struct pcap_pkthdr *header,const u_char *packet, int& seq, int& ack)
{
    struct ether_header *eth_header;
    eth_header = (struct ether_header *) packet;
    if (ntohs(eth_header->ether_type) != ETHERTYPE_IP) {
        //not an IP
        return {nullptr};
    }

    /* The total packet length, including all headers
       and the data payload is stored in
       header->len and header->caplen. Caplen is
       the amount actually available, and len is the
       total packet length even if it is larger
       than what we currently have captured. If the snapshot
       length set with pcap_open_live() is too small, you may
       not have the whole packet. */
  //  printf("Total packet available: %d bytes\n", header->caplen);
  //  printf("Expected packet size: %d bytes\n", header->len);

    /* Pointers to start point of various headers */
    const u_char *ip_header;
    const u_char *tcp_header;
    const u_char *payload;

    /* Header lengths in bytes */
    int ethernet_header_length = 14; /* Doesn't change */
    int ip_header_length;
    int tcp_header_length;
    int payload_length;

    /* Find start of IP header */
    ip_header = packet + ethernet_header_length;
    /* The second-half of the first byte in ip_header
       contains the IP header length (IHL). */
    ip_header_length = ((*ip_header) & 0x0F);
    /* The IHL is number of 32-bit segments. Multiply
       by four to get a byte count for pointer arithmetic */
    ip_header_length = ip_header_length * 4;
    //printf("IP header length (IHL) in bytes: %d\n", ip_header_length);

    /* Now that we know where the IP header is, we can 
       inspect the IP header for a protocol number to 
       make sure it is TCP before going any further. 
       Protocol is always the 10th byte of the IP header */
    u_char protocol = *(ip_header + 9);
    if (protocol != IPPROTO_TCP) {
        //printf("Not a TCP packet. Skipping...\n\n");
        return {nullptr};
    }

    /* Add the ethernet and ip header length to the start of the packet
       to find the beginning of the TCP header */
    tcp_header = packet + ethernet_header_length + ip_header_length;
    /* TCP header length is stored in the first half 
       of the 12th byte in the TCP header. Because we only want
       the value of the top half of the byte, we have to shift it
       down to the bottom half otherwise it is using the most 
       significant bits instead of the least significant bits */
    seq = ntohl(*((int*)(tcp_header + 4)));
    ack = ntohl(*((int*)(tcp_header + 8)));
    printf("Seq: %d Ack: %d\n", seq, ack);
    tcp_header_length = ((*(tcp_header + 12)) & 0xF0) >> 4;
    /* The TCP header length stored in those 4 bits represents
       how many 32-bit words there are in the header, just like
       the IP header length. We multiply by four again to get a
       byte count. */
    tcp_header_length = tcp_header_length * 4;
    //printf("TCP header length in bytes: %d\n", tcp_header_length);

    /* Add up all the header sizes to find the payload offset */
    int total_headers_size = ethernet_header_length+ip_header_length+tcp_header_length;
    //printf("Size of all headers combined: %d bytes\n", total_headers_size);
    payload_length = header->caplen -
        (ethernet_header_length + ip_header_length + tcp_header_length);
    //printf("Payload size: %d bytes\n", payload_length);
    payload = packet + total_headers_size;
    //printf("Memory address where payload begins: %p\n\n", payload);

    if (payload_length > 0){
        auto result  = std::make_shared<std::vector<std::uint8_t>>();
        result->assign(payload,payload + payload_length);
        return result;
    }

    return {nullptr};
}
