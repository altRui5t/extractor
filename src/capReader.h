#include <string>
#include <memory>
#include <vector>
#include <cstdint>

#include <pcap.h>

class CapReader
{
public:
    CapReader(const std::string& pathToFile);
    virtual ~CapReader() noexcept;
    bool SaveImage(const std::string& srca, const std::string& srcp, const std::string& dsta, const std::string& dstp );

private:
    std::shared_ptr<std::vector<std::uint8_t>> ExtractData(const struct pcap_pkthdr *header,const u_char *packet, int& seq, int& ack);
    std::shared_ptr<std::vector<std::uint8_t>> ExtractTcpPayload(const struct pcap_pkthdr *header,const u_char *packet , int& seq, int& ack);
private:
    pcap_t *fileHandler {nullptr};
};