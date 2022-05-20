import pyshark
import collections

# ======== www.example.com ========
# Variables
example = pyshark.FileCapture('example.pcap', only_summaries=True)
protocolList = []
syn = []
syn_ack = []
http_queries = []
sessions = 0

# Splitting metadata and counting sessions by "Client Hello" messages -> Informing of '3 way handshake' has been made.
for packet in example:
    line = str(packet)
    formattedLine = line.split(" ")
    protocolList.append(formattedLine[4])

    if formattedLine[4] == "TCP":
        if formattedLine[9] == "[SYN]":
            syn.append(formattedLine[6])
        elif (formattedLine[9] == "[SYN,") & (formattedLine[10] == "ACK]"):
            syn_ack.append(formattedLine[8])
            syn.remove(formattedLine[8])
        elif formattedLine[9] == "[ACK]":
            check = formattedLine[6] in syn_ack
            if check:
                sessions += 1
                syn_ack.remove(formattedLine[6])

    if formattedLine[4] == "HTTP":
        if not formattedLine[6] == "HTTP/1.1":
            req = "HTTP " + formattedLine[6] + formattedLine[7] + formattedLine[8]
            http_queries.append(req)
        else:
            res = formattedLine[6:(len(formattedLine)-1)]
            res = " ".join(res)
            http_queries.append(res)


# Counting by protocol types.
counter = collections.Counter(protocolList)


# Counting total number of packets.
def count(packets_list):
    packets = 0
    for value in packets_list.values():
        packets += value
    return packets


def print_packets(dict):
    for key in dict:
        print(f"{key} : {dict.get(key)}")


def print_http(lst):
    for query in lst:
        print(query)


count_packets = count(counter)
count_DNS = counter.get("DNS")
count_HTTP = counter.get("HTTP")
print("The kinds of packets that were captured and their frequency:")
print_packets(counter)
print("\n")
print("All HTTP requests and responses that were captured: ")
print_http(http_queries)
print("\n")
print(f"Total number of packets: {count_packets}")
print(f"Total number of DNS Queries: {count_DNS}")
print(f"Total number of HTTP Queries: {count_HTTP}")
print(f"Total number of sessions: {sessions}")

print("=============================================================================")

# ======== www.ynet.co.il ========
ynet = pyshark.FileCapture('ynet.pcap', only_summaries=True)
protocolList = []
syn = []
syn_ack = []
http_queries = []
sessions = 0

# Splitting metadata and counting sessions by "Client Hello" messages -> Informing of '3 way handshake' has been made.
for packet in ynet:
    line = str(packet)
    formattedLine = line.split(" ")
    protocolList.append(formattedLine[4])

    if formattedLine[4] == "TCP":
        if formattedLine[9] == "[SYN]":
            syn.append(formattedLine[6])
        elif (formattedLine[9] == "[SYN,") & (formattedLine[10] == "ACK]"):
            syn_ack.append(formattedLine[8])
            syn.remove(formattedLine[8])
        elif formattedLine[9] == "[ACK]":
            check = formattedLine[6] in syn_ack
            if check:
                sessions += 1
                syn_ack.remove(formattedLine[6])

    if formattedLine[4] == "HTTP":
        if not formattedLine[6] == "HTTP/1.1":
            req = "HTTP " + formattedLine[6] + formattedLine[7] + formattedLine[8]
            http_queries.append(req)
        else:
            res = formattedLine[6:(len(formattedLine)-1)]
            res = " ".join(res)
            http_queries.append(res)

# Counting by protocol types.
counter = collections.Counter(protocolList)

count_packets = count(counter)
count_DNS = counter.get("DNS")
count_HTTP = counter.get("HTTP")
print("The kinds of packets that were captured and their frequency:")
print_packets(counter)
print("\n")
print("All HTTP requests and responses that were captured: ")
print_http(http_queries)
print("\n")
print(f"Total number of packets: {count_packets}")
print(f"Total number of DNS Queries: {count_DNS}")
print(f"Total number of HTTP Queries: {count_HTTP}")
print(f"Total number of sessions: {sessions}")
