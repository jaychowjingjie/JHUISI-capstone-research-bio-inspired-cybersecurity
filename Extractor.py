from scapy.utils import RawPcapReader
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP
from scapy.utils import rdpcap
import os
import pandas as pd
from statistics import stdev
from statistics import mean
import arff
import numpy
feature_names = ['Window size', 'Source port', 'Destination port', 'First packet size', 'forward packets',
                 'forward total bytes', 'Min forward inter arrival time difference',
                 'Max forward inter arrival time difference', 'Mean forward inter arrival time difference',
                 'STD forward inter arrival time difference', 'Mean forward packets', 'STD forward packets',
                 'backward packets', 'backward total bytes',
                 'Min backward inter arrival time difference', 'Max backward inter arrival time difference',
                 'Mean backward inter arrival time difference', 'STD backward inter arrival time difference',
                 'Mean backward packets', 'STD backward packets', 'Mean backward TTL value', 'Total packets',
                 'Minimum packet size', 'Maximum packet size', 'Mean packet size', 'class']
correct_names = []
for name in feature_names:
    correct_names.append(name.replace(' ', '_'))


def dict_to_df(vector):
    df = pd.DataFrame(columns=correct_names)
    df = df.append(vector, ignore_index=True)
    return df


# takes a pcap file as input and returns a list of the raw packets
def get_packets(filename):
    pkt_list = list()
    for pkt_data in rdpcap(filename):
        pkt_list.append(pkt_data)
    return pkt_list


# extracts the IPv4 portion of a packet returns returns None if one doesn't exist
def get_ip(pkt_data):
    if pkt_data.name != 'Ethernet':
        ether_pkt = Ether(pkt_data)
    else:
        ether_pkt = pkt_data
    if 'type' not in ether_pkt.fields:
        # LLC frames will have 'len' instead of 'type'.
        # We disregard those
        return None

    if ether_pkt.type != 0x0800 and ether_pkt.type != 0x8100:  # Because vms exist
        # disregard non-IPv4 packets
        return None

    ip_pkt = ether_pkt[IP]
    if ip_pkt.proto != 6:
        # Ignore non-TCP packet
        return None
    return ip_pkt


# Extractor for basic features(size, # of packets, TTL values)
def basic_features(pkt_list):
    result = dict()
    for_bytes, back_bytes = [], []
    ttl = []
    src = ''
    # Scapy reads files differently than live traffic

    for pkt_data in pkt_list:
        ip_packet = get_ip(pkt_data)
        if ip_packet is None:
            continue
        # Set source and dst for forwards and backwards features
        if len(for_bytes) == 0:
            src = ip_packet.src
        packet_len = len(ip_packet[TCP])

        # Forward packet features
        if ip_packet.src == src:
            for_bytes.append(packet_len)

        # Backward Packet Features
        else:
            back_bytes.append(packet_len)
            ttl.append(ip_packet.ttl)
    # Somethings broke
    if len(back_bytes) + len(for_bytes) <= 0:
        return result
    result['forward packets'.replace(' ', '_')] = len(for_bytes)
    result['backward packets'.replace(' ', '_')] = len(back_bytes)
    result['forward total bytes'.replace(' ', '_')] = sum(for_bytes)
    result['backward total bytes'.replace(' ', '_')] = sum(back_bytes)
    result['Total packets'.replace(' ', '_')] = len(back_bytes) + len(for_bytes)
    result['Mean packet size'.replace(' ', '_')] = (sum(back_bytes) + sum(for_bytes)) / (len(back_bytes) + len(for_bytes))
    result['Minimum packet size'.replace(' ', '_')] = min(back_bytes, default=1000) if min(back_bytes, default=1000) < min(for_bytes) \
        else min(for_bytes)
    result['Maximum packet size'.replace(' ', '_')] = max(back_bytes, default=0) if max(back_bytes, default=0) > max(for_bytes) \
        else max(for_bytes)
    result['Minimum forward packet'.replace(' ', '_')] = min(for_bytes)
    result['Minimum backward packet'.replace(' ', '_')] = min(back_bytes, default=0)
    result['Maximum forward packet'.replace(' ', '_')] = max(for_bytes)
    result['Maximum backward packet'.replace(' ', '_')] = max(back_bytes, default=0)
    result['Mean forward packets'.replace(' ', '_')] = sum(for_bytes)/len(for_bytes)
    if len(back_bytes) > 0:
        result['Mean backward TTL value'.replace(' ', '_')] = mean(ttl)
        result['Mean backward packets'.replace(' ', '_')] = mean(back_bytes)

    if len(for_bytes) > 1:
        result['STD forward packets'.replace(' ', '_')] = stdev(for_bytes)
    if len(back_bytes) > 1:
        result['STD backward packets'.replace(' ', '_')] = stdev(back_bytes)
    return result


# Calculates inter-arrival times for each packet in each direction returns a list of times for each direction
def get_interarrival_times(pkt_list):
    timestamp, for_time, back_time = 0, 0, 0
    for_times, back_times = [], []
    src = ''
    count = 0
    for pkt_data in pkt_list:
        ip_packet = get_ip(pkt_data)
        if ip_packet is None:
            continue
        if timestamp == 0:
            src = ip_packet.src
        timestamp = pkt_data.time
        if ip_packet.src == src:
            if count == 0:
                for_time = timestamp
                continue
            for_times.append(timestamp - for_time)
            for_time = timestamp
        # Backward Packet Features
        else:
            if count == 1:
                back_time = timestamp
                continue
            back_times.append(timestamp - back_time)
            back_time = timestamp
        count += 1
    return for_times, back_times


# Actual calculation of timing features happens here
def timing_features(pkt_list):
    result = dict()
    for_times, back_times = get_interarrival_times(pkt_list)
    # print(back_times)
    if len(for_times) > 0:
        result['Mean forward inter arrival time difference'.replace(' ', '_')] = mean(for_times)
        result['Min forward inter arrival time difference'.replace(' ', '_')] = min(for_times)
        result['Max forward inter arrival time difference'.replace(' ', '_')] = max(for_times)
    if len(back_times) > 0:
        result['Mean backward inter arrival time difference'.replace(' ', '_')] = mean(back_times)
        result['Min backward inter arrival time difference'.replace(' ', '_')] = min(back_times)
        result['Max backward inter arrival time difference'.replace(' ', '_')] = max(back_times)
    if len(for_times) > 1:
        result['STD forward inter arrival time difference'.replace(' ', '_')] = stdev(for_times)
    if len(back_times) > 1:
        result['STD backward inter arrival time difference'.replace(' ', '_')] = stdev(back_times)
    return result


def other_features(pkt_list):
    result = dict()
    if TCP not in pkt_list[0]:
        return result
    result['Window_size'] = pkt_list[0][TCP].window
    result['Source_port'] = pkt_list[0][TCP].sport
    result['Destination_port'] = pkt_list[0][TCP].dport
    if len(pkt_list) > 3:
        result['First_packet_size'] = len(pkt_list[3][TCP])
    return result


# given a list of packets will return the feature vector for a
def extract_features(pkt_list):
    result = basic_features(pkt_list)
    result.update(timing_features(pkt_list))
    result.update(other_features(pkt_list))
    return result
    # additional feature extracting functions can be called here just update on result


def extract_pcap_directory(directory_name, label, out_file):
    df = pd.DataFrame(columns=correct_names)

    for filename in os.listdir(directory_name):
        if filename.endswith('.pcap'):
            pkt_list = get_packets(os.path.join(directory_name, filename))
            new_row = extract_features(pkt_list)
            # skip empty connections
            if not new_row:
                continue
            new_row['class'] = label
            df = df.append(new_row, ignore_index=True)
    arff.dump(out_file + '.arff'
              , df.values
              , relation='Test'
              , names=df.columns)
    df[:] = numpy.nan_to_num(df)
    df.to_csv(out_file + '.csv')


#extract_pcap_directory('C:\\Users\\Scotty\\Desktop\\SplitCap_2-1\\normal', 'normal', 'normal2')

