from scapy.utils import RawPcapReader
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP
from math import sqrt
import os
import pandas as pd
from statistics import stdev


def get_variance(for_mean, back_mean, tot_mean, filename):
    for_var, back_var, tot_var = 0, 0, 0
    src = ''
    for (pkt_data, pkt_metadata,) in RawPcapReader(filename):
        ip_packet = get_ip(pkt_data)
        if ip_packet is None:
            continue
        if tot_var == 0:
            src = ip_packet.src
        packet_len = len(ip_packet[TCP])
        tot_var = (packet_len - tot_mean) ** 2
        if ip_packet.src == src:
            for_var = (packet_len - for_mean) ** 2
        # Backward Packet Features
        else:
            back_var = (packet_len - back_mean) ** 2
    return for_var, back_var, tot_var


def get_ip(pkt_data):
    ether_pkt = Ether(pkt_data)
    if 'type' not in ether_pkt.fields:
        # LLC frames will have 'len' instead of 'type'.
        # We disregard those
        return None

    if ether_pkt.type != 0x0800:
        # disregard non-IPv4 packets
        return None

    ip_pkt = ether_pkt[IP]
    if ip_pkt.proto != 6:
        # Ignore non-TCP packet
        return None
    return ip_pkt


def basic_features(filename):
    result = dict()
    tot_count, for_count, back_count, for_bytes, back_bytes = 0, 0, 0, 0, 0
    min_for, min_back, max_for, max_back, ttl = 0, 0, 0, 0, 0
    src = ''
    for (pkt_data, pkt_metadata,) in RawPcapReader(filename):
        ip_packet = get_ip(pkt_data)
        if ip_packet is None:
            continue
        # Set soucre and dst for forwards and backwards features
        if tot_count == 0:
            src = ip_packet.src
        tot_count += 1
        packet_len = len(ip_packet[TCP])

        # Forward packet features
        if ip_packet.src == src:
            if packet_len < min_for or for_count == 0:
                min_for = packet_len
            if packet_len > max_for or for_count == 0:
                max_back = packet_len
            for_count += 1
            for_bytes += packet_len

        # Backward Packet Features
        else:
            if packet_len < min_back or back_count == 0:
                min_back = packet_len
            if packet_len > max_back or back_count == 0:
                max_back = packet_len
            ttl += ip_packet.ttl
            back_count += 1
            back_bytes += packet_len
    # Somethings broke
    if back_count + for_count <= 0:
        return result
    result['# forward packets'] = for_count
    result['# backward packets'] = back_count
    result['# forward total bytes'] = for_bytes
    result['# backward total bytes'] = back_bytes
    result['# Total packets'] = for_count + back_count
    result['Mean packet size'] = (for_bytes + back_bytes) / (for_count + back_count)
    result['Minimum packet size'] = min_back if min_back < min_for else min_for
    result['Maximum packet size'] = max_back if max_back > max_for else max_for
    result['Minimum forward packet'] = min_for
    result['Minimum backward packet'] = min_back
    result['Maximum forward packet'] = max_for
    result['Maximum backward packet'] = max_back
    result['Mean forward packets'] = for_bytes / for_count
    if back_count > 0:
        result['Mean backward TTL value'] = ttl / back_count
        result['Mean backward packets'] = back_bytes / back_count
        std_for, std_back, tot_var = get_variance(result['Mean forward packets'], result['Mean backward packets'],
                                                  result['Mean packet size'], filename)
    else:
        std_for, std_back, tot_var = get_variance(result['Mean forward packets'], 0, result['Mean packet size'],
                                                  filename)

    if for_count > 1:
        result['STD forward packets'] = sqrt(std_for / (for_count - 1))
    if back_count > 1:
        result['STD forward packets'] = sqrt(std_back / (back_count - 1))
    return result


def get_interarrival_times(filename):
    timestamp, for_time, back_time = 0, 0, 0
    tot_for_time, tot_back_time = [], []
    src = ''
    count = 0
    for (pkt_data, pkt_metadata,) in RawPcapReader(filename):
        ip_packet = get_ip(pkt_data)
        if ip_packet is None:
            continue
        if timestamp == 0:
            src = ip_packet.src
        timestamp = pkt_metadata.sec + pkt_metadata.usec * 10 ** -6
        if ip_packet.src == src:
            if count == 0:
                for_time = timestamp
                continue
            tot_for_time.append(timestamp - for_time)
            for_time = timestamp
        # Backward Packet Features
        else:
            if count == 1:
                back_time = timestamp
                continue
            tot_back_time.append(timestamp - back_time)
            back_time = timestamp
        count += 1
    return tot_for_time, tot_back_time


def timing_features(filename, result):
    for_times, back_times = get_interarrival_times(filename)
    # print(back_times)
    if len(for_times) > 0:
        result['Mean forward inter arrival time difference'] = sum(for_times) / len(for_times)
        result['Min forward inter arrival time difference'] = min(for_times)
        result['Max forward inter arrival time difference'] = max(for_times)
    if len(back_times) > 0:
        result['Mean backward inter arrival time difference'] = sum(back_times) / len(back_times)
        result['Min backward inter arrival time difference'] = min(back_times)
        result['Max backward inter arrival time difference'] = max(back_times)
    if len(for_times) > 1:
        result['STD forward inter arrival time difference'] = stdev(for_times)
    if len(back_times) > 1:
        result['STD backward inter arrival time difference'] = stdev(back_times)
    return result


def extract_pcap(filename):
    result = basic_features(filename)
    return timing_features(filename, result)


def extract_pcaps(directory_name, label):
    feature_names = ['# forward packets', '# forward total bytes', 'Min forward inter arrival time difference',
                     'Max forward inter arrival time difference', 'Mean forward inter arrival time difference',
                     'STD forward inter arrival time difference', 'Mean forward packets', 'STD forward packets',
                     '# backward packets', '# backward total bytes',
                     'Min backward inter arrival time difference', 'Max backward inter arrival time difference',
                     'Mean backward inter arrival time difference', 'STD backward inter arrival time difference',
                     'Mean backward packets', 'STD backward packets', 'Mean backward TTL value', '# Total packets',
                     'Minimum packet size', 'Maximum packet size', 'Mean packet size', 'Label']
    df = pd.DataFrame(columns=feature_names)

    for filename in os.listdir(directory_name):
        if filename.endswith('.pcap'):
            new_row = extract_pcap(os.path.join(directory_name, filename))
            new_row['Label'] = label
            df = df.append(new_row, ignore_index=True)
    df.to_csv(label + '.csv')


#extract_pcaps('C:\\Users\\Scotty\\Desktop\\SplitCap_2-1\\normal', 'normal')
