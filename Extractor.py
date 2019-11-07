from scapy.utils import RawPcapReader
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP
import os
import pandas as pd
from statistics import stdev
from statistics import mean
import arff


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
    for_bytes, back_bytes = [], []
    ttl = []
    src = ''
    for (pkt_data, pkt_metadata,) in RawPcapReader(filename):
        ip_packet = get_ip(pkt_data)
        if ip_packet is None:
            continue
        # Set soucre and dst for forwards and backwards features
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


def extract_pcap(filename):
    result = basic_features(filename)
    return timing_features(filename, result)


def extract_pcaps(directory_name, label, out_file):
    feature_names = ['forward packets', 'forward total bytes', 'Min forward inter arrival time difference',
                     'Max forward inter arrival time difference', 'Mean forward inter arrival time difference',
                     'STD forward inter arrival time difference', 'Mean forward packets', 'STD forward packets',
                     'backward packets', 'backward total bytes',
                     'Min backward inter arrival time difference', 'Max backward inter arrival time difference',
                     'Mean backward inter arrival time difference', 'STD backward inter arrival time difference',
                     'Mean backward packets', 'STD backward packets', 'Mean backward TTL value', 'Total packets',
                     'Minimum packet size', 'Maximum packet size', 'Mean packet size', 'Label']
    correct_names =[]
    for name in feature_names:
        correct_names.append(name.replace(' ', '_'))
    #print(correct_names)
    df = pd.DataFrame(columns=correct_names)

    for filename in os.listdir(directory_name):
        if filename.endswith('.pcap'):
            new_row = extract_pcap(os.path.join(directory_name, filename))
            # skip empty connections
            if not new_row:
                continue
            new_row['Label'] = label
            df = df.append(new_row, ignore_index=True)
    arff.dump(out_file + '.arff'
              , df.values
              , relation='Test'
              , names=df.columns)
    df.to_csv(out_file + '.csv')


extract_pcaps('C:\\Users\\Scotty\\Desktop\\SplitCap_2-1\\test2', 'normal', 'test2')
