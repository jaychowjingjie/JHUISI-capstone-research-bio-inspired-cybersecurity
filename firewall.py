import numpy
import datetime
from functools import partial
from scapy.all import *
from Extractor import *
from supervised import train
import pickle
import sys

unique_flows = set()
blocked_connections = set()
blocked_ips = []
active_connections = dict()
bad_features = ['class']


def train_new_model(training_file, output):
    model = train(training_file)
    pickle.dump(model, open(output, 'wb'))


# IDs are Host IP,Port and Dest IP,Port
def get_details(pkt, host):
    if pkt[IP].src == host:
        dest_ip = pkt[IP].dst
        dest_port = pkt[IP][TCP].dport
        host_port = pkt[IP][TCP].sport
    else:
        dest_ip = pkt[IP].src
        dest_port = pkt[IP][TCP].sport
        host_port = pkt[IP][TCP].dport
    conn_id = [host, str(host_port), dest_ip, str(dest_port)]
    if ''.join(conn_id) not in active_connections:
        unique_flows.add(''.join(conn_id))
        active_connections[''.join(conn_id)] = []
    return conn_id


def block(det):
    blocked_connections.add(''.join(det))
    if det[2] not in blocked_ips:
        blocked_ips.append(det[2])
        file = open('firewall_log.txt', 'a')
        file.write('%s: Host IP: %s was blocked\n' % (datetime.now(), det[2]))
        file.close()
        # Bad syscalls are bad but this should work, at least on non-Windows systems
        if not sys.platform.startswith('win'):
            cmd = "/sbin/iptables -A INPUT -s " + det[2] + " -j DROP"
            subprocess.call(cmd, shell=True)


def evaluate(vector, model_file):
    vector = dict_to_df(vector)
    file = open(model_file, 'rb')
    vector = vector.drop(bad_features, axis=1)
    vector[:] = numpy.nan_to_num(vector)
    model = pickle.load(file)
    file.close()
    return model.predict(vector)


# Checks to see if the TCP session is over
def is_ended(pkt_list):
    # Check for reset flag
    if pkt_list[-1][IP][TCP].flags.R:
        return True
    # Lazy check for 4-way session close
    elif len(pkt_list) < 4:
        return False
    else:
        last_4 = pkt_list[-4:]
        return last_4[0][IP][TCP].flags.F and last_4[2][IP][TCP].flags.F


def process_pkt(host, model_file, pkt):
    if TCP not in pkt:
        return
    details = get_details(pkt, host)
    con_id = ''.join(details)
    active_connections[con_id].append(pkt)
    if len(active_connections[con_id]) % 5 == 0 or is_ended(active_connections[con_id]):
        ingest(con_id, model_file, details)
    if is_ended(active_connections[con_id]):
        del active_connections[con_id]


def ingest(con_id, model_file, details):
    vector = extract_features(active_connections[con_id])
    label = evaluate(vector, model_file)
    #print(type(label))
    if isinstance(label, str):
        if label == 'bad':
            block(details)
    else:
        label = list(label)
        if label[0] == 1:
            block(details)


def packet_scanner(host, model_file):
    sniff(prn=partial(process_pkt, host, model_file), filter="tcp and host " + host, store=0)


def canned_scanner(filename, host, model_file):
    sniff(offline=filename, prn=partial(process_pkt, host, model_file))
    print('Unique Connections: ' + str(len(unique_flows)))
    print('Malicious Connections: ' + str(len(blocked_connections)))


def main(argv):
    hostname = socket.gethostname()
    host_ip = socket.gethostbyname(hostname)
    model_file = ''
    can_file = ''
    train_file = ''
    live_flag = False
    retrain_flag = False
    try:
        opts, args = getopt.getopt(argv, "hlc:m:i:t:o:")
    except getopt.GetoptError:
        print('Input Error')
        sys.exit(2)
    for opt, arg in opts:
        if opt == '-h':
            print('Usage: firewall.py -m <model_pkl>  -i <host_ip> -c <canned_pcap> (Canned Traffic)')
            print('firewall.py -m <model_pkl>  -i <host_ip> -l (Live Traffic)')
            print('firewall.py -t <training_data> -m <output_model> (Retrain Model)')
            sys.exit()
        elif opt == "-c":
            can_file = arg
        elif opt == "-m":
            model_file = arg
        elif opt == '-l':
            live_flag = True
        elif opt == '-i':
            host_ip = arg
        elif opt == 't':
            retrain_flag = True
            train_file = arg

    if live_flag:
        packet_scanner(host_ip, model_file)
    elif retrain_flag:
        train_new_model(train_file, model_file)
    else:
        canned_scanner(can_file, host_ip, model_file)


if __name__ == "__main__":
    #main(sys.argv[1:])
    canned_scanner('test2.pcap', '192.168.1.13', 'supervised_model2.pkl')
    print(len(unique_flows))
    print(len(blocked_connections))
