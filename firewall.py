import numpy
from functools import partial
from scapy.all import *
from Extractor import *
import pickle

connection_dict = dict()
bad_features = ['class', 'Mean_backward_inter_arrival_time_difference', 'Mean_backward_TTL_value',
                'Max_backward_inter_arrival_time_difference', 'STD_backward_inter_arrival_time_difference']


# IDs are Host IP,Port and Dest IP,Port
def get_id(pkt, host):
    if pkt[IP].src == host:
        dest_ip = pkt[IP].dst
        dest_port = pkt[IP][TCP].dport
        host_port = pkt[IP][TCP].sport
    else:
        dest_ip = pkt[IP].src
        dest_port = pkt[IP][TCP].sport
        host_port = pkt[IP][TCP].dport
    conn_id = host + str(host_port) + dest_ip + str(dest_port)
    if conn_id not in connection_dict:
        connection_dict[conn_id] = []
    return conn_id


def block(pkt):
    print('Connection ID: ' + pkt + 'was blocked')


def evaluate(vector, model_file):
    vector = dict_to_df(vector)
    file = open(model_file, 'rb')
    vector[:] = numpy.nan_to_num(vector)
    vector = vector.drop(bad_features, axis=1)
    model = pickle.load(file)
    file.close()
    return model.predict(vector)


# Checks to see if the TCP session is over
def is_ended(pkt_list):
    # Check for reset flag
    if pkt_list[-1][IP][TCP].flags.R:
        return True
    # Lazy check for 4-way session close
    else:
        last_4 = pkt_list[-4:]
        return last_4[0][IP][TCP].flags.F and last_4[2][IP][TCP].flags.F


def process_pkt(host: str, model_file: str, pkt):
    if TCP not in pkt:
        return
    con_id = get_id(pkt, host)
    connection_dict[con_id].append(pkt)
    if len(connection_dict[con_id]) % 30 == 0 or is_ended(connection_dict[con_id]):
        ingest(con_id, model_file)
    if is_ended(connection_dict[con_id]):
        del connection_dict[con_id]


def ingest(con_id, model_file):
    vector = extract_features(connection_dict[con_id])
    label = evaluate(vector, model_file)
    if label != 'normal':
        block(con_id)


def packet_scanner(host, model_file):
    sniff(prn=partial(process_pkt, host, model_file), filter="tcp and host " + host, store=0)


def canned_scanner(filename, host, model_file):
    sniff(offline=filename, prn=partial(process_pkt, host, model_file))


def main(argv):
    hostname = socket.gethostname()
    host_ip = socket.gethostbyname(hostname)
    model_file = ''
    can_file = ''
    live_flag = False
    try:
        opts, args = getopt.getopt(argv, "hlc:m:i:o:")
    except getopt.GetoptError:
        print('firewall.py -m <model_pkl> -c <canned_pcap> -i <host_ip>|-l (Live Traffic)')
        sys.exit(2)
    for opt, arg in opts:
        if opt == '-h':
            print('Usage: firewall.py -m <model_pkl> -c <canned_pcap> -h <host_ip>|-l (Live Traffic)')
            sys.exit()
        elif opt == "-c":
            can_file = arg
        elif opt == "-m":
            model_file = arg
        elif opt == '-l':
            live_flag = True
        elif opt == '-i':
            host_ip = arg
    if live_flag:
        packet_scanner(host_ip, model_file)
    else:
        canned_scanner(can_file, host_ip, model_file)


if __name__ == "__main__":
    main(sys.argv[1:])
