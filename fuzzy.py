# id,forward_packets,forward_total_bytes,Min_forward_inter_arrival_time_difference,
# Max_forward_inter_arrival_time_difference,Mean_forward_inter_arrival_time_difference,
# STD_forward_inter_arrival_time_difference,Mean_forward_packets,STD_forward_packets,
# backward_packets,backward_total_bytes,Min_backward_inter_arrival_time_difference,
# Max_backward_inter_arrival_time_difference,Mean_backward_inter_arrival_time_difference,
# STD_backward_inter_arrival_time_difference,Mean_backward_packets,STD_backward_packets,
# Mean_backward_TTL_value,Total_packets,Minimum_packet_size,Maximum_packet_size,Mean_packet_size,
# class,Maximum_backward_packet,Maximum_forward_packet,Minimum_backward_packet,Minimum_forward_packet

# TODO: discuss which features are most important, did for 1 feature, which is forward packets, column 1
# Input: full.csv
# Output: only focus on column 1, aka index 1, forward packets, in this program
import csv
from statistics import mean

forward_packets_total_col_list = []
forward_packets_normal_col_list = []
forward_packets_bad_col_list = []
with open("full.csv", "r") as csv_file:
    csv_reader = csv.reader(csv_file, delimiter=',')
    # the below statement will skip the first row, don't need first row
    next(csv_reader)
    for row in csv_reader:
    	forward_packets_total_col_list.append(int(row[1]))
    	# only normal or bad values under the 22nd column
    	if row[22] == 'normal':
    		forward_packets_normal_col_list.append(int(row[1]))
    	else:
    		forward_packets_bad_col_list.append(int(row[1]))

# calculate stats, build forward_packets_total_min_avg_max_list from forward_packets_total_col_list
forward_packets_total_min_avg_max_list = []
forward_packets_total_min_avg_max_list.append(min(forward_packets_total_col_list))
forward_packets_total_min_avg_max_list.append(mean(forward_packets_total_col_list))
forward_packets_total_min_avg_max_list.append(max(forward_packets_total_col_list))
# Use these 3 values
print('Considering both normal and bad traffic for forward_packets feature...')
print(forward_packets_total_min_avg_max_list)

forward_packets_normal_min_avg_max_list = []
forward_packets_normal_min_avg_max_list.append(min(forward_packets_normal_col_list))
forward_packets_normal_min_avg_max_list.append(mean(forward_packets_normal_col_list))
forward_packets_normal_min_avg_max_list.append(max(forward_packets_normal_col_list))
print('Considering only normal traffic for forward_packets feature...')
print(forward_packets_normal_min_avg_max_list)

forward_packets_bad_min_avg_max_list = []
forward_packets_bad_min_avg_max_list.append(min(forward_packets_bad_col_list))
forward_packets_bad_min_avg_max_list.append(mean(forward_packets_bad_col_list))
forward_packets_bad_min_avg_max_list.append(max(forward_packets_bad_col_list))
print('Considering only bad traffic for forward_packets feature...')
print(forward_packets_bad_min_avg_max_list)