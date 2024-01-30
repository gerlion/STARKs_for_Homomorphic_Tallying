#!/bin/bash
# Bash script to collect performance data

output_file="gen_data_stats.csv"
echo "Num votes, Generation time, Data size" >> $output_file

counter=2
while [ $counter -le 10 ] # 2^10 = 1024, 2^16 = 65536, 2^17 = 131072
do
    echo "Generating input data of size 2^$counter"

    data_file="voting_input_$counter.json"
    
    # start run timer
    start_gen=$(date +%s%N)

    python generate_data.py $counter $data_file

    finish_gen=$(date +%s%N)

    # find size of data
    data_size=$(stat -c “%s” artifacts/$data_file)

    # input data to output_file
    echo "$counter, $(($finish_gen - $start_gen)), $data_size" >> $output_file

    # increment counter
    ((counter++))
done

echo "Finished generation."