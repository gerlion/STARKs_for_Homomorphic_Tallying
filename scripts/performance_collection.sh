#!/bin/bash
# Bash script to collect performance data

# Set up the data collection csv
output_file="performance_data/performance_data.csv"
#echo "Input votes (log_2), Cairo run time (ns), Proving time (ns), Proof size (bytes), Verification time (ns)" >> $output_file

counter=2
while [ $counter -le 6 ] # 2^16 = 65536, 2^17 = 131072
do
    echo "Collecting run of 2**$counter"

    input_file="voting_input_$counter.json"

    param_file="cpu_air_params_$counter.json"

    log_dir="logging/size_$counter"
    mkdir $log_dir
    
    # start run timer
    start_run=$(date +%s%N)

    # run the cairo program
    cairo-run --program=artifacts/evoting_compiled.json \
    --layout=all_solidity \
    --program_input=artifacts/$input_file \
    --air_public_input=artifacts/evoting_public_input.json \
    --air_private_input=artifacts/evoting_private_input.json \
    --trace_file=artifacts/evoting_trace.json \
    --memory_file=artifacts/evoting_memory.json \
    --proof_mode

    finish_cairo=$(date +%s%N)

    # run the STONE prover
    ./cpu_air_prover   --out_file=artifacts/evoting_proof.json \
    --private_input_file=artifacts/evoting_private_input.json \
    --public_input_file=artifacts/evoting_public_input.json \
    --prover_config_file=src/cpu_air_prover_config.json \
    --parameter_file=artifacts/$param_file \
    --v 2 --log_dir $log_dir

    finish_proof=$(date +%s%N)

    # run the STONE verifier
    ./cpu_air_verifier --in_file=artifacts/evoting_proof.json && echo "Successfully verified proof."

    finish_verify=$(date +%s%N)

    # find size of proof
    proof_size=$(stat -c “%s” artifacts/evoting_proof.json)

    # input data to output_file
    echo "$counter, $(($finish_cairo - $start_run)), $(($finish_proof - $finish_cairo)), $proof_size, $(($finish_verify - $finish_proof))" >> $output_file

    # increment counter
    ((counter++))
done

echo "All done."