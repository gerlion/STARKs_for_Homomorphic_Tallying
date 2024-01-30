# Cairo0 E-Voting Scheme
## Installing dependencies
Install Cairo0 following the [install page](https://docs.cairo-lang.org/0.12.0/quickstart.html) and activate the virtual environment.
Clone the [STONE prover](https://github.com/starkware-libs/stone-prover) project, build the docker image, and fetch the prover and verifier executables:
```bash
container_id=$(docker create prover)
docker cp -L ${container_id}:/bin/cpu_air_prover .
docker cp -L ${container_id}:/bin/cpu_air_verifier .
```

## Running the project and using the STONE prover
Generate the input data:
```bash
python generate_data.py 3 artifacts/voting_input_3_example.json
```
Within a Cairo0 python virtual environment, compile the Cairo0 program:
```bash
cairo-compile src/evoting.cairo --output artifacts/evoting_compiled.json --proof_mode
```
Run the Cairo0 program to generate the prover input files:
```bash
cairo-run --program=artifacts/evoting_compiled.json \
 --layout=all_solidity \
 --program_input=artifacts/voting_input.json \
 --air_public_input=artifacts/evoting_public_input.json \
 --air_private_input=artifacts/evoting_private_input.json \
 --trace_file=artifacts/evoting_trace.json \
 --memory_file=artifacts/evoting_memory.json \
 --print_output --proof_mode
```
Run the STONE prover executable on the program data to generate a STARK proof:
```bash
./cpu_air_prover   --out_file=artifacts/evoting_proof.json \
  --private_input_file=artifacts/evoting_private_input.json \
  --public_input_file=artifacts/evoting_public_input.json \
  --prover_config_file=src/cpu_air_prover_config.json \
  --parameter_file=src/cpu_air_params.json
```
Finally, run the STONE verifier executable on the STARK proof and confirm verification:
```bash
./cpu_air_verifier --in_file=artifacts/evoting_proof.json && echo "Successfully verified proof."
```