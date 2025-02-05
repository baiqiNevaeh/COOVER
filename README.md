# Cookie Value Analysis and Coovers

## Configuration environment

### Step 1: Install Hashcat

#### For Windows

1. Download the latest Hashcat binaries from the [official Hashcat website](https://hashcat.net/hashcat/ "Hashcat").
2. Extract the contents of the zip file to a folder of your choice.

#### For macOS and Linux

Install Hashcat through the package manager:

    On macOS with Homebrew: brew install hashcat
    On Linux (Debian-based): sudo apt install hashcat

<!-- Compile from Source (Optional)
If you need a version not available through your package manager or want the latest development version, you can compile Hashcat from source. This process requires `git`, `make`, and a C compiler:

    git clone https://github.com/hashcat/hashcat.git
    cd hashcat
    make
    sudo make install -->

This project is based on `Hashcat v6.2.6`.

### Step 2: Requirements

The required libraries are listed inside `requirements.txt` placed in the base folder.
You can use `pip install -r requirements.txt` to setup all the required libraries.

## Cookie Value Learning Algorithm

    bash cookie_value_learning_algorithm.sh

Run this file to obtain the ful output of the cookie value analysis. As the final output, the algorithm will generate a csv file containing all learned segments for the cookie values.

### Phase 1: Cookie Value Pre-processing

`cookie_value_pre_processing.py`: Run this file to pre-processing all input cookie values. The input for this phase is the collected cookie values (default as: `/Dataset/all_collected_cookies.xlsx`). The output is default as the `1_decoded_cracked_example_crawl.csv`.

### Phase 2: Rules-Based Patterns Extraction

`rules_based_patterns_extraction.py`: Run this file to extract all fixed patterns in cookie values. The input for this phase is pre-processed cookie values from `Phase 1` (default as: `1_decoded_cracked_example_crawl.csv`). The output is default as the `2_filtered_rules_based_patterns.csv` to the remaining cookie values and the extracted segments are saved in `all_segments_date_pattern.txt`, `all_segments_ipv4_pattern.txt`, `all_segments_uuid_pattern.txt`, `all_segments_url_or_domain_pattern.txt`.

### Pre-processing with Delimiter

`pre_processing_with_delimiter.py`: The input for this phase is from the `Phase 2` (default as: `2_filtered_rules_based_patterns.csv`). The output is default as the `3_final_separated_data.csv` to the remaining cookie values and the extracted segments are saved in `all_segments_date_pattern.txt`, `all_segments_ipv4_pattern.txt`, `all_segments_uuid_pattern.txt`, `all_segments_url_or_domain_pattern.txt`.

### Plain-texts Recognition

`plain_texts_recognition.py`: The input for this phase is default as: `3_final_separated_data.csv`. The output contains two files named `3_all_plain_texts.csv` and `3_all_non_plain_texts.csv`.
