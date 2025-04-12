#ifndef CFB_CONFIG_H
#define CFB_CONFIG_H

#include <stdint.h>
#include <stdbool.h>

#define CFB_LINE_BUFFER_SIZE 512

typedef struct {
    int count;
    char *hex_key;
    char *hex_iv;
    char *hex_input_block;
    char *hex_output_block;
    char *plaintext_str;
    char *ciphertext_str;
    int segment_size;
    int segment_number;
    bool is_encrypt;
} TestCaseData;

typedef enum {
    KEY, IV, SEGMENT, INPUT_BLOCK, OUTPUT_BLOCK, PLAINTEXT, CIPHERTEXT, MODE_CHANGE, UNKNOWN
} LineType;

void free_test_case_data(TestCaseData *data);
void process_cfb(uint8_t* key, uint8_t* iv, const void* input, void* output, 
                 int segment_size, bool encrypt);
bool parse_test_data(FILE *fp, TestCaseData *data, uint8_t *key, uint8_t *iv, 
                     uint8_t *original_iv, int *test_count, int *passed_count,
                     int segment_size, bool *first_segment_in_file);
int get_segment_size(const char* filename);

#endif // CFB_CONFIG_H