# maes_demos

## Inštrukcie pre kompiláciu

Na skompilovanie projektu pre rôzne režimy použite nasledujúce GCC príkazy:

### Režim CCM

```bash
# AES-128-ECB
gcc -Wall -Wextra -O2 -o ecb_demo_128 ecb_demo.c libs/micro_aes.c -DECB=1 -DAES___=128

# AES-192-ECB
gcc -Wall -Wextra -O2 -o ecb_demo_192 ecb_demo.c libs/micro_aes.c -DECB=1 -DAES___=192

# AES-256-ECB
gcc -Wall -Wextra -O2 -o ecb_demo_256 ecb_demo.c libs/micro_aes.c -DECB=1 -DAES___=256

# AES-128-CBC
gcc -Wall -Wextra -O2 -o cbc_demo_128 cbc_demo.c libs/micro_aes.c -DCBC=1 -DAES___=128

# AES-192-CBC
gcc -Wall -Wextra -O2 -o cbc_demo_192 cbc_demo.c libs/micro_aes.c -DCBC=1 -DAES___=192

# AES-256-CBC
gcc -Wall -Wextra -O2 -o cbc_demo_256 cbc_demo.c libs/micro_aes.c -DCBC=1 -DAES___=256

# AES-128-CTR
gcc -Wall -Wextra -O2 -o ctr_demo_128 ctr_demo.c libs/micro_aes.c -DCTR=1 -DAES___=128

# AES-192-CTR
gcc -Wall -Wextra -O2 -o ctr_demo_192 ctr_demo.c libs/micro_aes.c -DCTR=1 -DAES___=192

# AES-256-cTR
gcc -Wall -Wextra -O2 -o ctr_demo_256 ctr_demo.c libs/micro_aes.c -DCTR=1 -DAES___=256

# AES-128-OFB
gcc -Wall -Wextra -O2 -o ofb_demo_128 ctr_demo.c libs/micro_aes.c -DCTR=1 -DAES___=128

# AES-192-OFB
gcc -Wall -Wextra -O2 -o ofb_demo_192 ctr_demo.c libs/micro_aes.c -DCTR=1 -DAES___=192

# AES-256-OFB
gcc -Wall -Wextra -O2 -o ofb_demo_256 ctr_demo.c libs/micro_aes.c -DCTR=1 -DAES___=256

# AES-128-XTS
gcc -Wall -Wextra -O2 -o xts_demo_128 ctr_demo.c libs/micro_aes.c -DCTR=1 -DAES___=128

# AES-192-XTS
gcc -Wall -Wextra -O2 -o xts_demo_192 ctr_demo.c libs/micro_aes.c -DCTR=1 -DAES___=192

# AES-256-XTS
gcc -Wall -Wextra -O2 -o xts_demo_256 ctr_demo.c libs/micro_aes.c -DCTR=1 -DAES___=256

# AES-128-CFB
gcc -Wall -Wextra -O2 -o cfb_demo_128 ctr_demo.c libs/micro_aes.c -DCTR=1 -DAES___=128

# AES-192-CFB
gcc -Wall -Wextra -O2 -o cfb_demo_192 ctr_demo.c libs/micro_aes.c -DCTR=1 -DAES___=192

# AES-256-CFB
gcc -Wall -Wextra -O2 -o cfb_demo_256 ctr_demo.c libs/micro_aes.c -DCTR=1 -DAES___=256

# AES-128-GCM (96 BIT NONCE)
gcc -Wall -Wextra -O2 -o gcm_demo_128 ctr_demo.c libs/micro_aes.c -DCTR=1 -DAES___=128

# AES-192-FCM (96 BIT NONCE)
gcc -Wall -Wextra -O2 -o gcm_demo_192 ctr_demo.c libs/micro_aes.c -DCTR=1 -DAES___=192

# AES-256-GCM (96 BIT NONCE)
gcc -Wall -Wextra -O2 -o gcm_demo_256 ctr_demo.c libs/micro_aes.c -DCTR=1 -DAES___=256

# AES-128-GCM (1024 BIT NONCE)
gcc -Wall -Wextra -O2 -o gcm_demo_128 ctr_demo.c libs/micro_aes.c -DCTR=1 -DAES___=128 -DGCM_NONCE_LEN=128

# AES-192-FCM (1024 BIT NONCE)
gcc -Wall -Wextra -O2 -o gcm_demo_192 ctr_demo.c libs/micro_aes.c -DCTR=1 -DAES___=192 -DGCM_NONCE_LEN=128

# AES-256-GCM (1024 BIT NONCE)
gcc -Wall -Wextra -O2 -o gcm_demo_256 ctr_demo.c libs/micro_aes.c -DCTR=1 -DAES___=256 -DGCM_NONCE_LEN=128


