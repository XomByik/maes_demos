# Compiler and flags
CC = gcc
CFLAGS = -Wall -Wextra -O2
LIBS = -lm
RM = rm -f

# --- Source Files ---
# AES library
AES_LIB_SRC = libs/micro_aes.c
AES_LIB_HDR = libs/micro_aes.h
# FPE library header (dependency for FPE demos)
FPE_LIB_HDR = libs/micro_fpe.h
# Common utilities
COMMON_SRC = common.c
COMMON_HDR = header_files/common.h
COMMON_OBJ = $(COMMON_SRC:.c=.o)
# Demo source files (base names)
# List all base names for demos that exist
# Note: gcm1024 is not a base, it's a variant built from gcm_demo.c
DEMO_BASES = ecb cbc cfb ofb ctr xts gcm ccm kw eax ocb siv gcm_siv fpe
DEMO_SRCS = $(patsubst %,%_demo.c,$(DEMO_BASES))
DEMO_SRCS := $(filter-out $(COMMON_SRC), $(DEMO_SRCS))

# --- Executable Definitions ---
AES_SIZES = 128 192 256
# Define specific sizes supported by certain modes if different from AES_SIZES
XTS_SIZES = 128 256
GCM_SIV_SIZES = 128 256
OCB_SIZES = 128
EAX_SIZES = 128

# Generate all possible executable names based on modes and sizes
# Standard modes (ECB, CBC, CFB, OFB, CTR, GCM, CCM, KW, EAX) using AES_SIZES
STD_MODES = ecb cbc cfb ofb ctr gcm ccm kw siv
ALL_EXES = $(foreach size,$(AES_SIZES),$(patsubst %,%_demo_$(size),$(STD_MODES)))
# XTS mode
ALL_EXES += $(foreach size,$(XTS_SIZES),xts_demo_$(size))
# OCB mode
ALL_EXES += $(foreach size,$(OCB_SIZES),ocb_demo_$(size))
# GCM-SIV mode
ALL_EXES += $(foreach size,$(GCM_SIV_SIZES),gcm_siv_demo_$(size))
# GCM 1024 Nonce mode (uses gcm_demo.c) - Define specific targets
ALL_EXES += $(foreach size,$(AES_SIZES),gcm_demo_$(size)_nonce1024)
# FPE modes (use fpe_demo.c)
ALL_EXES += $(foreach size,$(AES_SIZES),fpe_demo_ff1_$(size))
ALL_EXES += $(foreach size,$(AES_SIZES),fpe_demo_ff3_$(size))
ALL_EXES += $(foreach size,$(EAX_SIZES),eax_demo_$(size))


# --- Targets ---

# Default target: build all demos
all: $(ALL_EXES)

# Rule to compile common.c into common.o
$(COMMON_OBJ): $(COMMON_SRC) $(COMMON_HDR) $(AES_LIB_HDR)
	$(CC) $(CFLAGS) -c $< -o $@

# --- Generic Compilation Rules ---
# Common dependencies for all demo rules that don't need FPE
COMMON_DEPS = $(COMMON_OBJ) $(AES_LIB_SRC) $(AES_LIB_HDR) $(COMMON_HDR)
# Dependencies for FPE demos (add FPE header)
FPE_DEPS = $(COMMON_DEPS) $(FPE_LIB_HDR)

# Define a function to get necessary flags based on source file ($1) and target name ($2)
define GET_FLAGS
$(if $(filter xts_demo.c,$1),-DXTS=1) \
$(if $(filter gcm_demo.c,$1),$(if $(findstring nonce1024,$2),-DGCM_NONCE_LEN=128)) \
$(if $(filter ccm_demo.c,$1),-DCCM=1 -DCCM_NONCE_LEN=7 -DCCM_TAG_LEN=16) \
$(if $(filter kw_demo.c,$1),-DKW=1) \
$(if $(filter fpe_demo.c,$1),$(if $(findstring ff1,$2),-DFF_X=1) $(if $(findstring ff3,$2),-DFF_X=3))
endef

# Specific rules for GCM 1024 Nonce demo - Handles all AES sizes
# Stem * is the size (e.g., 128)
gcm_demo_%_nonce1024: gcm_demo.c $(COMMON_DEPS)
	$(CC) $(CFLAGS) -o $@ $< $(COMMON_OBJ) $(AES_LIB_SRC) $(LIBS) -DAES___=$* $(call GET_FLAGS,$<,$@)

# Rules for standard sizes (128, 192, 256) applied to remaining modes
# The stem % will match the mode name (e.g., ecb, cbc, gcm, etc.)
# These rules cover all targets like ecb_demo_128, gcm_demo_192, etc.
# Excludes FPE and GCM Nonce1024 which are handled by the more specific rules above.
%_demo_128: %_demo.c $(COMMON_DEPS)
	$(CC) $(CFLAGS) -o $@ $< $(COMMON_OBJ) $(AES_LIB_SRC) $(LIBS) -DAES___=128 $(call GET_FLAGS,$<,$@)

%_demo_192: %_demo.c $(COMMON_DEPS)
	$(CC) $(CFLAGS) -o $@ $< $(COMMON_OBJ) $(AES_LIB_SRC) $(LIBS) -DAES___=192 $(call GET_FLAGS,$<,$@)

%_demo_256: %_demo.c $(COMMON_DEPS)
	$(CC) $(CFLAGS) -o $@ $< $(COMMON_OBJ) $(AES_LIB_SRC) $(LIBS) -DAES___=256 $(call GET_FLAGS,$<,$@)

# Specific rules for FPE (FF1/FF3) demos - Handles all AES sizes
# Dvoje špeciálne pravidlá pre FF1 a FF3 varianty

# FF1 variant rule
fpe_demo_ff1_%: fpe_demo.c $(FPE_DEPS)
	$(CC) $(CFLAGS) -o $@ $< $(COMMON_OBJ) $(AES_LIB_SRC) $(LIBS) -DAES___=$* -DFF_X=1

# FF3 variant rule
fpe_demo_ff3_%: fpe_demo.c $(FPE_DEPS)
	$(CC) $(CFLAGS) -o $@ $< $(COMMON_OBJ) $(AES_LIB_SRC) $(LIBS) -DAES___=$* -DFF_X=3

# Pridáme cieľ pre kompiláciu všetkých FPE variant
fpe: $(filter fpe_demo_%,$(ALL_EXES))

# --- Specific Targets ---
# Example: build just cfb_demo (all applicable sizes)
cfb_demo: $(filter cfb_demo_%,$(ALL_EXES))

# Target to build all GCM variants (standard and 1024 nonce)
gcm: $(filter gcm_demo_%,$(ALL_EXES))

# --- Clean Target ---
clean:
	$(RM) $(ALL_EXES) $(COMMON_OBJ) *.o

.PHONY: all clean cfb_demo gcm $(DEMO_BASES)

# Add phony targets for each demo base name to build all its variants
$(foreach base,$(DEMO_BASES),$(eval $(base): $(filter $(base)_demo_%,$(ALL_EXES))))
