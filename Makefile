# Compiler and flags
CC = gcc -std=gnu23
CFLAGS = -Wall -Wextra -O2
LIBS = -lm
# Cross-platform command for removing files
ifeq ($(OS),Windows_NT)
    # Windows-specific commands
    RM = del /Q /F
    RMDIR = rmdir /Q /S
    CFLAGS += -D__USE_MINGW_ANSI_STDIO=1
    # Handle Windows path separator for source files
    fixpath = $(subst /,\,$1)
    # Create executable with .exe extension on Windows
    EXE_EXT = .exe
else
    # Unix/Linux commands
    RM = rm -f
    RMDIR = rm -rf
    fixpath = $1
    EXE_EXT = 
endif

# Add this in your Makefile for the Windows build
ifdef MINGW
  CFLAGS += -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=0
endif

# --- Source Files ---
# AES library
AES_LIB_SRC = libs/micro_aes.c
AES_LIB_HDR = libs/micro_aes.h
# FPE library header (dependency for FPE demos)
FPE_LIB_HDR = libs/micro_fpe.h
# Common utilities
COMMON_SRC = src/common.c
COMMON_HDR = header_files/common.h
COMMON_OBJ = $(COMMON_SRC:.c=.o)
# Demo source files (base names)
# List all base names for demos that exist
# Note: gcm1024 is not a base, it's a variant built from gcm_demo.c
DEMO_BASES = ecb cbc cfb ofb ctr xts gcm ccm kw eax ocb siv gcm_siv fpe
DEMO_SRCS = $(patsubst %,src/%_demo.c,$(DEMO_BASES))
DEMO_SRCS := $(filter-out $(COMMON_SRC), $(DEMO_SRCS))

# --- Executable Definitions ---
AES_SIZES = 128 192 256
# Define specific sizes supported by certain modes if different from AES_SIZES
XTS_SIZES = 128 256
GCM_SIV_SIZES = 128 256
OCB_SIZES = 128
EAX_SIZES = 128
SIV_SIZES = 128

# Generate all possible executable names based on modes and sizes
# Standard modes (ECB, CBC, CFB, OFB, CTR, GCM, CCM, KW, EAX) using AES_SIZES
STD_MODES = ecb cbc cfb ofb ctr gcm ccm kw
ALL_EXES = $(foreach size,$(AES_SIZES),$(patsubst %,%_demo_$(size)$(EXE_EXT),$(STD_MODES)))
# XTS mode
ALL_EXES += $(foreach size,$(XTS_SIZES),xts_demo_$(size)$(EXE_EXT))
# OCB mode
ALL_EXES += $(foreach size,$(OCB_SIZES),ocb_demo_$(size)$(EXE_EXT))
# GCM-SIV mode
ALL_EXES += $(foreach size,$(GCM_SIV_SIZES),gcm_siv_demo_$(size)$(EXE_EXT))
# GCM 1024 Nonce mode (uses gcm_demo.c) - Define specific targets
ALL_EXES += $(foreach size,$(AES_SIZES),gcm_demo_$(size)_nonce1024$(EXE_EXT))
# FPE modes (use fpe_demo.c)
ALL_EXES += $(foreach size,$(AES_SIZES),fpe_demo_ff1_$(size)$(EXE_EXT))
ALL_EXES += $(foreach size,$(AES_SIZES),fpe_demo_ff3_$(size)$(EXE_EXT))
ALL_EXES += $(foreach size,$(EAX_SIZES),eax_demo_$(size)$(EXE_EXT))
ALL_EXES += $(foreach size,$(SIV_SIZES),siv_demo_$(size)$(EXE_EXT))

# --- Targets ---

# Default target: build all demos
all: $(ALL_EXES)

# Rule to compile common.c into common.o
$(COMMON_OBJ): $(COMMON_SRC) $(COMMON_HDR) $(AES_LIB_HDR)
	$(CC) $(CFLAGS) -c $(call fixpath,$<) -o $(call fixpath,$@)

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
gcm_demo_%_nonce1024$(EXE_EXT): src/gcm_demo.c $(COMMON_DEPS)
	$(CC) $(CFLAGS) -o $(call fixpath,$@) $(call fixpath,$<) $(call fixpath,$(COMMON_OBJ)) $(call fixpath,$(AES_LIB_SRC)) $(LIBS) -DAES___=$* $(call GET_FLAGS,$(notdir $<),$@)

# Rules for standard sizes (128, 192, 256) applied to remaining modes
# The stem % will match the mode name (e.g., ecb, cbc, gcm, etc.)
%_demo_128$(EXE_EXT): src/%_demo.c $(COMMON_DEPS)
	$(CC) $(CFLAGS) -o $(call fixpath,$@) $(call fixpath,$<) $(call fixpath,$(COMMON_OBJ)) $(call fixpath,$(AES_LIB_SRC)) $(LIBS) -DAES___=128 $(call GET_FLAGS,$(notdir $<),$@)

%_demo_192$(EXE_EXT): src/%_demo.c $(COMMON_DEPS)
	$(CC) $(CFLAGS) -o $(call fixpath,$@) $(call fixpath,$<) $(call fixpath,$(COMMON_OBJ)) $(call fixpath,$(AES_LIB_SRC)) $(LIBS) -DAES___=192 $(call GET_FLAGS,$(notdir $<),$@)

%_demo_256$(EXE_EXT): src/%_demo.c $(COMMON_DEPS)
	$(CC) $(CFLAGS) -o $(call fixpath,$@) $(call fixpath,$<) $(call fixpath,$(COMMON_OBJ)) $(call fixpath,$(AES_LIB_SRC)) $(LIBS) -DAES___=256 $(call GET_FLAGS,$(notdir $<),$@)

# Specific rules for FPE (FF1/FF3) demos - Handles all AES sizes
# FF1 variant rule
fpe_demo_ff1_%$(EXE_EXT): src/fpe_demo.c $(FPE_DEPS)
	$(CC) $(CFLAGS) -o $(call fixpath,$@) $(call fixpath,$<) $(call fixpath,$(COMMON_OBJ)) $(call fixpath,$(AES_LIB_SRC)) $(LIBS) -DAES___=$* -DFF_X=1

# FF3 variant rule
fpe_demo_ff3_%$(EXE_EXT): src/fpe_demo.c $(FPE_DEPS)
	$(CC) $(CFLAGS) -o $(call fixpath,$@) $(call fixpath,$<) $(call fixpath,$(COMMON_OBJ)) $(call fixpath,$(AES_LIB_SRC)) $(LIBS) -DAES___=$* -DFF_X=3

# Pridáme cieľ pre kompiláciu všetkých FPE variant
fpe: $(filter fpe_demo_%,$(ALL_EXES))

# --- Specific Targets ---
# Example: build just cfb_demo (all applicable sizes)
cfb_demo: $(filter cfb_demo_%,$(ALL_EXES))

# Target to build all GCM variants (standard and 1024 nonce)
gcm: $(filter gcm_demo_%,$(ALL_EXES))

# --- Clean Target ---
clean:
ifeq ($(OS),Windows_NT)
	$(RM) $(subst /,\,$(ALL_EXES)) $(subst /,\,$(COMMON_OBJ)) *.o
else
	$(RM) $(ALL_EXES) $(COMMON_OBJ) *.o
endif

.PHONY: all clean cfb_demo gcm $(DEMO_BASES)

# Add phony targets for each demo base name to build all its variants
$(foreach base,$(DEMO_BASES),$(eval $(base): $(filter $(base)_demo_%,$(ALL_EXES))))
