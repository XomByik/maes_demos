# Kompilator a priznaky
CC = gcc -std=gnu23
CFLAGS = -Wall -Wextra -O2
LIBS = -lm
# Multiplatformovy prikaz na odstranenie suborov
ifeq ($(OS),Windows_NT)
    # Prikazy specificke pre Windows
    RM = del /Q /F
    RMDIR = rmdir /Q /S
    CFLAGS += -D__USE_MINGW_ANSI_STDIO=1
    # Spracovanie oddelovaca ciest vo Windows pre zdrojove subory
    fixpath = $(subst /,\,$1)
    # Vytvorenie spustitelneho suboru s priponou .exe na Windows
    EXE_EXT = .exe
else
    # Prikazy pre Unix/Linux
    RM = rm -f
    RMDIR = rm -rf
    fixpath = $1
    EXE_EXT = 
endif

# Pridajte toto do vasho Makefile pre kompilaciu na Windows
ifdef MINGW
  CFLAGS += -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=0
endif

# --- Zdrojove subory ---
# AES kniznica
AES_LIB_SRC = libs/micro_aes.c
AES_LIB_HDR = libs/micro_aes.h
# FPE kniznicny hlavickovy subor (zavislost pre FPE demo)
FPE_LIB_HDR = libs/micro_fpe.h
# Spolocne nastroje
COMMON_SRC = src/common.c
COMMON_HDR = header_files/common.h
COMMON_OBJ = $(COMMON_SRC:.c=.o)
# Zdrojove subory demo (zakladne nazvy)
# Zoznam vsetkych zakladnych nazvov pre existujuce dema
# Poznamka: gcm1024 nie je zaklad, je to variant vytvoreny z gcm_demo.c
DEMO_BASES = ecb cbc cfb ofb ctr xts gcm ccm kw eax ocb siv gcm_siv fpe
DEMO_SRCS = $(patsubst %,src/%_demo.c,$(DEMO_BASES))
DEMO_SRCS := $(filter-out $(COMMON_SRC), $(DEMO_SRCS))

# --- Definicie spustitelnych suborov ---
AES_SIZES = 128 192 256
# Definujte specificke velkosti podporovane urcitymi rezimami, ak sa lisia od AES_SIZES
XTS_SIZES = 128 256
GCM_SIV_SIZES = 128 256
OCB_SIZES = 128
EAX_SIZES = 128
SIV_SIZES = 128

# Generovanie vsetkych moznych nazvov spustitelnych suborov podla rezimov a velkosti
# Standardne rezimy (ECB, CBC, CFB, OFB, CTR, GCM, CCM, KW, EAX) pouzivajuce AES_SIZES
STD_MODES = ecb cbc cfb ofb ctr gcm ccm kw
ALL_EXES = $(foreach size,$(AES_SIZES),$(patsubst %,%_demo_$(size)$(EXE_EXT),$(STD_MODES)))
# XTS rezim
ALL_EXES += $(foreach size,$(XTS_SIZES),xts_demo_$(size)$(EXE_EXT))
# OCB rezim
ALL_EXES += $(foreach size,$(OCB_SIZES),ocb_demo_$(size)$(EXE_EXT))
# GCM-SIV rezim
ALL_EXES += $(foreach size,$(GCM_SIV_SIZES),gcm_siv_demo_$(size)$(EXE_EXT))
# GCM 1024 Nonce rezim (pouziva gcm_demo.c) - Definujte specificke ciele
ALL_EXES += $(foreach size,$(AES_SIZES),gcm_demo_$(size)_nonce1024$(EXE_EXT))
# FPE rezimy (pouzivaju fpe_demo.c)
ALL_EXES += $(foreach size,$(AES_SIZES),fpe_demo_ff1_$(size)$(EXE_EXT))
ALL_EXES += $(foreach size,$(AES_SIZES),fpe_demo_ff3_$(size)$(EXE_EXT))
ALL_EXES += $(foreach size,$(EAX_SIZES),eax_demo_$(size)$(EXE_EXT))
ALL_EXES += $(foreach size,$(SIV_SIZES),siv_demo_$(size)$(EXE_EXT))

# --- Ciele ---

# Predvoleny ciel: zostavi vsetky dema
all: $(ALL_EXES)

# Pravidlo na kompilaciu common.c do common.o
$(COMMON_OBJ): $(COMMON_SRC) $(COMMON_HDR) $(AES_LIB_HDR)
	$(CC) $(CFLAGS) -c $(call fixpath,$<) -o $(call fixpath,$@)

# --- Genericke pravidla kompilacie ---
# Spolocne zavislosti pre vsetky demo pravidla, ktore nepotrebuju FPE
COMMON_DEPS = $(COMMON_OBJ) $(AES_LIB_SRC) $(AES_LIB_HDR) $(COMMON_HDR)
# Zavislosti pre FPE dema (pridanie FPE hlavickoveho suboru)
FPE_DEPS = $(COMMON_DEPS) $(FPE_LIB_HDR)

# Definicia funkcie na ziskanie potrebnych priznakov na zaklade zdrojoveho suboru ($1) a nazvu cieloveho suboru ($2)
define GET_FLAGS
$(if $(filter xts_demo.c,$1),-DXTS=1) \
$(if $(filter gcm_demo.c,$1),$(if $(findstring nonce1024,$2),-DGCM_NONCE_LEN=128)) \
$(if $(filter ccm_demo.c,$1),-DCCM=1 -DCCM_NONCE_LEN=7 -DCCM_TAG_LEN=16) \
$(if $(filter kw_demo.c,$1),-DKW=1) \
$(if $(filter fpe_demo.c,$1),$(if $(findstring ff1,$2),-DFF_X=1) $(if $(findstring ff3,$2),-DFF_X=3))
endef

# Specificke pravidla pre GCM 1024 Nonce demo - Spracuva vsetky AES velkosti
# Stem * je velkost (napr. 128)
gcm_demo_%_nonce1024$(EXE_EXT): src/gcm_demo.c $(COMMON_DEPS)
	$(CC) $(CFLAGS) -o $(call fixpath,$@) $(call fixpath,$<) $(call fixpath,$(COMMON_OBJ)) $(call fixpath,$(AES_LIB_SRC)) $(LIBS) -DAES___=$* $(call GET_FLAGS,$(notdir $<),$@)

# Pravidla pre standardne velkosti (128, 192, 256) aplikovane na zvysne rezimy
# Stem % zodpoveda nazvu rezimu (napr. ecb, cbc, gcm, atd.)
%_demo_128$(EXE_EXT): src/%_demo.c $(COMMON_DEPS)
	$(CC) $(CFLAGS) -o $(call fixpath,$@) $(call fixpath,$<) $(call fixpath,$(COMMON_OBJ)) $(call fixpath,$(AES_LIB_SRC)) $(LIBS) -DAES___=128 $(call GET_FLAGS,$(notdir $<),$@)

%_demo_192$(EXE_EXT): src/%_demo.c $(COMMON_DEPS)
	$(CC) $(CFLAGS) -o $(call fixpath,$@) $(call fixpath,$<) $(call fixpath,$(COMMON_OBJ)) $(call fixpath,$(AES_LIB_SRC)) $(LIBS) -DAES___=192 $(call GET_FLAGS,$(notdir $<),$@)

%_demo_256$(EXE_EXT): src/%_demo.c $(COMMON_DEPS)
	$(CC) $(CFLAGS) -o $(call fixpath,$@) $(call fixpath,$<) $(call fixpath,$(COMMON_OBJ)) $(call fixpath,$(AES_LIB_SRC)) $(LIBS) -DAES___=256 $(call GET_FLAGS,$(notdir $<),$@)

# Specificke pravidla pre FPE (FF1/FF3) dema - Spracuva vsetky AES velkosti
# FF1 variant pravidlo
fpe_demo_ff1_%$(EXE_EXT): src/fpe_demo.c $(FPE_DEPS)
	$(CC) $(CFLAGS) -o $(call fixpath,$@) $(call fixpath,$<) $(call fixpath,$(COMMON_OBJ)) $(call fixpath,$(AES_LIB_SRC)) $(LIBS) -DAES___=$* -DFF_X=1

# FF3 variant pravidlo
fpe_demo_ff3_%$(EXE_EXT): src/fpe_demo.c $(FPE_DEPS)
	$(CC) $(CFLAGS) -o $(call fixpath,$@) $(call fixpath,$<) $(call fixpath,$(COMMON_OBJ)) $(call fixpath,$(AES_LIB_SRC)) $(LIBS) -DAES___=$* -DFF_X=3

# Pridame ciel pre kompilaciu vsetkych FPE variant
fpe: $(filter fpe_demo_%,$(ALL_EXES))

# --- Specificke ciele ---
# Priklad: zostav len cfb_demo (vsetky aplikovatelne velkosti)
cfb_demo: $(filter cfb_demo_%,$(ALL_EXES))

# Ciel na zostavenie vsetkych GCM variantov (standardny a 1024 nonce)
gcm: $(filter gcm_demo_%,$(ALL_EXES))

# --- Ciel na vycistenie ---
clean:
ifeq ($(OS),Windows_NT)
	$(RM) $(subst /,\,$(ALL_EXES)) $(subst /,\,$(COMMON_OBJ)) *.o
else
	$(RM) $(ALL_EXES) $(COMMON_OBJ) *.o
endif

.PHONY: all clean cfb_demo gcm $(DEMO_BASES)

# Pridaj virtualne ciele pre kazdy zakladny nazov dema na zostavenie vsetkych jeho variantov
$(foreach base,$(DEMO_BASES),$(eval $(base): $(filter $(base)_demo_%,$(ALL_EXES))))
