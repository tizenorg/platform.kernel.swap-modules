if MEMCHECKER
memchecker = -DMEMORY_CHECKER
endif

if DEBUG
debug_opt = -D__DEBUG
endif

if ANDROID
android_opt = -D__ANDROID
android = yes
endif

if SLP_APP
slp_opt = -DSLP_APP
endif

if ANDROID_APP
android_app_opt = -DANDROID_APP
endif

board_opt = -DBOARD_@BOARD@

include Makefile
