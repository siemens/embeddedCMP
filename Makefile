.PHONY: default Debug zip clean_zip

WIN_PATH="C:/nxp/MCUXpressoIDE_10.3.1_2233/ide/plugins/com.nxp.mcuxpresso.tools.win32_10.3.0.201811011841/tools/bin;C:/nxp/MCUXpressoIDE_10.3.1_2233/ide/plugins/com.nxp.mcuxpresso.tools.win32_10.3.0.201811011841/buildtools/bin;C:/nxp/MCUXpressoIDE_10.3.1_2233/ide/plugins/com.nxp.mcuxpresso.tools.bin.win32_10.3.1.201902111813/binaries/;C:/nxp/MCUXpressoIDE_10.3.1_2233/ide/jre/bin/client;C:/nxp/MCUXpressoIDE_10.3.1_2233/ide/jre/bin;C:/nxp/MCUXpressoIDE_10.3.1_2233/ide/jre/lib/i386;C:/Program Files (x86)/Common Files/Intel/Shared Libraries/redist/ia32/mpirt;C:/Program Files (x86)/Common Files/Intel/Shared Libraries/redist/ia32/compiler;C:/Program Files (x86)/Common Files/Intel/Shared Files/fortran/bin/ia32;C:/WINDOWS/system32;C:/WINDOWS;C:/WINDOWS/System32/Wbem;C:/WINDOWS/System32/WindowsPowerShell/v1.0/;C:/Program Files/PuTTY/;C:/Program Files/Java/jre1.8.0_201/bin;C:/Program Files (x86)/Java/jre1.8.0_201/bin;C:/Users/z0042hzd/AppData/Local/Microsoft/WindowsApps;;C:/nxp/MCUXpressoIDE_10.3.1_2233/ide"

default: Debug

Debug:
	PATH=$(WIN_PATH)
	make -C Debug -r -j4 all


SHELL=bash # for supporting extended globbing used below
ZIP_PUBLIC = README.md LICENSE.txt frdmk64f_CMP-Client.mex config_and_debug_tweaks.diff cmp_doc/*.{md,jpg} \
  Makefile cmplib/ cmpclient/ resources/sdcard_root/SDHC/{tlssrv/,wwwroot/,certs/{insta/,netguard/}}
ZIP_EXCLUDES=-x 'Californium.properties' '*~'
dist_zip:
	zip frdmk64f_CMP-Client_dist.zip -r $(ZIP_PUBLIC) $(ZIP_EXCLUDES) cmpclient/cmpclient_config-ext.h
zip:
	zip frdmk64f_CMP-Client.zip -r $(ZIP_PUBLIC) README-Siemens.md resources/sdcard_root/SDHC/certs/ppki \
             resources/lra_config/{LraConfig.xml,SimpleLraConfig.xml,RunLra.sh,certs/,jar/} $(ZIP_EXCLUDES)

clean_zip:
	rm -f frdmk64f_CMP-Client*.zip
