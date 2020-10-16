cmake_minimum_required(VERSION 3.10)
project(Dynano LANGUAGES C)
include(FindPkgConfig)
include(GNUInstallDirs)

add_executable(nanodnsd
	daemon.h
	db.c db.h
	defs.h
	dns.c dns.h
	http.c http.h
	log.c log.h
	main.c
	pkt.c pkt.h
	poll.c poll.h
	utils.c utils.h
)
target_compile_definitions(nanodnsd
	PUBLIC "CMAKE_INSTALL_FULL_SYSCONFDIR=\"${CMAKE_INSTALL_FULL_SYSCONFDIR}\""
	"CMAKE_INSTALL_FULL_LOCALSTATEDIR=\"${CMAKE_INSTALL_FULL_LOCALSTATEDIR}\"")

set_property(TARGET nanodnsd PROPERTY C_STANDARD 99)

option(NANODNS_HARDENING "Enable security hardening options" ON)
if(NANODNS_HARDENING)
	set_property(TARGET nanodnsd PROPERTY POSITION_INDEPENDENT_CODE True)
	target_compile_options(nanodnsd PUBLIC -fstack-protector-strong)
	target_compile_definitions(nanodnsd PUBLIC "_FORTIFY_SOURCE=1")
	target_link_options(nanodnsd PUBLIC -Wl,-z,now -Wl,-z,relro)
endif()

# Enable pedantic checks by default
option(NANODNS_PREDANTIC "Enable extra warnings and treat all warnigs as errors" ON)
if(NANODNS_PREDANTIC)
	target_compile_options(nanodnsd PUBLIC
		-Wall -Wextra -Wconversion -Wsign-conversion -Werror)
endif()

pkg_check_modules(libcrypto REQUIRED IMPORTED_TARGET libcrypto libcrypto)
target_link_libraries(nanodnsd PUBLIC PkgConfig::libcrypto)

# Installation rules
install(TARGETS nanodnsd
	RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}"
)

# conditionally enable systemd support
pkg_check_modules(libsystemd IMPORTED_TARGET libsystemd)
if(libsystemd_FOUND)
	target_sources(nanodnsd PRIVATE daemon.c)
	target_link_libraries(nanodnsd PUBLIC PkgConfig::libsystemd)
	target_compile_definitions(nanodnsd PUBLIC HAVE_SD_DAEMON)

	configure_file(nanodnsd.service nanodnsd.service)

	pkg_get_variable(SYSTEMD_INSTALL_SYSTEM_UNIT_DIR systemd systemdsystemunitdir)
	install(FILES "${CMAKE_CURRENT_BINARY_DIR}/nanodnsd.service"
			nanodnsd-dns.socket nanodnsd-http.socket
		DESTINATION "${SYSTEMD_INSTALL_SYSTEM_UNIT_DIR}")
endif()
