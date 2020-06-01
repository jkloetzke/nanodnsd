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
	PUBLIC "CMAKE_INSTALL_FULL_SYSCONFDIR=\"${CMAKE_INSTALL_FULL_SYSCONFDIR}\"")

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

option(ENABLE_FUZZING "Enable build of fuzzing tests")
if(ENABLE_FUZZING)
	add_executable(nanodnsd-fuzz
		fuzz-main.c

		dns.c dns.h
		poll.c poll.h
		pkt.c pkt.h
		utils.c utils.h
		db.c db.h

		daemon.h poll.h
	)
	target_compile_definitions(nanodnsd-fuzz PUBLIC HAVE_SD_DAEMON)
endif()
