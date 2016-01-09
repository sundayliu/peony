
# CMAKE_INSTALL_PREFIX default value /usr/local
PROJECT(HELLO)
ADD_SUBDIRECTORY(src bin)

INSTALL(FILES COPYRIGHT README 
    DESTINATION share/doc/cmake/hello2)

INSTALL(PROGRAMS runhello.sh DESTINATION bin)
INSTALL(DIRECTORY doc/ DESTINATION share/doc/cmake/hello2)